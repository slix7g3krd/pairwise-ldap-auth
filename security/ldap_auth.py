"""Hardened helpers for the LDAP-backed login flow.

The module is deliberately stateless: it never caches a connection or an
authentication context, so every call to :func:`authenticate` is served by
whatever (fresh) connection the injected callbacks create.  Callers that need
an explicit per-request lifecycle can use :func:`request_connection`.

Security policy encoded here:

* RFC 4515 escaping for values interpolated into search filters.
* RFC 4514 escaping for values interpolated into DNs.
* Empty, malformed and wildcard-bearing filters are rejected.
* Anonymous binds (empty user or password) are refused.
* Referral chasing is disabled; referrals are never followed.
* Only explicitly allow-listed attributes may be returned.
* Authentication failures produce one generic message.
"""

from __future__ import annotations

import contextlib
import inspect
import itertools
import logging
import re
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

#: Advisory timeout, in seconds, handed to the injected LDAP callbacks when
#: they accept a ``timeout`` keyword.  Connections must apply it to both the
#: bind and the search.
DEFAULT_TIMEOUT = 5.0

#: A login must resolve to exactly one entry, so a search only ever needs to
#: look at two results (the second is enough to prove ambiguity).
MAX_SEARCH_RESULTS = 2

#: The single message returned for every authentication failure.  Returning
#: distinct messages for "unknown user" and "bad password" lets an attacker
#: enumerate accounts.
GENERIC_AUTH_ERROR = "Invalid username or password."

#: RFC 4515 escapes for characters with special meaning in a filter.
_FILTER_ESCAPES = {
    "\x00": "\\00",
    "(": "\\28",
    ")": "\\29",
    "*": "\\2a",
    "\\": "\\5c",
}

#: Characters that must be backslash-escaped anywhere in a DN value (RFC 4514).
_DN_ESCAPED_CHARS = frozenset(',"+\\<>;')

#: Attribute type (descriptor or dotted OID) plus optional options, e.g.
#: ``cn``, ``objectClass``, ``cn;lang-en``, ``1.2.840.113556.1.4.221``.
_ATTR_DESCRIPTION_RE = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*)(?:;[A-Za-z0-9-]+)*\Z"
)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def escape_filter(value: str) -> str:
    """Escape *value* for safe interpolation into an RFC 4515 search filter.

    ``\\ * ( ) NUL`` become their ``\\XX`` hex forms, which prevents a value
    such as ``*)(uid=*`` from terminating the assertion and injecting a new
    filter component.
    """
    if not isinstance(value, str):
        raise TypeError("filter value must be a str")
    return "".join(_FILTER_ESCAPES.get(ch, ch) for ch in value)


def escape_dn(value: str) -> str:
    """Escape a single relative distinguished value per RFC 4514.

    Commas, plus signs, quotes, backslashes, angle brackets and semicolons are
    backslash-escaped.  A leading ``#`` and leading/trailing spaces are escaped
    too, since they are otherwise syntactically significant in a DN.  This
    stops values like ``x,ou=admins`` from moving the search base.
    """
    if not isinstance(value, str):
        raise TypeError("DN value must be a str")
    if not value:
        return ""

    last = len(value) - 1
    escaped = []
    for index, char in enumerate(value):
        if char == "\x00":
            escaped.append("\\00")
        elif char in _DN_ESCAPED_CHARS:
            escaped.append("\\" + char)
        elif char == " " and (index == 0 or index == last):
            escaped.append("\\ ")
        elif char == "#" and index == 0:
            escaped.append("\\#")
        else:
            escaped.append(char)
    return "".join(escaped)


class _FilterSyntaxError(ValueError):
    """Raised internally when a filter does not conform to RFC 4515."""


def _parse_filter(text: str) -> None:
    """Validate *text* as a single RFC 4515 filter.

    Raises :class:`_FilterSyntaxError` for malformed input and also for
    presence/substring filters, because this deployment does not permit
    wildcards in authentication filters.
    """
    length = len(text)
    pos = 0

    def fail(message: str) -> None:
        raise _FilterSyntaxError(message)

    def peek() -> str:
        return text[pos] if pos < length else ""

    def parse_filter() -> None:
        nonlocal pos
        if peek() != "(":
            fail("filter must start with '('")
        pos += 1
        parse_filtercomp()
        if peek() != ")":
            fail("unbalanced parentheses")
        pos += 1

    def parse_filtercomp() -> None:
        nonlocal pos
        char = peek()
        if char in "&|":
            pos += 1
            count = 0
            while peek() == "(":
                parse_filter()
                count += 1
            if count == 0:
                fail("empty filter list")
        elif char == "!":
            pos += 1
            parse_filter()
        else:
            parse_item()

    def parse_item() -> None:
        nonlocal pos
        start = pos
        while pos < length and text[pos] not in "=<>~":
            if text[pos] in "()":
                fail("invalid attribute description")
            pos += 1
        attribute = text[start:pos]
        if not attribute or not _ATTR_DESCRIPTION_RE.match(attribute):
            fail("invalid attribute description")

        if pos >= length:
            fail("missing filter operator")
        if text[pos] == "=":
            pos += 1
        elif text[pos] in "<>~" and pos + 1 < length and text[pos + 1] == "=":
            pos += 2
        else:
            fail("invalid filter operator")

        value_octets = 0
        while pos < length and text[pos] != ")":
            char = text[pos]
            if char == "(":
                fail("unescaped '(' in assertion value")
            if char == "\\":
                if (
                    pos + 2 >= length
                    or text[pos + 1] not in _HEX_DIGITS
                    or text[pos + 2] not in _HEX_DIGITS
                ):
                    fail("invalid escape in assertion value")
                pos += 3
                value_octets += 1
                continue
            if char == "*":
                # Presence ("(uid=*)") and substring ("(uid=u*)") filters both
                # match multiple entries; the login flow forbids them.
                fail("wildcards are not permitted")
            if char == "\x00":
                fail("unescaped NUL in assertion value")
            pos += 1
            value_octets += 1

        if value_octets == 0:
            fail("empty assertion value")

    parse_filter()
    if pos != length:
        fail("trailing data after filter")


def validate_filter(value: Any) -> bool:
    """Return ``True`` only for a well-formed, non-wildcard RFC 4515 filter.

    Empty/whitespace-only input, ``None``, unbalanced parentheses, injection
    attempts such as ``*)(uid=*`` and any presence or substring filter are all
    rejected.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        _parse_filter(value)
    except _FilterSyntaxError:
        return False
    return True


def safe_attrs(
    requested: Optional[Iterable[str]], allowed: Optional[Iterable[str]]
) -> list[str]:
    """Filter *requested* attribute names down to the *allowed* allow-list.

    Order follows *requested*; matching is case-insensitive because LDAP
    attribute descriptions are.  ``None`` and unknown names yield ``[]``.
    Rejecting everything not listed keeps sensitive attributes such as
    ``userPassword`` and ``manager`` out of responses.
    """
    if not allowed:
        return []
    allow_set = {
        name.strip().lower() for name in allowed if isinstance(name, str) and name.strip()
    }
    if not allow_set or not requested:
        return []

    result: list[str] = []
    seen: set[str] = set()
    for name in requested:
        if not isinstance(name, str):
            continue
        key = name.strip().lower()
        if key in allow_set and key not in seen:
            seen.add(key)
            result.append(name)
    return result


def auth_error(reason: Any = None) -> str:
    """Return the single generic message for any authentication failure.

    ``reason`` is accepted for call-site convenience and logging but never
    influences the returned value, so responses cannot distinguish an unknown
    user from an incorrect password.
    """
    if reason is not None:
        logger.debug("authentication failure reason: %s", reason)
    return GENERIC_AUTH_ERROR


def follow_referral(referral_url: Optional[str], allowed_hosts: Any = None) -> None:
    """Refuse every LDAP referral.

    Following referrals lets an attacker who can influence directory data
    redirect authentication queries to a directory they control.  This
    function therefore always returns ``None``; callers must treat a referral
    as "no result" rather than chasing it, regardless of ``allowed_hosts``.
    """
    if referral_url:
        logger.debug("ignoring LDAP referral: %s", referral_url)
    return None


@contextlib.contextmanager
def request_connection(factory: Callable[..., Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
    """Create and dispose of a connection for exactly one request.

    Reusing a connection across requests can leak the bound authentication
    context from one user into the next.  This context manager makes the
    per-request lifecycle explicit: it opens a connection, yields it, then
    unbinds and closes it on the way out.
    """
    connection = factory(*args, **kwargs)
    try:
        yield connection
    finally:
        unbind = getattr(connection, "unbind", None)
        if callable(unbind):
            with contextlib.suppress(Exception):
                unbind()
        close = getattr(connection, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()


def _invoke(func: Callable[..., Any], args: Sequence[Any], timeout: Optional[float]) -> Any:
    """Call *func* with *args*, adding ``timeout`` only when it accepts one."""
    if timeout is not None:
        try:
            parameters = inspect.signature(func).parameters
        except (TypeError, ValueError):
            parameters = {}
        accepts_timeout = "timeout" in parameters or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
        if accepts_timeout:
            return func(*args, timeout=timeout)
    return func(*args)


def _is_entry_iterable(result: Any) -> bool:
    """Reject scalar/mapping results that are not a collection of entries."""
    if result is None or isinstance(result, (str, bytes, Mapping)):
        return False
    return isinstance(result, Iterable)


def authenticate(
    username: str,
    password: str,
    bind_func: Callable[..., Any],
    search_func: Callable[..., Any],
    *,
    timeout: Optional[float] = DEFAULT_TIMEOUT,
) -> bool:
    """Authenticate *username* against LDAP using injected callbacks.

    ``search_func(escaped_username)`` must return the entries matching
    ``(uid=<escaped_username>)`` and ``bind_func(username, password)`` must
    attempt the bind.  Exactly one entry must match, which also caps how many
    results are consumed.  Any failure — including exceptions raised by the
    callbacks — collapses to ``False`` so callers cannot distinguish causes.

    Anonymous binds are refused up front: an empty username or password never
    reaches the directory.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    if not username or not password:
        return False

    escaped_username = escape_filter(username)
    search_filter = f"(uid={escaped_username})"
    if not validate_filter(search_filter):
        return False

    try:
        result = _invoke(search_func, (escaped_username,), timeout)
    except Exception:
        logger.debug("LDAP search failed", exc_info=True)
        return False

    if not _is_entry_iterable(result):
        return False

    try:
        entries = list(itertools.islice(iter(result), MAX_SEARCH_RESULTS))
    except Exception:
        logger.debug("LDAP search result could not be read", exc_info=True)
        return False

    # Zero matches means no such user; more than one means an ambiguous
    # identity.  Both are authentication failures.
    if len(entries) != 1:
        return False

    try:
        return bool(_invoke(bind_func, (username, password), timeout))
    except Exception:
        logger.debug("LDAP bind failed", exc_info=True)
        return False
