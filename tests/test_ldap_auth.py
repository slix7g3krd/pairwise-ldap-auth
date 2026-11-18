import pytest

from security.ldap_auth import (
    escape_filter,
    escape_dn,
    validate_filter,
    authenticate,
    safe_attrs,
    auth_error,
    follow_referral
)


def test_filter_star():
    assert escape_filter('*') == chr(92) + '2a'

def test_filter_paren():
    assert escape_filter('(') == chr(92) + '28'

def test_filter_backslash():
    assert escape_filter(chr(92)) == chr(92) + '5c'

def test_dn_comma():
    assert escape_dn('a,b') == 'a' + chr(92) + ',b'

def test_dn_plus():
    assert escape_dn('a+b') == 'a' + chr(92) + '+b'

def test_empty_filter():
    assert validate_filter('') is False

def test_wildcard_filter():
    assert validate_filter('(uid=*)') is False

def test_anonymous():
    assert authenticate('', 'p', lambda u, p: True, lambda u: []) is False

def test_auth_ok():
    assert authenticate('u', 'p', lambda u, p: True, lambda u: [{'uid': 'u'}]) is True

def test_bad_password():
    assert authenticate('u', 'bad', lambda u, p: False, lambda u: [{'uid': 'u'}]) is False

def test_attrs():
    assert safe_attrs(['cn', 'mail', 'pwd'], {'cn', 'mail'}) == ['cn', 'mail']

def test_same_error():
    assert auth_error('no_user') == auth_error('bad_pw')

def test_no_referral():
    assert follow_referral(None, []) is None

def test_evil_referral():
    assert follow_referral('https://evil.example', []) is None

def test_valid_filter():
    assert validate_filter('(uid=u)') is True
