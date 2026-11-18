# pairwise-ldap-auth

企业目录服务接上 LDAP 后，登录过滤器的拼接就开始出事：用户名直接拼进 search filter，`*)(uid=*` 能匹配任意账号；DN 里的逗号和反斜杠不转义，能改搜索基准；通配符和空过滤器没有拒绝，匿名 bind 也能返回全员；referral 默认跟随，攻击者能把查询转到外部目录；返回属性没有白名单，密码哈希和 manager 字段一起带出；连接复用后认证上下文串号；超时和返回条数不限制；错误信息区分“用户不存在”和“密码错误”。security/ldap_auth.py 是核心，tests/test_ldap_auth.py 15个红。要修的是：RFC 4515 转义；DN 转义；拒绝空过滤器与通配符；禁用匿名 bind；关闭 referral；属性白名单；连接按请求隔离；超时与条数；错误统一。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
