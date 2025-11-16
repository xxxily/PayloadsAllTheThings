[原文文档](README.en.md)

# 暴力破解和速率限制

## 摘要

* [工具](#工具)
* [暴力破解](#暴力破解)
    * [Burp Suite Intruder](#burp-suite-intruder)
    * [FFUF](#ffuf)
* [速率限制](#速率限制)
    * [TLS 栈 - JA3](#tls-栈---ja3)
    * [网络 IPv4](#网络-ipv4)
    * [网络 IPv6](#网络-ipv6)
* [参考资料](#参考资料)

## 工具

* [ddd/gpb](https://github.com/ddd/gpb) - 在轮换IPv6地址的同时暴力破解任何Google用户的电话号码。
* [ffuf/ffuf](https://github.com/ffuf/ffuf) - 用Go语言编写的快速网络模糊测试工具。
* [PortSwigger/Burp Suite](https://portswigger.net/burp) - 业界领先的漏洞扫描、渗透测试和Web应用安全平台。
* [lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate) - 特殊构建的curl，可以模拟Chrome和Firefox。

## 暴力破解

在Web上下文中，暴力破解是指试图通过大量非法请求或利用目标软件中的漏洞使服务不可用，从而获得对Web应用程序未经授权访问的方法。攻击者系统性地输入大量凭据组合或其他值（例如，迭代数字范围）来利用弱密码或不足的安全措施。

例如，他们可能提交数千个用户名和密码组合，或通过迭代范围（例如0到10,000）来猜测安全令牌。如果没有得到有效缓解，这种方法可能导致未经授权的访问和数据泄露。

速率限制、账户锁定策略、 CAPTCHA和强密码要求等对策对于保护Web应用程序免受此类暴力破解攻击至关重要。

### Burp Suite Intruder

* **狙击手攻击**：针对单个位置（一个变量）同时循环遍历一个有效载荷集。

    ```ps1

    用户名: 密码
    用户名1:密码1
    用户名1:密码2
    用户名1:密码3
    用户名1:密码4
    ```

* **撞击锤攻击**：通过使用单个有效载荷集一次将相同有效载荷发送到所有标记位置。

    ```ps1
    用户名1:用户名1
    用户名2:用户名2
    用户名3:用户名3
    用户名4:用户名4
    ```

* **干草叉攻击**：并行使用不同的有效载荷列表，将每个列表的第n个条目组合到一个请求中。

    ```ps1
    用户名1:密码1
    用户名2:密码2
    用户名3:密码3
    用户名4:密码4
    ```

* **集束炸弹攻击**：迭代遍历多个有效载荷集的所有组合。

    ```ps1
    用户名1:密码1
    用户名1:密码2
    用户名1:密码3
    用户名1::密码4

    用户名2:密码1
    用户名2:密码2
    用户名2:密码3
    用户名2:密码4
    ```

### FFUF

```bash
ffuf -w usernames.txt:USER -w passwords.txt:PASS \
     -u https://target.tld/login \
     -X POST -d "username=USER&password=PASS" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "X-Forwarded-For: FUZZ" -w ipv4-list.txt:FUZZ \
     -mc all
```

## 速率限制

### HTTP 流水线

HTTP流水线是HTTP/1.1的一项功能，允许客户端在单个持久TCP连接上发送多个HTTP请求，而无需先等待相应的响应。客户端在同一个连接上"管道化"请求，一个接一个。

### TLS 栈 - JA3

JA3是一种通过对TLS"hello"消息内容进行哈希来指纹识别TLS客户端（JA3S用于TLS服务器）的方法。它提供了一个紧凑的标识符，即使更高级别的协议字段（如HTTP user-agent）被隐藏或伪造，您也可以使用它在网络上检测、分类和跟踪客户端。

> JA3收集客户端Hello包中以下字段的字节的十进制值；SSL版本、接受的密码套件、扩展列表、椭圆曲线和椭圆曲线格式。然后它按顺序将这些值连接起来，使用","分隔每个字段，使用"-"分隔每个字段中的每个值。

* Burp Suite JA3: `53d67b2a806147a7d1d5df74b54dd049`, `62f6a6727fda5a1104d5b147cd82e520`
* Tor Client JA3: `e7d705a3286e19ea42f587b344ee6865`

**对策:**

* 使用浏览器驱动的自动化（Puppeteer / Playwright）
* 使用[lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate)伪造TLS握手
* 浏览器/库的JA3随机化插件

### 网络 IPv4

使用多个代理来模拟多个客户端。

```bash
proxychains ffuf -w wordlist.txt -u https://target.tld/FUZZ
```

* 使用`random_chain`为每个请求轮换

    ```ps1
    random_chain
    ```

* 将每个连接的代理链数量设置为1。

    ```ps1
    chain_len = 1
    ```

* 最后，在配置文件中指定代理：

    ```ps1
    # 类型  主机      端口
    socks5  127.0.0.1 1080
    socks5  192.168.1.50 1080
    http    proxy1.example.com 8080
    http    proxy2.example.com 8080
    ```

### 网络 IPv6

许多云提供商，如Vultr，提供/64 IPv6范围，这提供了大量的地址（18 446 744 073 709 551 616）。这允许在暴力破解攻击期间进行广泛的IP轮换。

## 参考资料

* [暴力破解任何Google用户的电话号码 - brutecat - 2025年6月9日](https://brutecat.com/articles/leaking-google-phones)
* [Burp Intruder攻击类型 - PortSwigger - 2025年8月19日](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types)
* [检测和骚扰Burp用户 - Julien Voisin - 2021年5月3日](https://dustri.org/b/detecting-and-annoying-burp-users.html)