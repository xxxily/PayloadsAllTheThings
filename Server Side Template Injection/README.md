[原文文档](README.en.md)

# 服务器端模板注入

> 模板注入允许攻击者将模板代码包含到现有（或不存在）模板中。模板引擎通过使用静态模板文件使设计HTML页面变得更容易，这些模板文件在运行时用HTML页面中的实际值替换变量/占位符

## 概述

- [工具](#工具)
- [方法论](#方法论)
    - [识别易受攻击的输入字段](#识别易受攻击的输入字段)
    - [注入模板语法](#注入模板语法)
    - [枚举模板引擎](#枚举模板引擎)
    - [升级到代码执行](#升级到代码执行)
- [实验环境](#实验环境)
- [参考资料](#参考资料)

## 工具

- [Hackmanit/TInjA](https://github.com/Hackmanit/TInjA) - 高效的SSTI + CSTI扫描器，利用新颖的多语言

  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

- [epinna/tplmap](https://github.com/epinna/tplmap) - 服务器端模板注入和代码注入检测与利用工具

  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) - 基于[epinna/tplmap](https://github.com/epinna/tplmap)的自动SSTI检测工具，具有交互式界面

  ```powershell
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```

## 方法论

### 识别易受攻击的输入字段

攻击者首先定位一个输入字段、URL参数或应用程序的任何用户可控制的部分，该部分被传递到服务器端模板中而没有适当的清理或转义。

例如，攻击者可能识别一个Web表单、搜索栏或模板预览功能，该功能似乎基于动态用户输入返回结果。

**提示**：生成的PDF文件、发票和电子邮件通常使用模板。

### 注入模板语法

攻击者通过注入特定于正在使用的模板引擎的模板语法来测试已识别的输入字段。不同的Web框架使用不同的模板引擎（例如，Python使用Jinja2，PHP使用Twig，或Java使用FreeMarker）。

常见的模板表达式：

- Jinja2（Python）的`{{7*7}}`。
- Thymeleaf（Java）的`#{7*7}`。

在专门针对该技术的页面（PHP、Python等）中找到更多模板表达式。

![SSTI备忘单工作流程](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

在大多数情况下，这个多语言负载在存在SSTI漏洞时会触发错误：

```ps1
${{<%[%'"}}%\.
```

[Hackmanit/模板注入表](https://github.com/Hackmanit/template-injection-table)是一个交互式表格，包含最有效的模板注入多语言以及44个最重要模板引擎的预期响应。

### 枚举模板引擎

基于成功的响应，攻击者确定正在使用哪个模板引擎。这一步至关重要，因为不同的模板引擎具有不同的语法、功能和利用潜力。攻击者可能尝试不同的负载来查看哪一个执行，从而识别引擎。

- **Python**：Django、Jinja2、Mako、...
- **Java**：Freemarker、Jinjava、Velocity、...
- **Ruby**：ERB、Slim、...

[@0xAwali的文章"template-engines-injection-101"](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)总结了JavaScript、Python、Ruby、Java和PHP的大多数模板引擎的语法和检测方法，以及如何区分使用相同语法的引擎。

### 升级到代码执行

一旦识别出模板引擎，攻击者注入更复杂的表达式，旨在执行服务器端命令或任意代码。

## 实验环境

- [Root Me - Java - 服务器端模板注入](https://www.root-me.org/en/Challenges/Web-Server/Java-Server-side-Template-Injection)
- [Root Me - Python - 服务器端模板注入介绍](https://www.root-me.org/en/Challenges/Web-Server/Python-Server-side-Template-Injection-Introduction)
- [Root Me - Python - 盲SSTI过滤器绕过](https://www.root-me.org/en/Challenges/Web-Server/Python-Blind-SSTI-Filters-Bypass)

## 参考资料

- [服务器端模板注入（SSTI）渗透测试人员指南 - Busra Demir - 2020年12月24日](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
- [使用服务器端模板注入（SSTI）获取Shell - David Valles - 2018年8月22日](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
- [模板引擎注入101 - Mahmoud M. Awali - 2024年11月1日](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
- [在加固目标上的模板注入 - Lucas 'BitK' Philippe - 2022年9月28日](https://youtu.be/M0b_KA0OMFw)