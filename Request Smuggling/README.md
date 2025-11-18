[原文文档](README.en.md)

# 请求走私

> 当多个"组件"处理请求，但在确定请求开始/结束的位置上存在分歧时，就会发生HTTP请求走私。这种分歧可用于干扰另一个用户的请求/响应或绕过安全控制。它通常是由于优先处理不同的HTTP头（Content-Length vs Transfer-Encoding）、处理格式错误头的差异（例如是否忽略具有意外空格的头）、由于从较新协议降级请求，或由于部分请求超时时应被丢弃的时间差异而发生的。

## 摘要

* [工具](#tools)
* [方法论](#methodology)
    * [CL.TE 漏洞](#clte-vulnerabilities)
    * [TE.CL 漏洞](#tecl-vulnerabilities)
    * [TE.TE 漏洞](#tete-vulnerabilities)
    * [HTTP/2 请求走私](#http2-request-smuggling)
    * [客户端去同步](#client-side-desync)
* [实验环境](#labs)
* [参考资料](#references)

## 工具

* [bappstore/HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - Burp Suite的扩展，旨在帮助您发起HTTP请求走私攻击
* [defparam/Smuggler](https://github.com/defparam/smuggler) - 用Python 3编写的HTTP请求走私/去同步测试工具
* [dhmosfunk/simple-http-smuggler-generator](https://github.com/dhmosfunk/simple-http-smuggler-generator) - 为Burp Suite从业者证书考试和HTTP请求走私实验室开发的工具。

## 方法论

如果您想手动利用HTTP请求走私，您将面临一些问题，特别是在TE.CL漏洞中，您必须计算第二个请求（恶意请求）的块大小，正如PortSwigger所建议的"手动修复请求走私攻击中的长度字段可能很棘手"。

### CL.TE 漏洞

> 前端服务器使用Content-Length头，后端服务器使用Transfer-Encoding头。