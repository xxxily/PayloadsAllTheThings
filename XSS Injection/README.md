[原文文档](README.en.md)

# 跨站脚本

> 跨站脚本（XSS）是一种通常在Web应用程序中发现的计算机安全漏洞类型。XSS使攻击者能够将客户端脚本注入到其他用户查看的网页中。

## 摘要

- [方法论](#methodology)
- [概念验证](#proof-of-concept)
    - [数据获取器](#data-grabber)
    - [CORS](#cors)
    - [UI重绘](#ui-redressing)
    - [JavaScript键盘记录器](#javascript-keylogger)
    - [其他方式](#other-ways)
- [识别XSS端点](#identify-an-xss-endpoint)
    - [工具](#tools)
- [HTML/应用程序中的XSS](#xss-in-htmlapplications)
    - [常见载荷](#common-payloads)
    - [使用HTML5标签的XSS](#xss-using-html5-tags)
    - [使用远程JS的XSS](#xss-using-a-remote-js)
    - [隐藏输入中的XSS](#xss-in-hidden-input)
    - [大写输出中的XSS](#xss-in-uppercase-output)
    - [基于DOM的XSS](#dom-based-xss)
    - [JS上下文中的XSS](#xss-in-js-context)
- [URI包装器中的XSS](#xss-in-wrappers-for-uri)
    - [包装器javascript:](#wrapper-javascript)
    - [包装器data:](#wrapper-data)
    - [包装器vbscript:](#wrapper-vbscript)
- [文件中的XSS](#xss-in-files)
    - [XML中的XSS](#xss-in-xml)
    - [SVG中的XSS](#xss-in-svg)