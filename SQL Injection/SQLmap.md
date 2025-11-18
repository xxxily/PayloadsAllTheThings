[原文文档](SQLmap.en.md)

# SQLmap

> SQLmap是一个强大的工具，它自动化检测和利用SQL注入漏洞，与手动测试相比节省时间和精力。它支持广泛的数据库和注入技术，使其在各种场景中用途广泛且有效。
> 此外，SQLmap可以检索数据、操作数据库，甚至执行命令，为渗透测试人员和安全分析师提供了一套强大的功能。
> 重新发明轮子并不理想，因为SQLmap已经由专家严格开发、测试和改进。使用可靠、社区支持的工具意味着您受益于已建立的最佳实践，并避免错过漏洞或在自定义代码中引入错误的高风险。
> 但是您应该始终了解SQLmap的工作方式，并在必要时能够手动复制它。

## 摘要

* [SQLmap的基本参数](#basic-arguments-for-sqlmap)
* [加载请求文件](#load-a-request-file)
* [自定义注入点](#custom-injection-point)
* [二阶注入](#second-order-injection)
* [获取Shell](#getting-a-shell)
* [爬取和自动利用](#crawl-and-auto-exploit)
* [SQLmap的代理配置](#proxy-configuration-for-sqlmap)
* [注入篡改](#injection-tampering)
    * [后缀和前缀](#suffix-and-prefix)
    * [默认篡改脚本](#default-tamper-scripts)
    * [自定义篡改脚本](#custom-tamper-scripts)
    * [自定义SQL载荷](#custom-sql-payload)
    * [评估Python代码](#evaluate-python-code)
    * [预处理和后处理脚本](#preprocess-and-postprocess-scripts)
* [减少请求数量](#reduce-requests-number)
* [无SQL注入的SQLmap](#sqlmap-without-sql-injection)
* [参考资料](#references)