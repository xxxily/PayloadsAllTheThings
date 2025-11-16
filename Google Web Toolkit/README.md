[原文文档](README.en.md)

# Google Web 工具包

> Google Web 工具包（GWT），也称为 GWT Web 工具包，是一套开源工具，允许 Web 开发者使用 Java 创建和维护 JavaScript 前端应用程序。它最初由谷歌开发，于 2006 年 5 月 16 日首次发布。

## 摘要

* [工具](#tools)
* [方法论](#methodology)
* [参考资料](#references)

## 工具

* [FSecureLABS/GWTMap](https://github.com/FSecureLABS/GWTMap) - GWTMap 是一个帮助映射基于 Google Web 工具包（GWT）的应用程序攻击面的工具。
* [GDSSecurity/GWT-Penetration-Testing-Toolset](https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset) - 一套用于协助 GWT 应用程序渗透测试的工具。

## 方法论

* 通过引导文件枚举远程应用程序的方法并创建代码的本地备份（随机选择排列）：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup
    ```

* 通过特定代码排列枚举远程应用程序的方法

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
    ```

* 通过 HTTP 代理路由流量时枚举方法：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
    ```

* 枚举任何给定排列的本地副本（文件）的方法：

    ```ps1
    ./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
    ```

* 将输出过滤到特定服务或方法：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login
    ```

* 为过滤服务的所有方法生成 RPC 载荷，带有彩色输出

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc --color
    ```

* 自动测试（探测）过滤服务方法的生成 RPC 请求

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe
    ```

## 参考资料

* [从序列化到 Shell：通过 EL 注入利用 Google Web 工具包 - Stevent Seeley - 2017年5月22日](https://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html)
* [破解 Google Web 工具包应用程序 - thehackerish - 2021年4月22日](https://thehackerish.com/hacking-a-google-web-toolkit-application/)