[原文文档](README.en.md)

# Web 缓存欺骗

> Web 缓存欺骗（WCD）是一种安全漏洞，当 Web 服务器或缓存代理误解客户端对 Web 资源的请求，并在缓存后提供可能更敏感或更私密的不同的资源时发生。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [缓存敏感数据](#缓存敏感数据)
    * [缓存自定义 JavaScript](#缓存自定义-javascript)
* [CloudFlare 缓存](#cloudflare-缓存)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - Web 缓存中毒 Burp 扩展

## 方法论

Web 缓存欺骗示例：

想象一下，攻击者诱骗已登录的受害者访问 `http://www.example.com/home.php/non-existent.css`

1. 受害者的浏览器请求资源 `http://www.example.com/home.php/non-existent.css`
2. 在缓存服务器中搜索请求的资源，但没有找到（资源不在缓存中）。
3. 然后将请求转发到主服务器。
4. 主服务器返回 `http://www.example.com/home.php` 的内容，很可能带有 HTTP 缓存头，指示不要缓存此页面。
5. 响应通过缓存服务器。
6. 缓存服务器识别文件具有 CSS 扩展名。
7. 在缓存目录下，缓存服务器创建一个名为 home.php 的目录，并将冒充的"CSS"文件（non-existent.css）缓存在其中。
8. 当攻击者请求 `http://www.example.com/home.php/non-existent.css` 时，请求被发送到缓存服务器，缓存服务器返回带有受害者敏感的 `home.php` 数据的缓存文件。

![WCD 演示](Images/wcd.jpg)

### 缓存敏感数据

**示例 1** - PayPal 主页上的 Web 缓存欺骗

1. 正常浏览，访问主页：`https://www.example.com/myaccount/home/`
2. 打开恶意链接：`https://www.example.com/myaccount/home/malicious.css`
3. 页面显示为 /home，缓存正在保存页面
4. 打开带有上一页面的私有标签页：`https://www.example.com/myaccount/home/malicious.css`
5. 显示缓存内容

Omer Gil 的攻击视频 - PayPal 主页上的 Web 缓存欺骗攻击
[![演示](https://i.vimeocdn.com/video/674856618-f9bac811a4c7bcf635c4eff51f68a50e3d5532ca5cade3db784c6d178b94d09a-d)](https://vimeo.com/249130093)

**示例 2** - OpenAI 上的 Web 缓存欺骗

1. 攻击者制作 `/api/auth/session` 端点的专用 .css 路径。
2. 攻击者分发链接
3. 受害者访问合法链接。
4. 响应被缓存。
5. 攻击者获取 JWT 凭据。

### 缓存自定义 JavaScript

1. 查找缓存中毒的未键入输入

    ```js
    值：User-Agent
    值：Cookie
    头：X-Forwarded-Host
    头：X-Host
    头：X-Forwarded-Server
    头：X-Forwarded-Scheme（头；也与 X-Forwarded-Host 组合）
    头：X-Original-URL（Symfony）
    头：X-Rewrite-URL（Symfony）
    ```

2. 缓存中毒攻击 - `X-Forwarded-Host` 未键入输入的示例（记住使用破坏器仅缓存此网页，而不是网站的主页）

    ```js
    GET /test?buster=123 HTTP/1.1
    Host: target.com
    X-Forwarded-Host: test"><script>alert(1)</script>

    HTTP/1.1 200 OK
    Cache-Control: public, no-cache
    [..]
    <meta property="og:image" content="https://test"><script>alert(1)</script>">
    ```

## 技巧

以下 URL 格式是检查"缓存"功能的良好起点。

* `https://example.com/app/conversation/.js?test`
* `https://example.com/app/conversation/;.js`
* `https://example.com/home.php/non-existent.css`

## 检测 Web 缓存欺骗

1. 检测分隔符差异：`/path/<dynamic-resource>;<static-resource>`
   * 例如：`/settings/profile;script.js`
   * 如果原始服务器使用 `;` 作为分隔符但缓存不是
   * 缓存解释路径为：`/settings/profile;script.js`
   * 原始服务器解释路径为：`/settings/profile`
   * 更多分隔符字符：请参阅 [Web 缓存欺骗实验室分隔符列表](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list)
2. 检测规范化：`/wcd/..%2fprofile`
   * 如果原始服务器解析了路径遍历序列但缓存没有
   * 缓存解释路径为：`/wcd/..%2fprofile`
   * 原始服务器解释路径为：`/profile`

## CloudFlare 缓存

当 `Cache-Control` 头设置为 `public` 且 `max-age` 大于 0 时，CloudFlare 会缓存资源。

* Cloudflare CDN 默认不缓存 HTML
* Cloudflare 仅基于文件扩展名而不是 MIME 类型缓存：[cloudflare/default-cache-behavior](https://developers.cloudflare.com/cache/about/default-cache-behavior/)

在 Cloudflare CDN 中，可以实现 `Cache Deception Armor`，它默认不启用。
当启用 `Cache Deception Armor` 时，规则将验证 URL 的扩展名与返回的 `Content-Type` 匹配。

CloudFlare 有一个默认扩展名列表，会在其负载均衡器后面缓存。

|       |      |      |      |      |       |      |
|-------|------|------|------|------|-------|------|
| 7Z    | CSV  | GIF  | MIDI | PNG  | TIF   | ZIP  |
| AVI   | DOC  | GZ   | MKV  | PPT  | TIFF  | ZST  |
| AVIF  | DOCX | ICO  | MP3  | PPTX | TTF   | CSS  |
| APK   | DMG  | ISO  | MP4  | PS   | WEBM  | FLAC |
| BIN   | EJS  | JAR  | OGG  | RAR  | WEBP  | MID  |
| BMP   | EOT  | JPG  | OTF  | SVG  | WOFF  | PLS  |
| BZ2   | EPS  | JPEG | PDF  | SVGZ | WOFF2 | TAR  |
| CLASS | EXE  | JS   | PICT | SWF  | XLS   | XLSX |

例外和绕过：

* 如果返回的 Content-Type 是 application/octet-stream，则扩展名无关紧要，因为这通常是指示浏览器保存资产而不是显示它的信号。
* CloudFlare 允许将 .jpg 作为 image/webp 提供或 .gif 作为 video/webm 提供，以及其他我们认为不太可能是攻击的情况。
* [使用 .avif 扩展名文件绕过缓存欺骗防护 - 已修复](https://hackerone.com/reports/1391635)

## 实验室

* [Web 缓存欺骗的 PortSwigger 实验室](https://portswigger.net/web-security/all-labs#web-cache-poisoning)

## 参考文献

* [缓存欺骗防护 - CloudFlare - 2023年5月20日](https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/)
* [利用缓存设计缺陷 - PortSwigger - 2020年5月4日](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
* [利用缓存实现缺陷 - PortSwigger - 2020年5月4日](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
* [我如何测试 Web 缓存漏洞 + 技巧和窍门 - bombon (0xbxmbn) - 2022年7月21日](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)
* [OpenAI 账户接管 - Nagli (@naglinagli) - 2023年3月24日](https://twitter.com/naglinagli/status/1639343866313601024)
* [实用的 Web 缓存中毒 - James Kettle (@albinowax) - 2018年8月9日](https://portswigger.net/blog/practical-web-cache-poisoning)
* [Shockwave 识别影响 OpenAI ChatGPT 的 Web 缓存欺骗和账户接管漏洞 - Nagli (@naglinagli) - 2024年7月15日](https://www.shockwave.cloud/blog/shockwave-works-with-openai-to-fix-critical-chatgpt-vulnerability)
* [Web 缓存欺骗攻击 - Omer Gil - 2017年2月27日](http://omergil.blogspot.fr/2017/02/web-cache-deception-attack.html)
* [Web 缓存欺骗攻击导致用户信息泄露 - Kunal Pandey (@kunal94) - 2019年2月25日](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)
* [Web 缓存纠缠：中毒的新途径 - James Kettle (@albinowax) - 2020年8月5日](https://portswigger.net/research/web-cache-entanglement)
* [Web 缓存中毒 - PortSwigger - 2020年5月4日](https://portswigger.net/web-security/web-cache-poisoning)