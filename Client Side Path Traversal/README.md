# 客户端路径遍历

[原文文档](README.en.md)

> 客户端路径遍历 (CSPT)，有时也称为"站内请求伪造"，是一种可以作为 CSRF 或 XSS 攻击工具来利用的漏洞。它利用客户端能够使用 fetch 向 URL 发送请求的能力，其中可以注入多个"../"字符。规范化后，这些字符将请求重定向到不同的 URL，可能导致安全漏洞。
> 由于每个请求都是从应用程序的前端发起的，浏览器会自动包含 cookie 和其他认证机制，使它们在攻击中可以被利用。

## 概要

* [工具](#工具)
* [方法论](#方法论)
    * [CSPT 到 XSS](#cspt-到-xss)
    * [CSPT 到 CSRF](#cspt-到-csrf)
* [实验室](#实验室)
* [参考资料](#参考资料)

## 工具

* [doyensec/CSPTBurpExtension](https://github.com/doyensec/CSPTBurpExtension) - CSPT 是一个开源的 Burp Suite 扩展，用于查找和利用客户端路径遍历。

## 方法论

### CSPT 到 XSS

![cspt-query-param](https://matanber.com/images/blog/cspt-query-param.png)

服务后页面调用 fetch 函数，向带有攻击者控制输入的 URL 发送请求，该输入在其路径中未被正确编码，允许攻击者向路径注入"../"序列，使请求被发送到任意端点。这种行为被称为 CSPT 漏洞。

**示例**：

* 页面 `https://example.com/static/cms/news.html` 接受 `newsitemid` 作为参数
* 然后获取 `https://example.com/newitems/<newsitemid>` 的内容
* 在 `https://example.com/pricing/default.js` 中通过 `cb` 参数也发现了文本注入
* 最终载荷为 `https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//`

### CSPT 到 CSRF

CSPT 重定向合法的 HTTP 请求，允许前端为 API 调用添加必要的令牌，如认证或 CSRF 令牌。这种能力可能被利用来规避现有的 CSRF 保护措施。

|                                             | CSRF               | CSPT2CSRF          |
| ------------------------------------------- | -----------------  | ------------------ |
| POST CSRF ?                                 | :white_check_mark: | :white_check_mark: |
| 可以控制正文吗？                           | :white_check_mark: | :x:                |
| 可以使用 anti-CSRF 令牌吗？               | :x:                | :white_check_mark: |
| 可以与 Samesite=Lax 一起工作吗？          | :x:                | :white_check_mark: |
| GET / PATCH / PUT / DELETE CSRF ?          | :x:                | :white_check_mark: |
| 1-click CSRF ?                             | :x:                | :white_check_mark: |
| 影响是否取决于源和接收器？                | :x:                | :white_check_mark: |

现实世界场景：

* Rocket.Chat 中的 1-click CSPT2CSRF
* CVE-2023-45316：Mattermost 中带有 POST 接收器的 CSPT2CSRF：`/<team>/channels/channelname?telem_action=under_control&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate`
* CVE-2023-6458：Mattermost 中带有 GET 接收器的 CSPT2CSRF
* [客户端路径操作 - erasec.be](https://www.erasec.be/blog/client-side-path-manipulation/)：CSPT2CSRF `https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=`
* [CVE-2023-5123：Grafana 的 JSON API 插件中的 CSPT2CSRF](https://medium.com/@maxime.escourbiac/grafana-cve-2023-5123-write-up-74e1be7ef652)

## 实验室

* [doyensec/CSPTPlayground](https://github.com/doyensec/CSPTPlayground) - CSPTPlayground 是一个开源的游乐场，用于查找和利用客户端路径遍历 (CSPT)。
* [Root Me - CSPT - The Ruler](https://www.root-me.org/en/Challenges/Web-Client/CSPT-The-Ruler)

## 参考资料

* [利用客户端路径遍历执行跨站请求伪造 - 介绍 CSPT2CSRF - Maxence Schmitt - 2024年7月2日](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)
* [利用客户端路径遍历 - CSRF 已死，CSRF 万岁 - 白皮书 - Maxence Schmitt - 2024年7月2日](https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf)
* [利用客户端路径遍历 - CSRF 已死，CSRF 万岁 - OWASP 全球 AppSec 2024 - Maxence Schmitt - 2024年6月24日](https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_OWASP_Appsec_Lisbon.pdf)
* [泄露 Jupyter 实例认证令牌链式利用 CVE-2023-39968、CVE-2024-22421 和 chromium bug - Davwwwx - 2023年8月30日](https://blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/)
* [站内请求伪造 - Dafydd Stuttard - 2007年5月3日](https://portswigger.net/blog/on-site-request-forgery)
* [绕过 WAF 利用 CSPT 使用编码级别 - Matan Berson - 2024年5月10日](https://matanber.com/blog/cspt-levels)
* [自动化客户端路径遍历发现 - Vitor Falcao - 2024年10月3日](https://vitorfalcao.com/posts/automating-cspt-discovery/)
* [CSPT the Eval Villain Way! - Dennis Goodlett - 2024年12月3日](https://blog.doyensec.com/2024/12/03/cspt-with-eval-villain.html)
* [绕过文件上传限制以利用客户端路径遍历 - Maxence Schmitt - 2025年1月9日](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)