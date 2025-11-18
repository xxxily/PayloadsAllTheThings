[原文文档](README.en.md)

# 正则表达式

> 正则表达式拒绝服务（ReDoS）是一种攻击类型，它利用某些正则表达式可能需要极长时间处理的事实，导致应用程序或服务变得无响应或崩溃。

## 摘要

* [工具](#tools)
* [方法论](#methodology)
    * [邪恶正则表达式](#evil-regex)
    * [回溯限制](#backtrack-limit)
* [参考资料](#references)

## 工具

* [tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector) - 一个CLI和库，它确实测试正则表达式模式是否安全免受ReDoS攻击。支持的浏览器、Node和Deno。
* [doyensec/regexploit](https://github.com/doyensec/regexploit) - 查找容易受到ReDoS（正则表达式拒绝服务）攻击的正则表达式
* [devina.io/redos-checker](https://devina.io/redos-checker) - 检查正则表达式是否存在潜在的拒绝服务漏洞

## 方法论

### 邪恶正则表达式

邪恶正则表达式包含：

* 带重复的分组
* 在重复组内：
    * 重复
    * 重叠的交替

**示例**：

* `(a+)+`
* `([a-zA-Z]+)*`
* `(a|aa)+`
* `(a|a?)+`
* `(.*a){x}` for x \> 10

这些正则表达式可以用`aaaaaaaaaaaaaaaaaaaaaaaa!`（20个'a'后跟一个'!'）来利用。

```ps1
aaaaaaaaaaaaaaaaaaaa! 
```

对于此输入，正则表达式引擎将尝试所有可能的方式来分组'a'字符，然后才意识到由于'！'字符匹配最终失败。这导致回溯尝试的爆炸。

### 回溯限制

正则表达式中的回溯发生在正则表达式引擎尝试匹配模式并遇到不匹配时。然后引擎回溯到前一个匹配位置并尝试替代路径来查找匹配。此过程可以重复多次，特别是对于复杂模式和大型输入字符串。

**PHP PCRE配置选项**：

| 名称                | 默认值 | 备注 |
|---------------------|--------|---------|
| pcre.backtrack_limit| 1000000| `PHP < 5.3.7`为100000|
| pcre.recursion_limit| 100000 | / |
| pcre.jit            | 1      | / |

有时有可能强制正则表达式超过100,000次递归，这会导致ReDOS并使`preg_match`返回false：

```php
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';

if (preg_match($pattern, $subject)) {
    echo "Match found";
} else {
    echo "No match";
}
```

## 参考资料

* [Intigriti Challenge 1223 - Hackbook Of A Hacker - December 21, 2023](https://simones-organization-4.gitbook.io/hackbook-of-a-hacker/ctf-writeups/intigriti-challenges/1223)
* [MyBB Admin Panel RCE CVE-2023-41362 - SorceryIE - September 11, 2023](https://blog.sorcery.ie/posts/mybb_acp_rce/)
* [OWASP Validation Regex Repository - OWASP - March 14, 2018](https://wiki.owasp.org/index.php/OWASP_Validation_Regex_Repository)
* [PCRE > Installing/Configuring - PHP Manual - May 3, 2008](https://www.php.net/manual/en/pcre.configuration.php#ini.pcre.recursion-limit)
* [Regular expression Denial of Service - ReDoS - Adar Weidman - December 4, 2019](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)