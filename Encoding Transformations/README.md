[原文文档](README.en.md)

# 编码和转换

> 编码和转换是改变数据表示或传输方式而不改变其核心含义的技术。常见示例包括URL编码、Base64、HTML实体编码和Unicode转换。攻击者使用这些方法作为绕过输入过滤器、逃避Web应用程序防火墙或突破清理程序的工具。

## 摘要

* [Unicode](#unicode)
    * [Unicode标准化](#unicode标准化)
    * [Punycode](#punycode)
* [Base64](#base64)
* [实验室](#实验室)
* [参考资料](#参考资料)

## Unicode

Unicode是用于表示世界上几乎每个书写系统的文本的通用字符编码标准。每个字符（字母、数字、符号、表情符号）都被分配一个唯一的代码点（例如，"A"的U+0041）。UTF-8和UTF-16等Unicode编码格式指定了这些代码点如何作为字节存储。

### Unicode标准化

Unicode标准化是将Unicode文本转换为标准化、一致形式的过程，以便等效字符在内存中以相同方式表示。

[Unicode标准化参考表](https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html)

* **NFC**（标准化形式规范组合）：将分解的序列组合为预组合字符（如果可能）。
* **NFD**（标准化形式规范分解）：将字符分解为其分解形式（基础+组合标记）。
* **NFKC**（标准化形式兼容性组合）：类似NFC，但也用兼容性等效字符替换字符（可能改变外观/格式）。
* **NFKD**（标准化形式兼容性分解）：类似NFD，但也分解兼容性字符。

| 字符    | 有效载荷               | 标准化后   |
| ------------ | --------------------- | --------------------- |
| `‥` (U+2025) | `‥/‥/‥/etc/passwd` | `../../../etc/passwd` |
| `︰` (U+FE30) | `︰/︰/︰/etc/passwd` | `../../../etc/passwd` |
| `＇` (U+FF07) | `＇ or ＇1＇=＇1` | `' or '1'='1` |
| `＂` (U+FF02) | `＂ or ＂1＂=＂1` | `" or "1"="1` |
| `﹣` (U+FE63) | `admin'﹣﹣` | `admin'--` |
| `。` (U+3002) | `domain。com` | `domain.com` |
| `／` (U+FF0F) | `／／domain.com` | `//domain.com` |
| `＜` (U+FF1C) | `＜img src=a＞` | `<img src=a/>` |
| `﹛` (U+FE5B) | `﹛﹛3+3﹜﹜` | `{{3+3}}` |
| `［` (U+FF3B) | `［［5+5］］` | `[[5+5]]` |
| `＆` (U+FF06) | `＆＆whoami` | `&&whoami` |
| `ｐ` (U+FF50) | `shell.ｐʰｐ` | `shell.php` |
| `ʰ` (U+02B0) | `shell.ｐʰｐ` | `shell.php` |
| `ª` (U+00AA) | `ªdmin` | `admin` |

```py
import unicodedata
string = "ᴾᵃʸˡᵒᵃᵈˢ𝓐𝓵𝓵𝕋𝕙𝕖𝒯𝒽𝒾𝓷ℊ𝓈"
print ('NFC: ' + unicodedata.normalize('NFC', string))
print ('NFD: ' + unicodedata.normalize('NFD', string))
print ('NFKC: ' + unicodedata.normalize('NFKC', string))
print ('NFKD: ' + unicodedata.normalize('NFKD', string))
```

### Punycode

Punycode是一种表示Unicode字符（包括非ASCII字母、符号和脚本）的方法，仅使用有限的ASCII字符集（字母、数字和连字符）。

它主要用于域名系统（DNS），传统上只支持ASCII。Punycode允许国际化域名（IDN），以便域名可以通过将字符转换为安全的ASCII形式来包含来自许多语言的字符。

| 浏览器中可见（IDN支持） | 实际ASCII (Punycode) |
| -------------------------------- | ----------------------- |
| раypal.com                       | xn--ypal-43d9g.com      |
| paypal.com                       | paypal.com              |

在MySQL中，相似字符被视为相等。这种行为可以在密码重置、忘记密码和OAuth提供商部分中被滥用。

```sql
SELECT 'a' = 'ᵃ';
+-------------+
| 'a' = 'ᵃ'   |
+-------------+
|           1 |
+-------------+
```

这个技巧适用于SQL查询使用`COLLATE utf8mb4_0900_as_cs`。

```sql
SELECT 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs;
+----------------------------------------+
| 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs   |
+----------------------------------------+
|                                      0 |
+----------------------------------------+
```

## Base64

Base64编码是一种将二进制数据（如图像或文件）或带有特殊字符的文本转换为可读字符串的方法，该字符串仅使用ASCII字符（A-Z、a-z、0-9、+和/）。输入的每3个字节被分为4组6位，并映射到4个Base64字符。如果输入不是3字节的倍数，输出用`=`字符填充。

```ps1
echo -n admin | base64                            
YWRtaW4=

echo -n YWRtaW4= | base64 -d
admin
```

## 实验室

* [NahamCon - Puny-Code: 0-Click账户接管](https://github.com/VoorivexTeam/white-box-challenges/tree/main/punycode)
* [PentesterLab - Unicode和NFKC](https://pentesterlab.com/exercises/unicode-transform)

## 参考资料

* [Puny-Code，0-Click账户接管 - Voorivex - 2025年6月1日](https://blog.voorivex.team/puny-code-0-click-account-takeover)
* [Unicode标准化漏洞 - Lazar - 2021年9月30日](https://lazarv.com/posts/unicode-normalization-vulnerabilities/)
* [Unicode标准化漏洞和特殊K多语言 - AppCheck - 2019年9月2日](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
* [使用Unicode兼容性绕过WAF - Jorge Lajara - 2020年2月19日](https://jlajara.gitlab.io/Bypass_WAF_Unicode)
* [当"Zoë" !== "Zoë"时。为什麼你需要标准化Unicode字符串 - Alessandro Segala - 2019年3月11日](https://withblue.ink/2019/03/11/why-you-need-to-normalize-unicode-strings.html)
