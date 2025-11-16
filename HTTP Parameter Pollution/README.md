[原文文档](README.en.md)

# HTTP 参数污染

> HTTP 参数污染 (HPP) 是一种Web攻击规避技术，允许攻击者构造HTTP请求以操纵Web逻辑或检索隐藏信息。这种规避技术基于在同名参数的多个实例之间拆分攻击向量（?param1=value&param1=value）。由于没有正式的方法来解析HTTP参数，各个Web技术都有自己的独特方式来解析和读取同名URL参数。有些取第一个出现的值，有些取最后一个出现的值，有些则将其读取为数组。攻击者利用这种行为来绕过基于模式的安全机制。

## 目录

* [工具](#工具)
* [方法论](#方法论)
    * [参数污染表](#参数污染表)
    * [参数污染载荷](#参数污染载荷)
* [参考资料](#参考资料)

## 工具

* **Burp Suite**: 手动修改请求以测试重复参数。
* **OWASP ZAP**: 拦截和操作HTTP参数。

## 方法论

HTTP参数污染（HPP）是一种Web安全漏洞，攻击者在请求中注入同一HTTP参数的多个实例。服务器在处理重复参数时的行为可能各不相同，可能导致意外或可利用的行为。

HPP可以针对两个级别：

* 客户端HPP：利用在客户端（浏览器）上运行的JavaScript代码。
* 服务器端HPP：利用服务器如何处理同名的多个参数。

**示例**:

```ps1
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```

### 参数污染表

当 ?par1=a&par1=b 时

| 技术                                      | 解析结果                  | 结果 (par1=) |
| ----------------------------------------- | ------------------------ | ------------ |
| ASP.NET/IIS                               | 所有出现的值             | a,b           |
| ASP/IIS                                   | 所有出现的值             | a,b           |
| Golang net/http - `r.URL.Query().Get("param")`  | 第一个出现的值           | a             |
| Golang net/http - `r.URL.Query()["param"]`      | 数组中的所有出现值       | ['a','b']     |
| IBM HTTP Server                           | 第一个出现的值           | a             |
| IBM Lotus Domino                          | 第一个出现的值           | a             |
| JSP,Servlet/Tomcat                        | 第一个出现的值           | a             |
| mod_wsgi (Python)/Apache                  | 第一个出现的值           | a             |
| Nodejs                                    | 所有出现的值             | a,b           |
| Perl CGI/Apache                           | 第一个出现的值           | a             |
| Perl CGI/Apache                           | 第一个出现的值           | a             |
| PHP/Apache                                | 最后一个出现的值         | b             |
| PHP/Zues                                  | 最后一个出现的值         | b             |
| Python Django                             | 最后一个出现的值         | b             |
| Python Flask                              | 第一个出现的值           | a             |
| Python/Zope                               | 数组中的所有出现值       | ['a','b']     |
| Ruby on Rails                             | 最后一个出现的值         | b             |

### 参数污染载荷

* 重复参数:

    ```ps1
    param=value1&param=value2
    ```

* 数组注入:

    ```ps1
    param[]=value1
    param[]=value1&param[]=value2
    param[]=value1&param=value2
    param=value1&param[]=value2
    ```

* 编码注入:

    ```ps1
    param=value1%26other=value2
    ```

* 嵌套注入:

    ```ps1
    param[key1]=value1&param[key2]=value2
    ```

* JSON注入:

    ```ps1
    {
        "test": "user",
        "test": "admin"
    }
    ```

## 参考资料

* [How to Detect HTTP Parameter Pollution Attacks - Acunetix - January 9, 2024](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)
* [HTTP Parameter Pollution - Itamar Verta - December 20, 2023](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
* [HTTP Parameter Pollution in 11 minutes - PwnFunction - January 28, 2019](https://www.youtube.com/watch?v=QVZBl8yxVX0&ab_channel=PwnFunction)