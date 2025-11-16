[原文文档](README.en.md)

# DNS重新绑定

> DNS重新绑定将攻击者控制机器名称的IP地址更改为目标应用程序的IP地址，绕过[同源策略](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)，从而允许浏览器向目标应用程序发出任意请求并读取其响应。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
* [保护绕过](#保护绕过)
    * [0.0.0.0](#0000)
    * [CNAME](#cname)
    * [localhost](#localhost)
* [参考资料](#参考资料)

## 工具

* [nccgroup/singularity](https://github.com/nccgroup/singularity) - DNS重新绑定攻击框架。
* [rebind.it](http://rebind.it/) - 源Web客户端奇点。
* [taviso/rbndr](https://github.com/taviso/rbndr) - 简单DNS重新绑定服务
* [taviso/rebinder](https://lock.cmpxchg8b.com/rebinder.html) - rbndr工具助手

## 方法论

**设置阶段**：

* 注册恶意域名（例如，`malicious.com`）。
* 配置能够将`malicious.com`解析为不同IP地址的自定义DNS服务器。

**初始受害者交互**：

* 在`malicious.com`上创建包含恶意JavaScript或其他利用机制的网页。
* 引诱受害者访问恶意网页（例如，通过网络钓鱼、社会工程或广告）。

**初始DNS解析**：

* 当受害者的浏览器访问`malicious.com`时，它查询攻击者的DNS服务器以获取IP地址。
* DNS服务器将`malicious.com`解析为初始的、看起来合法的IP地址（例如，203.0.113.1）。

**重新绑定到内部IP**：

* 在浏览器的初始请求之后，攻击者的DNS服务器将`malicious.com`的解析更新为私有或内部IP地址（例如，192.168.1.1，对应受害者的路由器或其他内部设备）。

这通常通过为初始DNS响应设置非常短的TTL（生存时间）来实现，强制浏览器重新解析域。

**同源利用：**

浏览器将后续响应视为来自同一源（`malicious.com`）。

在受害者浏览器中运行的恶意JavaScript现在可以向内部IP地址或本地服务（例如，192.168.1.1或127.0.0.1）发出请求，绕过同源策略限制。

**示例：**

1. 注册域名。
2. [设置源奇点](https://github.com/nccgroup/singularity/wiki/Setup-and-Installation)。
3. 根据需要编辑[自动攻击HTML页面](https://github.com/nccgroup/singularity/blob/master/html/autoattack.html)。
4. 浏览到`http://rebinder.your.domain:8080/autoattack.html`。
5. 等待攻击完成（可能需要几秒/分钟）。

## 保护绕过

> 大多数DNS保护以阻止在边界处包含不需要IP地址的DNS响应的形式实现，当DNS响应进入内部网络时。最常见的保护形式是阻止RFC 1918中定义的私有IP地址（即10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）。一些工具还允许阻止localhost（127.0.0.0/8）、本地（内部）网络或0.0.0.0/0网络范围。

在启用DNS保护的情况下（通常默认禁用），NCC Group记录了多种可用于的[DNS保护绕过](https://github.com/nccgroup/singularity/wiki/Protection-Bypasses)。

### 0.0.0.0

我们可以使用IP地址0.0.0.0来访问localhost（127.0.0.1）以绕过阻止包含127.0.0.1或127.0.0.0/8的DNS响应的过滤器。

### CNAME

我们可以使用DNS CNAME记录来绕过阻止所有内部IP地址的DNS保护解决方案。
由于我们的响应只会返回内部服务器的CNAME，
过滤内部IP地址的规则不会应用。
然后，本地内部DNS服务器将解析CNAME。

```bash
$ dig cname.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
cname.example.com.            381     IN      CNAME   target.local.
```

### localhost

我们可以使用"localhost"作为DNS CNAME记录来绕过阻止包含127.0.0.1的DNS响应的过滤器。

```bash
$ dig www.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
localhost.example.com.            381     IN      CNAME   localhost.
```

## 参考资料

* [DNS重新绑定攻击如何工作？ - nccgroup - 2019年4月9日](https://github.com/nccgroup/singularity/wiki/How-Do-DNS-Rebinding-Attacks-Work%3F)