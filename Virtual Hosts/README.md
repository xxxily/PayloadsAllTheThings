[原文文档](README.en.md)

# 虚拟主机

> **虚拟主机**（VHOST）是 Web 服务器（例如 Apache、Nginx、IIS）用于在单个 IP 地址上托管多个域或子域的机制。在枚举 Web 服务器时，默认请求通常仅针对主要或默认 VHOST。**隐藏主机**可能暴露额外功能或漏洞。

## 概述

* [工具](#工具)
* [方法论](#方法论)
* [参考文献](#参考文献)

## 工具

* [wdahlenburg/VhostFinder](https://github.com/wdahlenburg/VhostFinder) - 通过相似性比较识别虚拟主机。
* [codingo/VHostScan](https://github.com/codingo/VHostScan) - 可与透视工具一起使用的虚拟主机扫描器，检测通配符场景、别名和动态默认页面。
* [hakluke/hakoriginfinder](https://github.com/hakluke/hakoriginfinder) - 用于发现反向代理后面的原始主机的工具。对绕过云 WAF 很有用。

    ```ps1
    prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo
    ```

* [OJ/gobuster](https://github.com/OJ/gobuster) - 用 Go 编写的目录/文件、DNS 和 VHost 暴力破解工具。

    ```ps1
    gobuster vhost -u https://example.com -w /path/to/wordlist.txt
    ```

## 方法论

当 Web 服务器在同一个 IP 地址上托管多个网站时，它使用**虚拟主机**来决定在请求到来时提供哪个网站。

在 HTTP/1.1 及以上版本中，每个请求必须包含 `Host` 头：

```http
GET / HTTP/1.1
Host: example.com
```

此头告诉服务器客户端试图访问哪个域。

* 如果服务器只有一个站点：`Host` 头通常被忽略或设置为默认值。
* 如果服务器有多个虚拟主机：Web 服务器使用 `Host` 头在内部将请求路由到正确的内容。

假设服务器配置如下：

```ps1
<VirtualHost *:80>
    ServerName site-a.com
    DocumentRoot /var/www/a
</VirtualHost>

<VirtualHost *:80>
    ServerName site-b.com
    DocumentRoot /var/www/b
</VirtualHost>
```

带有默认主机（"site-a.com"）的请求返回站点 A 的内容。

```http
GET / HTTP/1.1
Host: site-a.com
```

带有更改主机（"site-b.com"）的请求返回站点 B 的内容（可能揭示新内容）。

```http
GET / HTTP/1.1
Host: site-b.com
```

### VHOST 指纹识别

将 `Host` 设置为其他已知或猜测的域可能会给出**不同的响应**。

```ps1
curl -H "Host: admin.example.com" http://10.10.10.10/
```

表明您正在访问不同 VHOST 的常见指标：

* 不同的 HTML 标题、元描述或品牌名称
* 不同的 HTTP Content-Length / 主体大小
* 不同的状态码（200 vs. 403 或重定向）
* 自定义错误页面
* 重定向链到完全不同的域
* 具有主题备用名称列出其他域的证书

**注意**：利用 DNS 历史记录来识别以前与您目标的域关联的旧 IP 地址。然后针对这些 IP 测试（或"喷射"）当前域名。如果成功，这可以揭示服务器的真实地址，允许您通过直接与原始服务器交互来绕过 Cloudflare 或其他 WAF 等保护。

## 参考文献

* [Gobuster 用于目录、DNS 和虚拟主机暴力破解 - erev0s - 2020年3月17日](https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/)
* [虚拟主机 - 一种被遗忘的枚举技术 - Wyatt Dahlenburg - 2022年6月16日](https://wya.pl/2022/06/16/virtual-hosting-a-well-forgotten-enumeration-technique/)