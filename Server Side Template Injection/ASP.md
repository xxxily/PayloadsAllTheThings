[原文文档](ASP.en.md)

# 服务器端模板注入 - ASP.NET

> 服务器端模板注入（SSTI）是一类漏洞，攻击者可以向服务器端模板注入恶意输入，导致模板引擎在服务器上执行任意代码。在ASP.NET上下文中，如果用户输入直接嵌入到模板（如Razor、ASPX或其他模板引擎）中而没有适当的清理，则可能发生SSTI。

## 概述

- [ASP.NET Razor](#aspnet-razor)
    - [ASP.NET Razor - 基本注入](#aspnet-razor---基本注入)
    - [ASP.NET Razor - 命令执行](#aspnet-razor---命令执行)
- [参考资料](#参考资料)

## ASP.NET Razor

[官方网站](https://docs.microsoft.com/en-us/aspnet/web-pages/overview/getting-started/introducing-razor-syntax-c)

> Razor是一种标记语法，允许你将基于服务器的代码（Visual Basic和C#）嵌入到网页中。

### ASP.NET Razor - 基本注入

```powershell
@(1+2)
```

### ASP.NET Razor - 命令执行

```csharp
@{
  // C# code
}
```

## 参考资料

- [ASP.NET Razor中的服务器端模板注入（SSTI） - Clément Notin - 2020年4月15日](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)