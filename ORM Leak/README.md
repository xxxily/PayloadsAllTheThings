[原文文档](README.en.md)

# ORM 泄露

> 当由于ORM查询处理不当而导致敏感信息（如数据库结构或用户数据）被无意中暴露时，就会发生ORM泄露漏洞。如果应用程序返回原始错误消息、调试信息或允许攻击者以揭示底层数据的方式操作查询，就会发生这种情况。

## 摘要

* [Django (Python)](#django-python)
    * [查询过滤器](#query-filter)
    * [关系过滤](#relational-filtering)
        * [一对一](#one-to-one)
        * [多对多](#many-to-many)
    * [基于错误的泄露 - ReDOS](#error-based-leaking---redos)
* [Prisma (Node.JS)](#prisma-nodejs)
    * [关系过滤](#relational-filtering-1)
        * [一对一](#one-to-one-1)
        * [多对多](#many-to-many-1)
* [Ransack (Ruby)](#ransack-ruby)
* [CVE](#cve)
* [参考资料](#references)

## Django (Python)

以下代码是ORM查询数据库的基本示例。

```py
users = User.objects.filter(**request.data)
serializer = UserSerializer(users, many=True)
```

问题在于Django ORM如何使用关键字参数语法构建QuerySet。通过利用解包操作符（`**`），用户可以动态控制传递给filter方法的关键字参数，允许他们根据需要过滤结果。