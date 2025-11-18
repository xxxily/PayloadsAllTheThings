[原文文档](README.en.md)

# SQL注入

> SQL注入（SQLi）是一种安全漏洞类型，允许攻击者干扰应用程序对其数据库的查询。SQL注入是最常见和严重的Web应用程序漏洞类型之一，使攻击者能够在数据库上执行任意SQL代码。这可能导致未经授权的数据访问、数据操作，在某些情况下，还可能导致数据库服务器的完全妥协。

## 摘要

* [速查表](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/)
    * [MSSQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
    * [MySQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
    * [OracleSQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)
    * [PostgreSQL注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
    * [SQLite注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
    * [Cassandra注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md)
    * [DB2注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/DB2%20Injection.md)
    * [SQLmap](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLmap.md)
* [工具](#tools)
* [入口点检测](#entry-point-detection)
* [DBMS识别](#dbms-identification)
* [身份验证绕过](#authentication-bypass)
    * [原始MD5和SHA1](#raw-md5-and-sha1)
* [基于UNION的注入](#union-based-injection)
* [基于错误的注入](#error-based-injection)
* [盲注](#blind-injection)
    * [基于布尔的注入](#boolean-based-injection)
    * [盲错误基础注入](#blind-error-based-injection)
    * [基于时间的注入](#time-based-injection)
    * [带外（OAST）](#out-of-band-oast)
* [基于堆叠的注入](#stacked-based-injection)
* [多语言注入](#polyglot-injection)
* [路由注入](#routed-injection)