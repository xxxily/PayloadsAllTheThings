[原文文档](README.en.md)

# HTTP 隐藏参数

> Web 应用程序通常具有在用户界面中未公开的隐藏或未记录的参数。模糊测试可以帮助发现这些参数，这些参数可能容易受到各种攻击。

## 目录

* [工具](#工具)
* [方法论](#方法论)
    * [暴力破解参数](#暴力破解参数)
    * [旧参数](#旧参数)
* [参考资料](#参考资料)

## 工具

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - 用于识别隐藏、未链接参数的 Burp 扩展。
* [s0md3v/Arjun](https://github.com/s0md3v/Arjun) - HTTP 参数发现套件
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8) - 隐藏参数发现套件
* [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) - 获取 Wayback Machine 知道的某个域的所有 URL
* [devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) - 从 Web 档案的隐蔽角落挖掘 URL 用于漏洞挖掘/模糊测试/进一步探测

## 方法论

### 暴力破解参数

* 使用常见参数的字典列表发送请求，观察后端的异常行为。

    ```ps1
    x8 -u "https://example.com/" -w <wordlist>
    x8 -u "https://example.com/" -X POST -w <wordlist>
    ```

字典列表示例：

* [Arjun/large.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt)
* [Arjun/medium.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt)
* [Arjun/small.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt)
* [samlists/sam-cc-parameters-lowercase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt)
* [samlists/sam-cc-parameters-mixedcase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt)

### 旧参数

探索目标的所有 URL 以查找旧参数。

* 浏览 [Wayback Machine](http://web.archive.org/)
* 查看 JS 文件以发现未使用的参数

## 参考资料

* [Hacker tools: Arjun – The parameter discovery tool - Intigriti - May 17, 2021](https://blog.intigriti.com/2021/05/17/hacker-tools-arjun-the-parameter-discovery-tool/)
* [Parameter Discovery: A quick guide to start - YesWeHack - April 20, 2022](http://web.archive.org/web/20220420123306/https://blog.yeswehack.com/yeswerhackers/parameter-discovery-quick-guide-to-start)