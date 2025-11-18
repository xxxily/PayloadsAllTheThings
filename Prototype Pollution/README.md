[原文文档](README.en.md)

# 原型污染

> 原型污染是JavaScript中发生的一种漏洞类型，当Object.prototype的属性被修改时就会发生。这特别危险，因为JavaScript对象是动态的，我们可以随时向它们添加属性。此外，JavaScript中几乎所有对象都从Object.prototype继承，使其成为潜在的攻击向量。

## 摘要

* [工具](#tools)
* [方法论](#methodology)
    * [示例](#examples)
    * [手动测试](#manual-testing)
    * [通过JSON输入的原型污染](#prototype-pollution-via-json-input)
    * [URL中的原型污染](#prototype-pollution-in-url)
    * [原型污染载荷](#prototype-pollution-payloads)
    * [原型污染gadget](#prototype-pollution-gadgets)
* [实验环境](#labs)
* [参考资料](#references)

## 工具

* [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder) - 帮助您找到原型污染利用的gadget
* [yuske/silent-spring](https://github.com/yuske/silent-spring) - 原型污染导致Node.js中的远程代码执行
* [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) - Node.js核心代码和第三方NPM包中的服务器端原型污染gadget
* [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) - 原型污染和有用的脚本Gadget
* [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution) - Burp Suite扩展检测原型污染漏洞
* [msrkp/PPScan](https://github.com/msrkp/PPScan) - 客户端原型污染扫描器

## 方法论

在JavaScript中，原型是什么允许对象从其他对象继承特性。如果攻击者能够添加或修改`Object.prototype`的属性，他们基本上可以影响从该原型继承的所有对象，可能导致各种安全风险。