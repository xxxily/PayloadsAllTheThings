[原文文档](README.en.md)

# 依赖混淆

> 依赖混淆攻击或供应链替换攻击发生在软件安装脚本被诱骗从公共仓库拉取恶意代码文件，而不是从内部仓库拉取相同名称的预期文件时。

## 摘要

* [工具](#工具)
* [方法论](#方法论)
    * [NPM示例](#npm示例)
* [参考资料](#参考资料)

## 工具

* [visma-prodsec/confused](https://github.com/visma-prodsec/confused) - 用于检查多个包管理系统中依赖混淆漏洞的工具
* [synacktiv/DepFuzzer](https://github.com/synacktiv/DepFuzzer) - 用于查找依赖混淆或所有者邮箱可以被接管的项目的工具

## 方法论

查找`npm`、`pip`、`gem`包，方法论是相同的：您注册一个与公司使用的私有包同名的公共包，然后等待它被使用。

* **DockerHub**: Dockerfile镜像
* **JavaScript** (npm): package.json
* **MVN** (maven): pom.xml
* **PHP** (composer): composer.json
* **Python** (pypi): requirements.txt

### NPM示例

* 列出所有包（即：package.json, composer.json, ...）
* 找到在[www.npmjs.com](https://www.npmjs.com/)上缺失的包
* 注册并创建一个具有相同名称的**公共**包
    * 包示例：[0xsapra/dependency-confusion-expoit](https://github.com/0xsapra/dependency-confusion-expoit)

## 参考资料

* [利用依赖混淆 - Aman Sapra (0xsapra) - 2021年7月2日](https://0xsapra.github.io/website//Exploiting-Dependency-Confusion)
* [依赖混淆：如何入侵苹果、微软和其他数十家公司 - Alex Birsan - 2021年2月9日](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
* [使用私有包源时缓解风险的3种方法 - Microsoft - 2021年3月29日](https://web.archive.org/web/20210210121930/https://azure.microsoft.com/en-gb/resources/3-ways-to-mitigate-risk-using-private-package-feeds/)
* [$130,000+ 在2021年学习新黑客技术 - 依赖混淆 - 漏洞赏金报告解释 - 2021年2月22日](https://www.youtube.com/watch?v=zFHJwehpBrU)