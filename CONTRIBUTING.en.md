[原文文档](CONTRIBUTING.en.md)

# 贡献指南

PayloadsAllTheThings 团队 :heart: 拉取请求。

欢迎使用您的有效载荷和技术来改进！

您还可以通过 :beers: 线下方式贡献，或使用 [赞助](https://github.com/sponsors/swisskyrepo) 按钮。

## 拉取请求指南

为了为社区提供最安全的有效载荷，**每个** 拉取请求都必须遵循以下规则。

- 有效载荷必须经过清理
    - 对于 RCE 概念验证，使用 `id` 和 `whoami`
    - 当用户需要替换回调域名时使用 `[REDACTED]`。例如：XSSHunter、BurpCollaborator 等。
    - 当有效载荷需要 IP 地址时使用 `10.10.10.10` 和 `10.10.10.11`
    - 为特权用户使用 `Administrator`，为普通账户使用 `User`
    - 在示例中使用 `P@ssw0rd`、`Password123`、`password` 作为默认密码
    - 优先使用常用的机器名称，如 `DC01`、`EXCHANGE01`、`WORKSTATION01` 等
- 引用必须包含 `author`、`title`、`link` 和 `date`
    - 如果引用已不可用，请使用 [ Wayback Machine ](https://web.archive.org/)
    - 日期必须遵循 `Month Number, Year` 格式，例如：`December 25, 2024`
    - 对 GitHub 仓库的引用必须遵循此格式：`[author/tool](https://github.com/URL) - Description`

每个拉取请求都会使用 `markdownlint` 进行检查，以确保一致的写作和 Markdown 最佳实践。您可以使用以下 Docker 命令在本地验证您的文件：

```ps1
docker run -v $PWD:/workdir davidanson/markdownlint-cli2:v0.15.0 "**/*.md" --config .github/.markdownlint.json --fix
```

## 技术文件夹

每个部分应包含以下文件，您可以使用 `_template_vuln` 文件夹来创建新的技术文件夹：

- **README.md**：漏洞描述及其利用方法，包括多个有效载荷，更多内容见下文
- **Intruder**：提供给 Burp Intruder 的一组文件
- **Images**：README.md 的图片
- **Files**：README.md 中引用的一些文件

## README.md 格式

使用示例文件夹 [_template_vuln/](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/) 来创建新的漏洞文档。主要页面是 [README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/README.md)。它按部分组织，包含漏洞的标题和描述，以及指向文档主要部分的目录摘要表格。

- **工具**：列出相关工具及其仓库链接和简要描述。
- **方法论**：提供所使用方法的快速概述，并提供代码片段来演示利用步骤。
- **实验室**：引用可以练习类似漏洞的在线平台，每个都有指向相应实验室的链接。
- **引用**：列出外部资源，如博客文章或文章，提供与漏洞相关的额外背景或案例研究。