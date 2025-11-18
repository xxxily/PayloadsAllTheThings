[Windows - AMSI Bypass.en.md](Windows - AMSI Bypass.en.md)

# Windows - AMSI 绕过

:warning: 此页面内容已移动至 [InternalAllTheThings/redteam/evasion/windows-amsi-bypass](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/)

- [列出 AMSI 提供程序](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#list-amsi-providers)
- [哪个端点保护使用 AMSI](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#which-endpoint-protection-is-using-amsi)
- [通过 rasta-mouse 修补 amsi.dll AmsiScanBuffer](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Patching-amsi.dll-AmsiScanBuffer-by-rasta-mouse)
- [不要使用 net webclient](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Dont-use-net-webclient)
- [Amsi ScanBuffer 补丁来自 -> https://www.contextis.com/de/blog/amsi-bypass](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Amsi-ScanBuffer-Patch)
- [强制错误](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Forcing-an-error)
- [禁用脚本日志记录](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Disable-Script-Logging)
- [Amsi 缓冲区补丁 - 内存中](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Amsi-Buffer-Patch---In-memory)
- [与第6项相同但使用整数字节而不是 Base64](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Same-as-6-but-integer-Bytes-instead-of-Base64)
- [使用 Matt Graeber 的反射方法](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Using-Matt-Graebers-Reflection-method)
- [使用 Matt Graeber 的反射方法和 WMF5 自动日志绕过](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Using-Matt-Graebers-Reflection-method-with-WMF5-autologging-bypass)
- [使用 Matt Graeber 的第二个反射方法](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Using-Matt-Graebers-second-Reflection-method)
- [使用 Cornelis de Plaa 的 DLL 劫持方法](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Using-Cornelis-de-Plaas-DLL-hijack-method")
- [使用 Powershell 版本 2 - 不支持 AMSI](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Using-PowerShell-version-2)
- [Nishang 一体化](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Nishang-all-in-one)
- [Adam Chester 补丁](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#Adam-Chester-Patch)
- [AMSI.fail](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-amsi-bypass/#amsifail)