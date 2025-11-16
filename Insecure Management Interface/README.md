[原文文档](README.en.md)

# 不安全的管理接口

> 不安全的管理接口是指用于管理服务器、应用程序、数据库或网络设备的管理接口中的漏洞。这些接口通常控制敏感设置，并可以访问系统配置，使它们成为攻击者的主要目标。
> 不安全的管理接口可能缺乏适当的安全措施，如强身份验证、加密或IP限制，允许未经授权的用户潜在地获得对关键系统的控制权。常见问题包括使用默认凭据、未加密通信或将接口暴露在公共互联网上。

## 目录

* [方法论](#方法论)
* [参考资料](#参考资料)

## 方法论

当系统或应用程序的管理接口安全措施不当，允许未经授权或恶意用户获得访问权限、修改配置或利用敏感操作时，就会出现不安全的管理接口漏洞。这些接口通常对维护、监控和控制系统至关重要，必须严格保护。

* 缺乏身份验证或弱身份验证：
    * 无需凭据即可访问的接口。
    * 使用默认或弱凭据（例如，admin/admin）。

    ```ps1
    nuclei -t http/default-logins -u https://example.com
    ```

* 暴露在公共互联网上

    ```ps1
    nuclei -t http/exposed-panels -u https://example.com
    nuclei -t http/exposures -u https://example.com
    ```

* 通过普通HTTP或其他未加密协议传输敏感数据

**示例**：

* **网络设备**：具有默认凭据或未修补漏洞的路由器、交换机或防火墙。
* **Web应用程序**：没有身份验证的管理面板或通过可预测URL暴露的面板（例如，/admin）。
* **云服务**：没有适当身份验证或角色权限过于宽松的API端点。

## 参考资料

* [CAPEC-121: 利用非生产接口 - CAPEC - 2020年7月30日](https://capec.mitre.org/data/definitions/121.html)
* [利用Spring Boot Actuators - Michael Stepankin - 2019年2月25日](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
* [Springboot - 官方文档 - 2024年5月9日](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html)