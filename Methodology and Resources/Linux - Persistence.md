[原文文档](Linux - Persistence.en.md)

# Linux - 持久化

:warning: 此页面的内容已移动到 [InternalAllTheThings/redteam/persistence/linux-persistence](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/)

- [基本反向shell](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#basic-reverse-shell)
- [添加root用户](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#add-a-root-user)
- [SUID 二进制文件](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#suid-binary)
- [Crontab - 反向shell](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#crontab---reverse-shell)
- [后门化用户的bash_rc](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-users-bash_rc)
- [后门化启动服务](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-startup-service)
- [后门化用户启动文件](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-user-startup-file)
- [后门化每日消息](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-message-of-the-day)
- [后门化驱动程序](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-driver)
- [后门化APT](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-the-apt)
- [后门化SSH](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-the-ssh)
- [后门化Git](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-git)
- [其他Linux持久化选项](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#additional-persistence-options)
- [参考资料](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#references)