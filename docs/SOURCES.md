# 参考来源与借用说明

查阅日期（用户时区 Asia/Shanghai）：2026-11-08。

- [Agent Skills specification](https://agentskills.io/specification)：用于包装的目录、name/description 和 YAML frontmatter 格式参考。没有把格式验证称为行为安全认证。
- [Cisco AI Defense Skill Scanner](https://cisco-ai-defense.github.io/docs/skill-scanner)：仅参考“扫描结果需人工复核、报告给出定位与类别”的范围表达。其文档描述的多种分析机制与本项目能力不同；本项目没有调用、包装或复制该扫描器实现。
- [Python AST 文档](https://docs.python.org/3.12/library/ast.html)：用于理解解析语法树与代码执行的区别。
- [Python subprocess 文档](https://docs.python.org/3.12/library/subprocess.html#security-considerations)：用于命令调用与 shell 参数的语义依据，不将 API 使用单独当作注入证明。
- [Python os 文档](https://docs.python.org/3.12/library/os.html#os.getenv)：用于环境变量读取、stat、路径及文件操作的语义依据。
- [PowerShell Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5)：网络请求命令的语义参考。

核心扫描器、规则、样本、测试与文档在本次任务中实现，没有从上述同类工具借用检测代码。规则等级、有限模式与计数方式是本项目的设计，不代表官方文档对本项目结论背书。

宿主 skill-creator 初始化器生成了包装骨架和 UI 元数据，正文随后按本项目需求编写。未复制初始化器或验证器到项目中。pytest 9.2.0 是开发测试依赖（MIT）；PyYAML 6.0.3 是宿主格式验证依赖（MIT），不是扫描引擎。交付 ZIP 不分发这些依赖的实现或虚拟环境；安装时应保留依赖包自身许可证。
