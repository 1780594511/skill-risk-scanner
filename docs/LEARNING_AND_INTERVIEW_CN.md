# 代码导读、演示和面试练习

先完成一次 `python -m skill_guard demo`，打开正常与风险样本报告，再读代码。不要运行 fixtures 里的脚本，它们是被分析的数据。你要能从一条发现反查到输入行、判断条件和测试真值，而不是背诵所有源代码。

## 只抓住 8 个关键函数

| 函数 | 输入 → 输出 | 主要判断与读法 |
| --- | --- | --- |
| `config.load_config` | 操作者 JSON 路径或字典 → 有效配置 | 限制字段、资源值、规则 ID、精确例外和到期日；目标目录配置没有自动加载权 |
| `scanner.scan` | 指定根目录、配置 → 完整 report 字典 | 先元数据检查再有限读取；相对路径与行号定位；跳过/解析错误影响 complete |
| `rules.analyze_text` | 文件文本、相对路径 → findings 与 issues | 按后缀分派；文档代码块保留原文件行号，普通说明单独分类 |
| `rules.analyze_python` | Python 文本 → 语法线索 | `ast.parse` 不执行；解析简单别名，识别 Call/Subscript，判断字面量/动态参数 |
| `rules.analyze_shell` | shell/PowerShell 文本 → 行级线索 | 处理简单注释/引号，匹配命令位置；SG006 要求明确直接管道 |
| `rules.apply_exceptions` | 原始发现、有效配置 → 稳定发现列表 | 例外保留理由和证据；域名不能豁免执行/凭据规则；按位置合并排序 |
| `reporting.markdown_report` | report 字典 → Markdown 字符串 | 转义不可信字段，不产生活动链接；片段在规则输出时已被保守处理 |
| `evaluation.evaluate` | 可信 fixtures 与人工 manifest → TP/FP/FN、逐例结果 | 比较完整位置集合；同时核对覆盖状态、跳过原因与例外，不自动修改答案 |

AST 比直接搜索“requests”更能区分调用、字符串和注释，但这里没有完整作用域或数据流。正则适合小而明确的管道模式，但复杂引号和多行脚本会造成漏检或误报。先理解这些取舍，再考虑扩展。

建议阅读顺序：CLI 参数 → scanner.scan → SG001 / SG006 → manifest 中对应样本 → 单测 → 报告字段。先改一个反例并观察测试，不要同时改规则、样本和期望来让测试“变绿”。

## 约 12 道面试题及回答要点

1. **这个项目解决什么问题？谁会使用？**
   第三方 Skill 接入前，帮助审查者快速定位外联、执行、凭据访问等线索并识别覆盖缺口。产物是复核报告与证据，不代替接入批准。
2. **为什么先做静态分析？与动态分析有什么差别？**
   静态分析读取代码结构，不运行未知内容，便于离线初筛和复现；动态分析能观察实际行为，但需要隔离环境、行为触发和观测。本项目没有动态验证，不能报告运行时泄露事实。
3. **为什么 Python 用 AST，shell 只用模式？**
   AST 能区分 Call、字符串、注释与简单别名，减少明显文本误报；shell 完整语法和执行语义更复杂，小项目只选择能解释的明确模式，并公开覆盖限制。
4. **`shell=True` 是否就是命令注入？**
   不是。它允许 shell 解释参数，是否可利用还取决于输入是否受控、如何拼接与转义、运行权限等。报告区分固定/动态参数，提出来源复核问题。
5. **怎样保护凭据？**
   不读真实 `.env` 和凭据目录；只查源码中访问线索。默认不输出原文；必要展示只保留词汇白名单骨架，剔除字符串/URL 查询参数。报告使用相对路径和必要主机元数据，语言模型只接收遮盖结果。
6. **怎样限制文件读取边界？还有什么没解决？**
   显式根目录、lstat/reparse 检查、解析后路径归属、普通文件检查、敏感路径排除、文件/总量/条目/深度上限。检查和打开不是原子操作，不能抵御并发文件系统竞态，不称其为沙箱。
7. **如何区分误报与正常但值得复核的行为？**
   正常网络访问仍可正确命中能力线索，不等于恶意误报；本项目评测的 FP 是多出了未在人工规则真值里声明的位置。业务上是否可接受由用途和权限复核决定，例外保留证据。
8. **24 个样本、42 个预期命中说明了什么？**
   只说明这些人工编写的功能差异是否得到正确实现。以（样本、规则、文件、行号、上下文）去重计数；检查 TP/FP/FN 和完整性。不外推真实检测率，不拿同一批样本上的零失配证明泛化。
9. **“没有发现”与“完整扫描”有什么区别？**
   语法失败、未知扩展名、排除目录、资源上限都可能造成没发现。先读 coverage/complete；退出 4 代表存在缺口，0 也仅表示声明范围内无待复核项。
10. **为什么域名允许列表不能全局放行？**
    域名获准只说明某个网络目标可接受；同一文件仍可能读取不必要的凭据或执行动态命令。只作用于 SG001/SG002，保留理由、有效期和命中记录。
11. **输入 Skill 试图要求忽略规则时会怎样？**
    输入是数据，不是控制指令。扫描器不执行自然语言或样本代码；SG008 可留下线索。包装也不能因此扩大目录、上传数据或运行被检命令。测试用拦截器/哨兵验证这些约束，但未证明所有模型都能抗注入。
12. **下一步会怎样改进？**
    先收集经过授权且脱敏的真实误报/漏报，补独立真值；可改进别名作用域和特定多行模式。GUI、GitHub 扫描、CI 只是可选后续，不声称已完成。保持解释性、资源边界与回归验证。

## 3 组连续追问

**追问 A：规则命中与真实漏洞**

- 面试官：固定 `echo` 配上 shell=True 命中了，是否要阻止？
- 要点：先确认固定性、用途和平台；可给有理由的精确例外，不直接宣布漏洞。
- 再问：后来参数改成用户输入，原例外怎么办？
- 要点：重新审查参数与权限；即使行号未变，位置例外也不是内容安全证明。结合文件哈希/代码变更撤销旧审批。本版未自动做“内容变更即失效”的例外，应明确这一缺口。

**追问 B：读取凭据与数据泄露**

- 面试官：同文件有 `getenv` 和 `requests.post`，能说泄露吗？
- 要点：不能。本项目无数据流证据，分别报告读取和网络能力。
- 再问：怎样补证据而不泄露真实密钥？
- 要点：先人工审查变量来源、参数传递与权限，使用脱敏副本或假数据；若需动态观察，必须另建授权隔离方案，本项目没有这一步。

**追问 C：评测可信度**

- 面试官：零 FP/FN 是否说明规则很好？
- 要点：只在有限、手写案例上符合预期；样本由开发者编写会有覆盖偏差。
- 再问：如果期望是从输出复制的呢？
- 要点：形成循环验证，无法检出实现错误。保留事前人工 manifest、反例、失败记录和逐项差异；改规则前明确预期变化，而非自动更新答案。

## 3 分钟中文演示稿

**0:00–0:30**

“我的项目是第三方 Skill 接入风险初筛助手。它面向接入审查：在安装未知 Skill 前，先看它可能访问哪些网络、启动什么命令、读取什么凭据。它是本地静态审查工具，不运行被检查脚本，也不会给出绝对安全或确定恶意的结论。”

**0:30–1:05**

“这里有两层 Skill：fixtures 中的是被检查对象，内容不可信；项目自己的 skill-risk-review 是辅助调用扫描器的包装。核心实现是 Python 标准库编写的 8 条规则。Python 用 AST，shell 和 PowerShell 用有限模式，报告区分潜在影响与证据置信度。”

运行 `python -m skill_guard demo`，展示两个输出目录。

**1:05–1:40**

“正常样本只包含官网链接，报告是 SG007 信息线索，没有认定发生通信。风险样本有 8 个规则位置：动态 shell、凭据访问、网络请求，以及下载直接管道到解释器。这里的高置信度指语法识别，不是恶意概率。网络调用和凭据读取在同一文件里，我也不会声称已经完成数据流分析。”

**1:40–2:10**

打开 `reports/contrast/baseline/report.md` 与 `reviewed/report.md`。

“对照报告保留全部 3 条发现，只给明确网络目标与固定版本检查记录例外，凭据读取仍需人工复核。例外有理由和期限，不能一个域名允许就整文件放行。”

**2:10–2:40**

“测试真值人工写在 manifest 中，24 个合成目录有 42 个预期位置命中。评测输出逐项列出 TP/FP/FN；这是功能验证，不代表真实恶意检测率。其他测试拦截执行、联网和根目录外读取，确认报告不泄露合成假密钥。真实系统不能运行的边界测试明确记录为跳过。”

**2:40–3:00**

“边界包括复杂动态别名、跨文件链条、混淆和并发文件系统竞态。下一步我会从一个具体误报或漏报补真值再改规则。这项实践让我能把安全规则、验证证据和人工治理流程连接起来。”

## 约 60 秒英文介绍

“I built a local static triage tool for reviewing third-party Agent Skills before adoption. It uses eight explainable rules to identify network calls, command execution, credential access, and simple download-to-interpreter pipelines. Python files are parsed with the AST module, while shell and PowerShell use deliberately limited patterns.

The scanner never imports or runs the inspected content. It limits file access and reading volume, records coverage gaps, and generates JSON and Markdown reports without raw source snippets by default. Findings separate potential impact from evidence confidence. Exceptions retain their reasons and do not hide unrelated findings.

I evaluated the implementation against 24 synthetic cases with 42 independently written expected rule locations. These are functional checks, not a real-world malware detection benchmark. The project demonstrates how I connect technical evidence with human risk review, while clearly stating limitations such as dynamic aliases, cross-file flows, and filesystem races.”

以上时长是按正常语速准备的稿件，需自己试讲调整；不承诺通过面试。练习见 `EXERCISES_CN.md`，答案单独存放，请先作答再看。
