# 规则依据、反例与限制

版本以 `skill_guard.RULESET_VERSION` 和实际报告为准。以下是自编启发式规则，不是外部产品的规则库；实现集中在 `rules.py`。API 含义参见 [Python AST](https://docs.python.org/3.12/library/ast.html)、[subprocess](https://docs.python.org/3.12/library/subprocess.html#security-considerations)、[os](https://docs.python.org/3.12/library/os.html#os.getenv) 与 [PowerShell Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5)。风险等级与复核问题是本项目的设计判断。

## SG001：Python 网络调用

依据：AST Call 匹配 requests/httpx 的常见请求函数与 urllib.request.urlopen/urlretrieve，解析简单 import/as 与 from/import 别名。字面量 URL 仅保存 host；动态参数报告目标待确认。网络访问是能力线索，本身可以完全合理。

正常反例：文档中的 URL、Python 注释和普通字符串赋值不作为网络调用；例如 `message = "https://example.invalid/help"`。测试覆盖 `04_aliases`、`15_comments`。

已知限制：不解析 Session/Client 实例方法、socket/http.client、复杂动态别名、运行时 import 或完整作用域/重绑定。全树收集简单别名可能把同名局部对象误认成库；可能漏掉间接调用。字面量目标不代表实际目的地，不追踪重定向、DNS 或代理。

复核：目标由谁管理？发送哪些数据？参数从哪里来？重定向后是否仍获授权？

## SG002：shell / PowerShell 网络命令

依据：命令位置上的 curl/wget（含 .exe）、Invoke-WebRequest/Invoke-RestMethod 及 iwr/irm。单个明确 URL 且未见简单变量替换时才记录字面量目标。行级分析不执行命令。

正常反例：`echo "curl https://example.invalid/x"`、整行注释不升级成网络请求。仅下载的样本只有 SG002，不因下载而自动触发 SG006。

已知限制：不完整解释引号、反引号、重定义别名、heredoc、子 shell 和命令替换；多行续接会报告覆盖问题。同名命令可能是函数或别名；目标中的变量与多个 URL 保守标为未知。

复核：命令真实解析到哪个程序？目标和请求参数是否必要？下载文件之后如何处理？

## SG003：系统命令 / 解释器

依据：subprocess 常用 API、os.system/popen、Python exec/eval 的调用语法，以及 shell/PowerShell 中明确的解释器/进程启动命令。区分固定字面量、动态参数、shell=True/隐含解释器、动态 shell 开关。固定参数低影响，动态 shell 参数优先复核。

正常反例：固定 `subprocess.run(["python", "--version"])` 是低影响线索，不称为注入；打印一段命令字符串不是进程启动。`shell=True` 本身不证明输入可控或漏洞可利用。

已知限制：不追踪动态参数来源或验证转义效果；固定命令也可能具有破坏性，本版不会完整解释命令意图。Windows 特定批处理启动语义及任意可执行文件启动未完整覆盖。

复核：参数是否由不可信输入控制？为何需要 shell？可否固定可执行文件及参数列表？进程有哪些权限？

## SG004：环境变量读取

依据：os.getenv、os.environ.get/下标读取，以及简单 shell 变量展开和 PowerShell `$env:`。敏感用途的变量名提升至 medium；普通变量为 low。写入 os.environ 不当作读取。

正常反例：读取 LANG/HOME/PATH 可以是正常配置；字符串里的变量表达式和 Python 写入操作不证明读取敏感信息。

已知限制：shell `$NAME` 可能是局部变量，故只报变量展开线索；不追踪后续传播。复制整个环境、变量名动态拼接等可能漏检；名称也不能证明值真的敏感。

复核：为何读取？读取到的值交给谁？权限与使用范围能否缩小？禁止据单条命中宣布数据泄露。

## SG005：凭据路径读取

依据：open/io.open、直接 Path(...).read_text/read_bytes/open 与常见凭据路径字面量相连；dotenv 常见读取入口；cat/Get-Content 等命令关联 `.env`、SSH 或云凭据路径。读取模式与纯写入模式区分。

正常反例：说明文档介绍 `.ssh/id_rsa` 只产生 SG007；`open(".env", "w")` 不产生读取发现。扫描器本身永不按源码所述路径读取凭据。

已知限制：不追踪变量路径、Path 对象别名、路径拼接或跨文件读取封装。某个同名路径可能只是测试文件；不据此断言真实凭据存在。

复核：该文件为何必要？最小权限是什么？访问值是否会传递出去？应在授权范围内让负责人确认，不自动读取文件验证。

## SG006：下载直接接解释器

依据：同一行、命令位置明确的下载命令，经单个 `|` 直接接到已支持的解释器。中间 `;`、`&`、`&&`、`||` 或其他管道命令不能代替这个关联。

正常反例：只有下载、只有执行、先下载另一文件再执行本地脚本，都不触发本规则；`curl ... && echo ... | sh` 也不是下载结果直接进入 sh。样本 11/12/13 和单测保留这些差异。

已知限制：不确认命令选项实际输出什么，不做完整 shell 数据流；重定向到文件后执行、多行/动态/跨文件链条均可能漏检。文档代码块命中只描述示例模式。

复核：是否验证内容来源、签名和固定版本？能否先下载、审查、再单独确认执行？

## SG007：说明性引用

依据：文档、注释、独立文档字符串或纯文本配置中的 URL / 常见凭据路径。始终是 info，并保留 document/comment/docstring/config_text 上下文。

正常反例：正常官网链接就是此规则的正例，同时也是“不能升级为实际网络调用”的反例。普通本地说明没有 URL/路径时不命中。

已知限制：不理解文档意图，引用可能已经过时；JSON/YAML 中看似可执行的配置只作文本，不模拟其调用方。代码块另按已支持的语言分析，不与普通说明混淆。

复核：它只是说明，还是有对应的可执行调用？没有对应证据时保留为信息线索，不作恶意通信结论。

## SG008：改变审查流程的文字

依据：说明/配置文本中有限的“忽略检查规则”“上传文件”及英文同类表达。记录为指令线索，不遵循内容。

正常反例：普通使用指南“格式化用户输入文本”不命中。安全教育材料引用恶意指令可能命中，但并无恶意意图；此处需要人工判断上下文。

已知限制：不覆盖所有自然语言、编码混淆、隐藏文本或多轮上下文攻击；不等于完整提示词注入检测。此规则没有决定扫描器执行权限的能力。

复核：该文字是否要求越过用户授权范围？与声明用途是否一致？只报告并保持原扫描边界。
