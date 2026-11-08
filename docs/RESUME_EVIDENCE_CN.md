# 简历与面试证据

项目名：第三方 Skill 接入风险初筛助手。时间标签使用 **硕士第 3 学期**，不虚构月份。当前为本地 MVP 已实现并完成所记录的功能验证；不是生产部署或商业安全产品。开发有 AI 辅助，使用者应能解释并小幅修改核心判断后再在面试中主张相应能力。

## 能力与证据对应

| 能力 | 可检查证据 | 可以说明什么 / 不可外推什么 |
| --- | --- | --- |
| 风险场景拆分 | PROJECT_BRIEF_CN.md；RULES_CN.md | 能把外联、执行、凭据、下载执行拆成审查问题；不证明覆盖全部攻击 |
| Python 静态分析 | `skill_guard/rules.py`；`tests/test_rules.py` | AST 调用、简单别名、上下文和固定/动态参数判断；无完整污点分析 |
| 安全边界与保密 | `scanner.py`、`reporting.py`；边界/报告测试 | 非执行读取、资源限制、遮盖、转义；不是系统级沙箱 |
| 可追溯规则治理 | `config.py`；`reports/contrast/` | 精确例外、理由、期限与残余复核；不是批准工作流平台 |
| 功能验证 | 手写 `fixtures/manifest.json`；JUnit；`reports/evaluation/` | 24 个有限合成样本、42 个预期位置的验证；不是现实恶意检测率 |
| 可复用 Agent 操作规范 | `skills/skill-risk-review/`；包装验证说明 | 核心只一份、默认读遮盖报告；未安装或认证全平台兼容 |
| 沟通与交接 | README、STATUS、教学和演示稿 | 能演示结果、解释缺口和提出复核建议；不承诺面试表现 |

实际测试数量、跳过原因、工具版本、执行命令均以 `reports/verification.json` 和 `reports/pytest-results.xml` 为准。不要把未运行的真实 junction/硬链接测试写成通过，也不要把语法命中称为已确认漏洞。

## 可用中文简历描述（3 条）

- 实现本地离线的第三方 Skill 风险初筛 CLI，使用 Python AST 与文本模式构建 8 条可解释规则，覆盖网络调用、命令执行、凭据访问及简单下载执行组合，生成带文件与行号的 JSON/Markdown 报告。
- 设计非执行读取边界、文件与总量限制、默认无原文报告及可追溯例外机制，区分潜在影响、证据置信度与覆盖缺口，支持接入前人工风险复核。
- 构建 24 个合成 Skill 目录和独立人工期望 manifest，对 42 个预期规则位置完成有限功能评测，并通过自动测试验证边界、遮盖、稳定性和 CLI 行为；交付可复用的项目内 Skill 包装与证据文档。

## English résumé bullets (3)

- Implemented an offline Python CLI for preliminary third-party Agent Skill review, using eight explainable AST and text rules to flag network calls, command execution, credential access, and simple download-to-interpreter pipelines in traceable JSON/Markdown reports.
- Added non-executing bounded file reads, conservative report redaction, coverage accounting, and reasoned exceptions, separating potential impact from evidence confidence for human intake review.
- Created 24 synthetic Skill fixtures with an independently written manifest covering 42 expected rule locations; evaluated functional behavior and automated boundary, redaction, determinism, and CLI checks, with a project-local Skill wrapper and reproducible evidence.

## 面试中主动说明的边界

“这个项目体现的是静态规则实现、验证设计与风险沟通。我没有把它部署到企业环境，没有做完整沙箱、跨文件污点分析或现实恶意样本检测率测量。哪些测试通过、哪些因权限跳过，都保留在真实运行记录里。”

不使用“准确率 100%”“彻底阻断数据外传”“独立开发企业级平台”“已经安装所有 Agent 平台”等没有证据的描述。练习尚未完成时，也不要声称自己已经熟练掌握所有实现细节。
