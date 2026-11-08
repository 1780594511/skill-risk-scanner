# Skill 包装的完成、验证与安装状态

| 状态 | 当前证据 | 边界 |
| --- | --- | --- |
| 完成 | `skills/skill-risk-review/SKILL.md` 与 `agents/openai.yaml` 已创建；指向唯一 `skill_guard/` 实现 | 没有复制第二套扫描器 |
| 格式验证 | 宿主 skill-creator 的 init_skill.py 初始化；quick_validate.py 返回 `Skill is valid!`，退出 0 | 只验证该工具实际实现的元数据/命名/占位符检查，不证明所有宿主兼容 |
| CLI 流程验证 | 包装规定的可信项目工作目录、显式配置、专用输出方式实际运行；结果见 `reports/wrapper-walkthrough/` 与 verification.json | 核心边界测试使用 mock/哨兵；没有宣称完成独立模型抗注入评测 |
| 安装 / 激活 | **未安装，未激活，未验证自动发现** | 没有改全局 skills、现有 Skill 或系统配置；仓库托管不等于包装安装 |

包装使用宿主 skill-creator 初始化器创建，使用其 quick_validate.py 验证。验证记录中的本机路径已用占位符替换，验证结果与 SKILL.md 哈希保留，见 evidence/skill-wrapper-validation.json。验证器本身不随仓库分发。

使用时，显式要求 Agent 读取本项目 skills/skill-risk-review/SKILL.md 并按其流程处理用户指定目录；这不代表自动发现或全局安装。重新运行宿主验证器时，请定位自己环境中的可信 quick_validate.py，不使用原作者机器路径。

更换宿主后验证工具可能不同，不承诺通用。若以后明确要求安装，应保持“包装与唯一可信核心一起定位”的约束，不能只复制 SKILL.md 后假定其相对路径仍有效。本项目未实施安装操作。

规范参考：[Agent Skills specification](https://agentskills.io/specification)。规范要求 SKILL.md 包含 YAML 元数据和正文；name 与 description 用于身份和使用场景描述。本包装使用该基础结构，Codex UI 信息另放 agents/openai.yaml。
