# Skill Guard 静态初筛报告

**需人工复核**

规则命中是复核线索；本报告不是安全认证，也不证明代码已执行或数据已外传。

- 已扫描文件：1；跳过文件：0；跳过目录：0；其他跳过条目（如链接）：0
- 部分分析文件：0；读取字节：198；范围完整：True
- 跳过目录的子文件未枚举，不能计入已知跳过文件数。
- 规则版本：2026&#46;11&#46;08&#45;v1
- 配置 SHA256：2f9f069ef99bca2ce21796f20be290380fc758302f77682031f4058939968632
- 参考日期：2026&#45;11&#45;08
- 覆盖类型：&#46;py
- 禁用规则：无
- 例外：2；仍保留所有命中。

## 发现

| 规则 | 类别 | 影响 / 置信度 | 定位 | 上下文 | 依据与复核 | 例外 |
| --- | --- | --- | --- | --- | --- | --- |
| SG001 | network | medium / high | review&#46;py&#58;3 | code | AST 调用匹配常见网络 API；URL 为字面量，仅记录主机名，不推断请求发生；目标归谁管理，是否允许重定向？；实际发送哪些字段，是否必要且获授权？；目标：example&#46;invalid；token skeleton&#58; requests get &#91;all other content omitted&#93; | applied；domain&#58;example&#46;invalid：合成演示目标；仅对明确网络目标记录例外，不表示可执行或可读取凭据（到期 2026&#45;12&#45;31） |
| SG003 | execution | low / high | review&#46;py&#58;4 | code | AST 命令调用；参数为固定字面量；未显式启用 shell；不能单独证明命令注入；参数来自固定值、用户输入还是网络？；是否必须使用解释器，能否限制参数与权限？单条命中不证明命令注入。；token skeleton&#58; subprocess run &#91;all other content omitted&#93; | applied；fixed&#45;version&#45;check：人工核对为固定 python &#45;&#45;version 调用；权限仍需复核（到期 2026&#45;12&#45;31） |
| SG005 | credential | medium / high | review&#46;py&#58;5 | code | AST 读取调用直接关联常见凭据路径/默认 dotenv 文件；只检查源代码，不读取被引用路径；为何需要读取该凭据文件？；用途、接收方与最小权限是否已记录？扫描器不会读取所提及的文件。；token skeleton&#58; open read &#91;all other content omitted&#93; | none |

## 覆盖明细

| 路径 | 类型 | 状态 | 原因 / 问题 |
| --- | --- | --- | --- |
| review&#46;py | file | scanned |  |

## 配置与边界

- 各类命中：&#123;&quot;credential&quot;&#58; 1, &quot;execution&quot;&#58; 1, &quot;network&quot;&#58; 1&#125;
- 资源上限：&#123;&quot;max&#95;depth&quot;&#58; 32, &quot;max&#95;entries&quot;&#58; 10000, &quot;max&#95;file&#95;bytes&quot;&#58; 262144, &quot;max&#95;files&quot;&#58; 1000, &quot;max&#95;total&#95;bytes&quot;&#58; 8388608&#125;
- 未匹配的精确例外：无
- 允许域名只作用于 SG001 / SG002，且仅在目标唯一、明确时适用。
- 不执行输入，不跟踪重定向，不做动态分析、跨文件污点分析、反混淆或并发文件系统竞态防护。
- Markdown 代码块是文档示例；JSON/YAML 仅作文本线索；JavaScript/TypeScript 等未覆盖。
