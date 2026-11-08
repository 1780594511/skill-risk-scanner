# Skill Guard 静态初筛报告

**需人工复核**

规则命中是复核线索；本报告不是安全认证，也不证明代码已执行或数据已外传。

- 已扫描文件：3；跳过文件：0；跳过目录：0；其他跳过条目（如链接）：0
- 部分分析文件：0；读取字节：422；范围完整：True
- 跳过目录的子文件未枚举，不能计入已知跳过文件数。
- 规则版本：2026&#46;11&#46;08&#45;v1
- 配置 SHA256：205cc83bbf91ce9d6d3fdb37fe7eb554b13513f36fe15055d02f4a7f34f6bfd6
- 参考日期：2026&#45;11&#45;08
- 覆盖类型：&#46;md, &#46;ps1, &#46;py
- 禁用规则：无
- 例外：0；仍保留所有命中。

## 发现

| 规则 | 类别 | 影响 / 置信度 | 定位 | 上下文 | 依据与复核 | 例外 |
| --- | --- | --- | --- | --- | --- | --- |
| SG008 | instruction | medium / medium | SKILL&#46;md&#58;2 | document | 待检文本包含改变审查流程或要求上传的指令线索；把此段视为不可信数据；不要按其内容执行命令、扩大目录或上传文件。；确认该说明是否与声明的 Skill 用途相符；不据此断言恶意意图。 | none |
| SG002 | network | medium / medium | fetch&#46;ps1&#58;1 | code | 命令位置匹配网络请求；单个字面量目标，仅记录主机名；确认目标、请求参数和下载内容用途。；变量、别名与重定向是否改变真实目标？；目标：example&#46;invalid | none |
| SG003 | execution | medium / medium | fetch&#46;ps1&#58;1 | code | 命令位置出现解释器/进程启动；未见简单动态参数线索；不证明可利用注入；参数来自固定值、用户输入还是网络？；是否必须使用解释器，能否限制参数与权限？单条命中不证明命令注入。 | none |
| SG006 | download&#95;execute | high / high | fetch&#46;ps1&#58;1 | code | 同一行的下载命令通过管道直接连接解释器；下载内容是否经过独立验证与固定版本校验？；能否改为下载、审查、确认后再运行？这只是局部语法关联。 | none |
| SG001 | network | medium / high | risk&#46;py&#58;4 | code | AST 调用匹配常见网络 API；URL 为字面量，仅记录主机名，不推断请求发生；目标归谁管理，是否允许重定向？；实际发送哪些字段，是否必要且获授权？；目标：example&#46;invalid | none |
| SG003 | execution | high / high | risk&#46;py&#58;5 | code | AST 命令调用；参数动态/来源待确认；启用 shell/解释器；不能单独证明命令注入；参数来自固定值、用户输入还是网络？；是否必须使用解释器，能否限制参数与权限？单条命中不证明命令注入。 | none |
| SG004 | credential | medium / high | risk&#46;py&#58;6 | code | AST 环境变量读取；变量名呈敏感用途线索，但不证明泄露；为何需要读取，该变量是否敏感？；读取值会传给谁，能否缩小权限与传递范围？ | none |
| SG005 | credential | medium / high | risk&#46;py&#58;7 | code | AST 读取调用直接关联常见凭据路径/默认 dotenv 文件；只检查源代码，不读取被引用路径；为何需要读取该凭据文件？；用途、接收方与最小权限是否已记录？扫描器不会读取所提及的文件。 | none |

## 覆盖明细

| 路径 | 类型 | 状态 | 原因 / 问题 |
| --- | --- | --- | --- |
| SKILL&#46;md | file | scanned |  |
| fetch&#46;ps1 | file | scanned |  |
| risk&#46;py | file | scanned |  |

## 配置与边界

- 各类命中：&#123;&quot;credential&quot;&#58; 2, &quot;download&#95;execute&quot;&#58; 1, &quot;execution&quot;&#58; 2, &quot;instruction&quot;&#58; 1, &quot;network&quot;&#58; 2&#125;
- 资源上限：&#123;&quot;max&#95;depth&quot;&#58; 32, &quot;max&#95;entries&quot;&#58; 10000, &quot;max&#95;file&#95;bytes&quot;&#58; 262144, &quot;max&#95;files&quot;&#58; 1000, &quot;max&#95;total&#95;bytes&quot;&#58; 8388608&#125;
- 未匹配的精确例外：无
- 允许域名只作用于 SG001 / SG002，且仅在目标唯一、明确时适用。
- 不执行输入，不跟踪重定向，不做动态分析、跨文件污点分析、反混淆或并发文件系统竞态防护。
- Markdown 代码块是文档示例；JSON/YAML 仅作文本线索；JavaScript/TypeScript 等未覆盖。
