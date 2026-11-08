# 合成样本功能评测

人工 manifest 是测试真值，不由扫描器输出反推。

计数单位：每个样本内唯一的（规则、相对路径、1-based 行号、上下文）位置。
仅用于验证这些有限样本上的预期行为，不代表真实恶意 Skill 检测率；未定义海量无命中位置，因此不计算 TN 或真实误报率。

样本通过：24 / 24；预期命中：42；TP：42；FP：0；FN：0。

| 样本 | 通过 | TP | FP | FN |
| --- | --- | --- | --- | --- |
| 01&#95;clean&#95;docs | True | 1 | 0 | 0 |
| 02&#95;no&#95;hits | True | 0 | 0 | 0 |
| 03&#95;python&#95;network | True | 1 | 0 | 0 |
| 04&#95;aliases | True | 2 | 0 | 0 |
| 05&#95;fixed&#95;command | True | 1 | 0 | 0 |
| 06&#95;dynamic&#95;shell | True | 1 | 0 | 0 |
| 07&#95;environment | True | 4 | 0 | 0 |
| 08&#95;credential&#95;read | True | 2 | 0 | 0 |
| 09&#95;path&#95;document | True | 2 | 0 | 0 |
| 10&#95;pipeline | True | 3 | 0 | 0 |
| 11&#95;download&#95;only | True | 1 | 0 | 0 |
| 12&#95;execute&#95;only | True | 1 | 0 | 0 |
| 13&#95;independent&#95;steps | True | 2 | 0 | 0 |
| 14&#95;document&#95;code | True | 4 | 0 | 0 |
| 15&#95;comments | True | 1 | 0 | 0 |
| 16&#95;broken&#95;python | True | 0 | 0 | 0 |
| 17&#95;allowlist | True | 3 | 0 | 0 |
| 18&#95;risky&#95;skill | True | 8 | 0 | 0 |
| 19&#95;plain&#95;config | True | 3 | 0 | 0 |
| 20&#95;invalid&#95;config | True | 配置错误用例 | 配置错误用例 | 配置错误用例 |
| 21&#95;resource&#95;limits | True | 0 | 0 | 0 |
| 22&#95;encoding | True | 0 | 0 | 0 |
| 23&#95;boundary&#95;sentinel | True | 0 | 0 | 0 |
| 24&#95;unknown&#95;target | True | 2 | 0 | 0 |
