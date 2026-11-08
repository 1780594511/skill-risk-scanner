# 上手练习（先不看答案）

三个练习分别训练反例、规则上下文和风险解释。答案放在 `EXERCISE_ANSWERS_CN.md`。从第一题开始，一次只做一题；把预期写下后再运行，不要为了通过测试倒改预期。

## 练习 1：新增一个正常反例

在项目 `work/exercise-01/notes.py` 新建一个只含下面注释的文件，**只扫描，不运行该文件**：

```python
# requests.get("https://example.invalid/help")
```

先回答：你预期是 SG001 还是 SG007？上下文应是什么？为什么不能说明已经外联？然后运行：

```powershell
python -m skill_guard scan work\exercise-01 --config configs\default.json --out reports\exercise-01
```

验收：报告准确定位 notes.py 第 1 行，属于信息线索，没有网络调用发现；范围完整。提交你的预期、报告中的 rule_id/context/line，以及一句解释。暂时不需要改核心代码或 manifest。

## 练习 2：调整一条规则的上下文条件

SG008 会把安全培训文档中引用的“忽略检查规则”也列为待复核。为显式以“教学引用：”开头的普通文档行增加一个狭窄条件：仍保留 SG008 证据，但 severity=info、confidence=medium，并说明是教学引用。只对 Markdown 普通文档行生效；不放宽代码、JSON/YAML 或其他句子。

验收：先写两个小测试——教学引用行保留 SG008 但不进入待复核队列；无前缀的相同句子仍为 medium 且需要复核。原有测试继续符合预期，报告中不删除发现。解释为什么这个前缀仍可能被伪装，因此不能构成自动接入批准。

## 练习 3：把一个命中转成人工复核问题

阅读 `reports/demo/18_risky_skill/report.json` 中 `risk.py:5` 的 SG003。用 4 句话回答：识别到了什么；哪些风险条件尚未证明；应向 Skill 提供者追问什么；有哪些可验证的降低影响方案。再说明允许 example.invalid 为什么不能豁免这一条。

验收：不把 shell=True 等同于命令注入，不声称已经执行/外传；明确参数来源和权限；提出可以检查的改进，例如固定程序与参数列表，并说明剩余限制。
