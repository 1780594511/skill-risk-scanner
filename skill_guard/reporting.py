"""Structured output and conservative display. Raw source never enters reports by default."""

import html
import json
from pathlib import Path
import re
import stat

OUTPUT_MARKER = ".skill-guard-output"


def _check_output_file(path):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1 or getattr(st, "st_file_attributes", 0) & 0x400:
        raise ValueError("Refusing linked or non-regular output")


def safe_excerpt(source):
    """A vocabulary-limited token skeleton, NOT a verbatim excerpt.

    All strings, comments, URLs, numbers and non-whitelisted identifiers are omitted.
    Prefer omission to guessing whether a literal is a credential.
    """
    # Never copy any source substring except these fixed, harmless language tokens.
    vocabulary = {"import", "from", "requests", "httpx", "urllib", "request", "get",
                  "post", "urlopen", "urlretrieve", "subprocess", "run", "Popen",
                  "shell", "True", "False", "os", "system", "getenv", "environ",
                  "open", "read", "read_text", "read_bytes", "Path", "curl", "wget",
                  "bash", "sh", "Invoke-WebRequest", "Invoke-RestMethod", "iex"}
    # String/URL removal happens before tokenization, including incomplete strings.
    clean = re.sub(r"https?://\S+", " ", source, flags=re.I)
    clean = re.sub(r"(['\"]).*?(?:\1|$)", " ", clean)
    clean = clean.split("#", 1)[0]
    words = [w for w in re.findall(r"[A-Za-z_][A-Za-z_-]*", clean) if w in vocabulary]
    return "token skeleton: " + " ".join(words[:16]) + " [all other content omitted]" if words else None


def safe_display(value):
    """Escape HTML and Markdown, including autolink punctuation and control chars."""
    value = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    value = html.escape(value, quote=True)
    return re.sub(r"[\\`*_{}\[\]()#+.!|:~\-]", lambda m: f"&#{ord(m[0])};", value)


def markdown_report(report):
    s = report["summary"]
    lines = ["# Skill Guard 静态初筛报告", "", "**" + safe_display(s["conclusion"]) + "**", "",
             "规则命中是复核线索；本报告不是安全认证，也不证明代码已执行或数据已外传。", "",
             f"- 已扫描文件：{s['files_scanned']}；跳过文件：{s['files_skipped']}；跳过目录：{s['directories_skipped']}；其他跳过条目（如链接）：{s['other_entries_skipped']}",
             f"- 部分分析文件：{s['files_partial']}；读取字节：{s['bytes_read']}；范围完整：{s['complete']}",
             "- 跳过目录的子文件未枚举，不能计入已知跳过文件数。",
             "- 规则版本：" + safe_display(report["ruleset_version"]),
             "- 配置 SHA256：" + report["config"]["sha256"],
             "- 参考日期：" + safe_display(report["config"]["reference_date"]),
             "- 覆盖类型：" + safe_display(", ".join(s["covered_types"])),
             "- 禁用规则：" + safe_display(", ".join(report["config"]["disabled_rules"]) or "无"),
             "- 例外：" + str(s["excepted_findings"]) + "；仍保留所有命中。", "", "## 发现", "",
             "| 规则 | 类别 | 影响 / 置信度 | 定位 | 上下文 | 依据与复核 | 例外 |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for f in report["findings"]:
        loc = f"{f['path']}:{f['line']}"
        reason = f["evidence"] + "；" + "；".join(f["review"])
        if f.get("target"):
            reason += "；目标：" + (f["target"].get("host") or "目标待确认")
        if f["snippet"]:
            reason += "；" + f["snippet"]
        ex = f["exception"]["status"]
        for match in f["exception"].get("matches", []):
            ex += "；" + match["id"] + "：" + match["reason"] + "（到期 " + match["expires"] + "）"
        cells = [f["rule_id"], f["category"], f["severity"] + " / " + f["confidence"], loc, f["context"], reason, ex]
        lines.append("| " + " | ".join(safe_display(x) for x in cells) + " |")
    if not report["findings"]:
        lines += ["", "在本次规则及已覆盖内容中无命中；请同时检查覆盖缺口。"]
    lines += ["", "## 覆盖明细", "", "| 路径 | 类型 | 状态 | 原因 / 问题 |", "| --- | --- | --- | --- |"]
    for entry in report["coverage"]:
        cells = [entry["path"], entry["kind"], entry["status"], "; ".join(entry.get("issues", [])) or entry.get("reason", "")]
        lines.append("| " + " | ".join(safe_display(x) for x in cells) + " |")
    lines += ["", "## 配置与边界", "", "- 各类命中：" + safe_display(json.dumps(s["by_category"], ensure_ascii=False)),
              "- 资源上限：" + safe_display(json.dumps(report["config"]["limits"], sort_keys=True)),
              "- 未匹配的精确例外：" + safe_display(", ".join(report["config"]["unmatched_exception_ids"]) or "无"),
              "- 允许域名只作用于 SG001 / SG002，且仅在目标唯一、明确时适用。",
              "- 不执行输入，不跟踪重定向，不做动态分析、跨文件污点分析、反混淆或并发文件系统竞态防护。",
              "- Markdown 代码块是文档示例；JSON/YAML 仅作文本线索；JavaScript/TypeScript 等未覆盖。", ""]
    return "\n".join(lines)


def prepare_output(out, root=None):
    """Reserve a dedicated report directory; refuse links and source-overwrite targets."""
    out = Path(out).absolute()
    for part in (out, *out.parents):
        try:
            st = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise ValueError("Output path must not contain links/reparse points")
    out = out.resolve()
    if root is not None:
        root = Path(root).resolve()
        if out == root or root.is_relative_to(out):
            raise ValueError("Output must not equal or contain the scan root")
    if out.exists() and not (out / OUTPUT_MARKER).is_file() and any(out.iterdir()):
        raise ValueError("Use an empty or previously generated output directory")
    out.mkdir(parents=True, exist_ok=True)
    marker = out / OUTPUT_MARKER
    _check_output_file(marker)
    marker.write_text("skill-guard report directory v1\n", encoding="utf-8")
    return out


def write_json(path, data):
    path = Path(path)
    _check_output_file(path)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_report(report, out):
    out = Path(out)
    write_json(out / "report.json", report)
    target = out / "report.md"
    _check_output_file(target)
    target.write_text(markdown_report(report), encoding="utf-8")
