"""Compare against independent, handwritten rule-location expectations."""

from collections import Counter
import json
from pathlib import Path
import re

from .config import ConfigError, RULE_IDS, load_config
from .reporting import prepare_output, safe_display, write_json, write_report
from .scanner import scan


def _key(f):
    return tuple(f[x] for x in ("rule_id", "path", "line", "context"))


def _load_manifest(fixtures):
    with (fixtures / "manifest.json").open("rb") as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("Manifest exceeds 1 MiB")
    manifest = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list) or len(manifest["cases"]) > 1000:
        raise ValueError("Invalid manifest cases")
    seen = set()
    for case in manifest["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not re.fullmatch(r"[a-z0-9_]+", case["id"]) or case["id"] in seen:
            raise ValueError("Invalid or duplicate fixture id")
        seen.add(case["id"])
        if type(case.get("complete")) is not bool or not isinstance(case.get("expected"), list) or case.get("expected_error") not in (None, "config"):
            raise ValueError("Invalid manifest expectation")
        for group in (case["expected"], case.get("expected_excepted", [])):
            if not isinstance(group, list):
                raise ValueError("Invalid expected locations")
            locations = set()
            for item in group:
                if not isinstance(item, dict) or item.get("rule_id") not in RULE_IDS or type(item.get("line")) is not int or item["line"] < 1 or not isinstance(item.get("context"), str):
                    raise ValueError("Invalid expected finding")
                path = item.get("path")
                if not isinstance(path, str) or any(part in ("", ".", "..") for part in path.split("/")) or "\\" in path or ":" in path:
                    raise ValueError("Invalid expected path")
                if _key(item) in locations:
                    raise ValueError("Duplicate expected location")
                locations.add(_key(item))
        if not isinstance(case.get("skip_reasons", []), list) or any(not isinstance(x, str) for x in case.get("skip_reasons", [])):
            raise ValueError("Invalid skip expectations")
    return manifest


def evaluate(fixtures, out):
    fixtures = Path(fixtures).resolve(strict=True)
    # Evaluation fixtures/manifest are TRUSTED developer input, not third-party configuration.
    manifest = _load_manifest(fixtures)
    out = prepare_output(out, fixtures)
    rows, expected_total, tp_total, fp_total, fn_total = [], 0, 0, 0, 0
    by_rule = {f"SG{i:03d}": {"tp": 0, "fp": 0, "fn": 0} for i in range(1, 9)}
    for case in manifest["cases"]:
        name = case["id"]
        if not isinstance(name, str) or not name.replace("_", "").isalnum() or "/" in name or "\\" in name:
            raise ValueError("Invalid fixture id")
        root = (fixtures / name).resolve(strict=True)
        if not root.is_relative_to(fixtures):
            raise ValueError("Fixture outside trusted fixtures root")
        case_out = prepare_output(out / name, root)
        try:
            cfg = load_config(data=case.get("config", {}))
            report = scan(root, cfg, out_dir=case_out)
        except ConfigError:
            ok = case.get("expected_error") == "config"
            row = {"case": name, "passed": ok, "expected_error": case.get("expected_error"), "actual_error": "config"}
            write_json(case_out / "result.json", row)
            rows.append(row)
            continue
        expected = {_key(x) for x in case["expected"]}
        actual = {_key(x) for x in report["findings"]}
        tp, fp, fn = expected & actual, actual - expected, expected - actual
        expected_total += len(expected)
        tp_total += len(tp)
        fp_total += len(fp)
        fn_total += len(fn)
        for group, label in ((tp, "tp"), (fp, "fp"), (fn, "fn")):
            for key in group:
                by_rule[key[0]][label] += 1
        actual_excepted = {_key(x) for x in report["findings"] if x["exception"]["status"] == "applied"}
        expected_excepted = {_key(x) for x in case.get("expected_excepted", [])}
        reasons = {x["reason"] for x in report["coverage"] if x["status"] == "skipped"}
        expected_reasons = set(case.get("skip_reasons", []))
        passed = not fp and not fn and report["summary"]["complete"] == case["complete"] and actual_excepted == expected_excepted and expected_reasons == reasons and not case.get("expected_error")
        row = {"case": name, "passed": passed, "expected": len(expected), "tp": len(tp), "fp": len(fp), "fn": len(fn),
               "false_positives": sorted(fp), "false_negatives": sorted(fn), "complete": report["summary"]["complete"],
               "exceptions_match": actual_excepted == expected_excepted, "skip_reasons_match": expected_reasons == reasons}
        rows.append(row)
        write_report(report, case_out)
    result = {"unit": "unique (case, rule_id, relative_path, 1-based line, context)",
              "benchmark": "handwritten synthetic functional fixtures; NOT real-world malware detection rates",
              "cases": rows, "case_count": len(rows), "passed_cases": sum(r["passed"] for r in rows),
              "expected_hits": expected_total, "tp": tp_total, "fp": fp_total, "fn": fn_total,
              "precision": tp_total / (tp_total + fp_total) if tp_total + fp_total else None,
              "recall": tp_total / (tp_total + fn_total) if tp_total + fn_total else None,
              "by_rule": by_rule}
    write_json(out / "evaluation.json", result)
    lines = ["# 合成样本功能评测", "", "人工 manifest 是测试真值，不由扫描器输出反推。", "",
             "计数单位：每个样本内唯一的（规则、相对路径、1-based 行号、上下文）位置。",
             "仅用于验证这些有限样本上的预期行为，不代表真实恶意 Skill 检测率；未定义海量无命中位置，因此不计算 TN 或真实误报率。", "",
             f"样本通过：{result['passed_cases']} / {len(rows)}；预期命中：{expected_total}；TP：{tp_total}；FP：{fp_total}；FN：{fn_total}。", "",
             "| 样本 | 通过 | TP | FP | FN |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        lines.append("| " + " | ".join(safe_display(row.get(k, "配置错误用例")) for k in ("case", "passed", "tp", "fp", "fn")) + " |")
    (out / "evaluation.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result
