"""Reproduce evidence using ONLY trusted CLI/test code, never execute fixture files."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

PROJECT = Path(__file__).resolve().parents[1]


def normalize(text):
    """Preserve test results while replacing machine-specific paths in shareable logs."""
    replacements = [(sys.executable, "<PYTHON>"), (str(PROJECT), "<PROJECT_ROOT>"),
                    (str(Path.home()), "<USER_HOME>")]
    for original, label in replacements:
        text = text.replace(original, label).replace(original.replace("\\", "/"), label)
    return re.sub(r"pytest-of-[^/\\\s]+", "pytest-of-USER", text)


def main():
    reports = PROJECT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / ".skill-guard-output").write_text("skill-guard report directory v1\n", encoding="utf-8")
    env = os.environ | {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    temp_parent = PROJECT / "work"
    temp_parent.mkdir(exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="verification-", dir=temp_parent))
    env["TEMP"] = env["TMP"] = str(temp)
    commands = [
        ("demo", ["-m", "skill_guard", "demo"], 3),
        ("contrast_baseline", ["-m", "skill_guard", "scan", "fixtures/17_allowlist", "--config", "configs/default.json", "--out", "reports/contrast/baseline"], 3),
        ("contrast_reviewed", ["-m", "skill_guard", "scan", "fixtures/17_allowlist", "--config", "configs/reviewed-example.json", "--out", "reports/contrast/reviewed"], 3),
        ("wrapper_cli", ["-m", "skill_guard", "scan", "fixtures/18_risky_skill", "--config", "configs/default.json", "--out", "reports/wrapper-walkthrough"], 3),
        ("evaluate", ["-m", "skill_guard", "evaluate", "--fixtures", "fixtures", "--out", "reports/evaluation"], 0),
        ("pytest", ["-m", "pytest"], 0),
    ]
    rows = []
    for name, args, expected in commands:
        start = time.perf_counter()
        completed = subprocess.run([sys.executable, *args], cwd=PROJECT, env=env,
                                   capture_output=True, text=True, encoding="utf-8", timeout=120)
        row = {"name": name, "command": ["<PYTHON>", *args], "cwd": "<PROJECT_ROOT>",
               "returncode": completed.returncode, "expected_returncode": expected,
               "matched_expected_exit": completed.returncode == expected,
               "stdout": normalize(completed.stdout), "stderr": normalize(completed.stderr),
               "elapsed_seconds": round(time.perf_counter() - start, 4)}
        rows.append(row)
        print(f"{name}: exit {completed.returncode}; expected {expected}")
        (reports / f"{name}-run.log").write_text(normalize(completed.stdout + completed.stderr), encoding="utf-8")
    # Normalize only paths/hostname. The measured outcomes and durations are unchanged.
    junit_path = reports / "pytest-results.xml"
    junit_text = normalize(junit_path.read_text(encoding="utf-8"))
    # Angle brackets in replacement labels must be escaped in XML attribute values.
    for label in ("PYTHON", "PROJECT_ROOT", "USER_HOME"):
        junit_text = junit_text.replace("<" + label + ">", "[" + label + "]")
    junit_tree = ET.fromstring(junit_text)
    for suite in junit_tree.iter("testsuite"):
        if "hostname" in suite.attrib:
            suite.set("hostname", "[HOSTNAME]")
    ET.ElementTree(junit_tree).write(junit_path, encoding="utf-8", xml_declaration=True)
    test_xml = ET.parse(reports / "pytest-results.xml").getroot()
    skipped = [{"test": item.get("name"), "reason": item.find("skipped").get("message")} for item in test_xml.iter("testcase") if item.find("skipped") is not None]
    suites = list(test_xml.iter("testsuite"))
    counts = {key: sum(int(s.get(key, 0)) for s in suites) for key in ("tests", "failures", "errors", "skipped")}
    counts["passed"] = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    result = {"recorded_at_utc": datetime.now(timezone.utc).isoformat(), "user_facing_date_asia_shanghai": datetime.now(timezone(timedelta(hours=8))).date().isoformat(),
              "python": sys.version, "platform": platform.platform(), "executable": "<PYTHON>",
              "publication_normalization": "Executable/project/home paths and JUnit hostname normalized; results, skips and timestamps retained.",
              "commands": rows, "tests": counts, "skipped_tests": skipped,
              "all_expected_exits_matched": all(r["matched_expected_exit"] for r in rows)}
    (reports / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if result["all_expected_exits_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
