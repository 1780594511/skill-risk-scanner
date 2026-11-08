from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skill_guard.config import load_config
from skill_guard.evaluation import evaluate
from skill_guard.reporting import markdown_report, prepare_output, safe_excerpt, write_report
from skill_guard.scanner import scan

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT / "fixtures"


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "skill_guard", *map(str, args)], cwd=PROJECT,
                          env=os.environ | {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
                          capture_output=True, text=True, encoding="utf-8", timeout=30)


@pytest.mark.parametrize("snippets", [False, True])
def test_no_synthetic_secret_values_in_reports(tmp_path, snippets):
    cfg = load_config(data={"report": {"include_snippets": snippets}})
    for case in ("03_python_network", "17_allowlist", "18_risky_skill", "19_plain_config"):
        report = scan(FIXTURES / case, cfg)
        out = prepare_output(tmp_path / case)
        write_report(report, out)
        for path in (out / "report.json", out / "report.md"):
            content = path.read_text(encoding="utf-8")
            assert "FAKE_QUERY_TOKEN_DO_NOT_USE" not in content
            assert "FAKE_AUTH_TOKEN_DO_NOT_USE" not in content
            assert "FAKE_CONFIG_TOKEN_DO_NOT_USE" not in content
            assert "FAKE_API_TOKEN" not in content
            assert "token=" not in content


def test_html_markdown_and_autolink_escaping():
    report = scan(FIXTURES / "03_python_network")
    # Such filenames are impossible on Windows; inject into report data for renderer testing.
    malicious = '<script>alert(1)</script> [click](https://example.invalid/?key=FAKE) `x` | ![image](x)'
    report["findings"][0]["path"] = malicious
    report["coverage"][0]["path"] = malicious
    rendered = markdown_report(report)
    assert "<script>" not in rendered
    assert "[click](" not in rendered
    assert "https://" not in rendered
    assert "![image](" not in rendered
    assert "&lt;script&gt;" in rendered


def test_excerpt_omits_unknown_tokens_and_all_literals():
    text = 'requests.post("https://user:FAKE_PASSWORD@example.invalid/?token=FAKE_QUERY", headers={"Authorization": "FAKE_BEARER"}, value=FAKE_VARIABLE) # FAKE_COMMENT'
    excerpt = safe_excerpt(text)
    assert excerpt is not None
    assert "FAKE" not in excerpt and "https" not in excerpt and "example" not in excerpt
    assert safe_excerpt("UNRECOGNIZED_PRIVATE_TEXT") is None


def test_identical_input_config_has_stable_core():
    cfg = load_config(PROJECT / "configs" / "default.json")
    first, second = scan(FIXTURES / "18_risky_skill", cfg), scan(FIXTURES / "18_risky_skill", cfg)
    first.pop("runtime")
    second.pop("runtime")
    assert first == second
    for finding in first["findings"]:
        assert {"rule_id", "category", "severity", "confidence", "path", "line", "context", "evidence", "snippet", "review", "exception"} <= finding.keys()
        assert finding["line"] >= 1


@pytest.mark.parametrize("case, expected", [("02_no_hits", 0), ("01_clean_docs", 0), ("03_python_network", 3), ("16_broken_python", 4)])
def test_cli_scan_exit_codes(tmp_path, case, expected):
    result = run_cli("scan", FIXTURES / case, "--config", PROJECT / "configs" / "default.json", "--out", tmp_path / "report")
    assert result.returncode == expected, result.stderr
    assert (tmp_path / "report" / "report.json").is_file()
    assert (tmp_path / "report" / "report.md").is_file()


def test_cli_config_error_is_distinct(tmp_path):
    cfg = tmp_path / "invalid.json"
    cfg.write_text('{"plugin": "FAKE_PRIVATE_VALUE"}', encoding="utf-8")
    result = run_cli("scan", FIXTURES / "01_clean_docs", "--config", cfg, "--out", tmp_path / "out")
    assert result.returncode == 2
    assert "FAKE_PRIVATE_VALUE" not in result.stderr
    assert not (tmp_path / "out").exists()


def test_cli_demo(tmp_path):
    result = run_cli("demo", "--out", tmp_path / "demo")
    assert result.returncode == 3
    assert json.loads((tmp_path / "demo" / "demo-index.json").read_text())["scan_exit_codes"] == [0, 3]


def test_evaluation_and_cli_mismatch_exit(tmp_path):
    result = evaluate(FIXTURES, tmp_path / "evaluation")
    assert result["passed_cases"] == 24
    assert result["expected_hits"] == result["tp"] == 42
    assert result["fp"] == result["fn"] == 0
    custom = tmp_path / "custom"
    (custom / "sample").mkdir(parents=True)
    (custom / "sample" / "source.py").write_text('import requests\nrequests.get("https://example.invalid")', encoding="utf-8")
    # A deliberately incorrect human expectation must fail, not silently update the manifest.
    manifest = {"cases": [{"id": "sample", "expected": [], "complete": True}]}
    (custom / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    completed = run_cli("evaluate", "--fixtures", custom, "--out", tmp_path / "bad-evaluation")
    assert completed.returncode == 1
    assert json.loads((custom / "manifest.json").read_text()) == manifest


def test_target_side_config_does_not_change_scanner(tmp_path):
    (tmp_path / "config.json").write_text('{"disabled_rules": ["SG001"], "callback": "do-not-run"}', encoding="utf-8")
    (tmp_path / "source.py").write_text('import requests\nrequests.get("https://example.invalid")', encoding="utf-8")
    report = scan(tmp_path)
    assert report["summary"]["by_rule"] == {"SG001": 1}
    assert report["config"]["disabled_rules"] == []


@pytest.mark.parametrize("manifest", [{}, {"cases": [{"id": "../escape", "expected": [], "complete": True}]}, {"cases": [{"id": "x", "expected": [{"rule_id": "SG001"}], "complete": True}]}])
def test_invalid_manifest_returns_input_error(tmp_path, manifest):
    fixture_root = tmp_path / "cases"
    fixture_root.mkdir()
    (fixture_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = run_cli("evaluate", "--fixtures", fixture_root, "--out", tmp_path / "report")
    assert result.returncode == 2
    assert not (tmp_path / "report").exists()
