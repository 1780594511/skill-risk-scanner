from datetime import date

import pytest

from skill_guard.config import ConfigError, load_config


@pytest.mark.parametrize("data", [
    {"plugin": "arbitrary.py"}, {"disabled_rules": ["SG999"]},
    {"limits": {"max_files": True}}, {"limits": {"max_file_bytes": 0}},
    {"limits": {"max_total_bytes": 10**20}}, {"limits": {"typo": 1}},
    {"report": {"include_snippets": "yes"}}, {"report": {"raw_secrets": True}},
    {"allowed_domains": ["example.invalid"]},
    {"allowed_domains": [{"domain": "*.example.invalid", "reason": "x", "expires": "2099-01-01"}]},
    {"allowed_domains": [{"domain": "example..invalid", "reason": "x", "expires": "2099-01-01"}]},
    {"allowed_domains": [{"domain": "https://example.invalid", "reason": "x", "expires": "2099-01-01"}]},
    {"allowed_domains": [{"domain": "example.invalid", "reason": "", "expires": "2099-01-01"}]},
    {"allowed_domains": [{"domain": "example.invalid", "reason": "x", "expires": "yesterday"}]},
    {"allowed_domains": [{"domain": "example.invalid", "reason": "x", "expires": "2000-01-01"}]},
    {"exceptions": [{"id": "x", "rule_id": "SG001", "path": "../file.py", "line": 1, "reason": "x", "expires": "2099-01-01"}]},
    {"exceptions": [{"id": "x", "rule_id": "SG001", "path": "*.py", "line": 1, "reason": "x", "expires": "2099-01-01"}]},
])
def test_invalid_config(data):
    with pytest.raises(ConfigError):
        load_config(data=data, today=date(2026, 11, 8))


def test_invalid_encoding_json_and_oversize(tmp_path):
    p = tmp_path / "bad.json"
    for content in (b"\x80", b"not-json", b" " * 65537):
        p.write_bytes(content)
        with pytest.raises(ConfigError):
            load_config(p)


def test_expiry_and_reproducible_reference_date():
    cfg = {"reference_date": "2026-11-08", "allowed_domains": [{"domain": "example.invalid", "reason": "reviewed", "expires": "2026-11-08"}]}
    assert load_config(data=cfg, today=date(2027, 1, 1))["reference_date"] == "2026-11-08"
    cfg.pop("reference_date")
    with pytest.raises(ConfigError):
        load_config(data=cfg, today=date(2027, 1, 1))
