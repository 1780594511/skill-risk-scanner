"""Strict JSON configuration; no plugins, callbacks, or target-side config discovery."""

from copy import deepcopy
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

RULE_IDS = tuple(f"SG{i:03d}" for i in range(1, 9))
DEFAULT = {
    "limits": {"max_file_bytes": 262144, "max_files": 1000,
               "max_total_bytes": 8388608, "max_entries": 10000, "max_depth": 32},
    "disabled_rules": [], "allowed_domains": [], "exceptions": [],
    "report": {"include_snippets": False},
}


class ConfigError(ValueError):
    pass


def _keys(value, allowed, label):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ConfigError(f"{label}: expected an object with supported keys only")


def _expiry(item, today):
    if not isinstance(item.get("reason"), str) or not item["reason"].strip():
        raise ConfigError("An exception requires a nonempty reason")
    try:
        if not isinstance(item.get("expires"), str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["expires"]):
            raise ValueError
        expiry = date.fromisoformat(item["expires"])
    except (ValueError, TypeError, KeyError):
        raise ConfigError("An exception requires expires in YYYY-MM-DD") from None
    if expiry < today:
        raise ConfigError("Expired exception: remove or renew after review")


def load_config(path=None, *, data=None, today=None):
    """Return a validated effective config. Only explicitly supplied JSON is read."""
    if path is not None and data is not None:
        raise ConfigError("Specify either path or data")
    if path is not None:
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ConfigError("Config exceeds 64 KiB")
            data = json.loads(raw.decode("utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ConfigError("Cannot read config as UTF-8 JSON") from None
    data = {} if data is None else deepcopy(data)
    _keys(data, (*DEFAULT, "reference_date"), "config")
    cfg = deepcopy(DEFAULT)
    cfg.update(data)
    now = today or datetime.now(timezone.utc).date()
    try:
        cfg["reference_date"] = date.fromisoformat(data.get("reference_date", now.isoformat())).isoformat()
    except (TypeError, ValueError):
        raise ConfigError("reference_date must be YYYY-MM-DD") from None
    reference = date.fromisoformat(cfg["reference_date"])
    _keys(cfg["limits"], DEFAULT["limits"], "limits")
    cfg["limits"] = DEFAULT["limits"] | cfg["limits"]
    ceilings = {"max_file_bytes": 16777216, "max_files": 100000,
                "max_total_bytes": 268435456, "max_entries": 1000000, "max_depth": 100}
    for key, val in cfg["limits"].items():
        if type(val) is not int or not 1 <= val <= ceilings[key]:
            raise ConfigError(f"Invalid positive bounded limit: {key}")
    disabled = cfg["disabled_rules"]
    if not isinstance(disabled, list) or any(x not in RULE_IDS for x in disabled):
        raise ConfigError("disabled_rules must contain known rule IDs")
    cfg["disabled_rules"] = sorted(set(disabled))
    _keys(cfg["report"], ("include_snippets",), "report")
    cfg["report"] = DEFAULT["report"] | cfg["report"]
    if type(cfg["report"]["include_snippets"]) is not bool:
        raise ConfigError("include_snippets must be boolean")
    for field in ("allowed_domains", "exceptions"):
        if not isinstance(cfg[field], list) or len(cfg[field]) > 1000:
            raise ConfigError(f"{field} must be a list of at most 1000 records")
    seen = set()
    for item in cfg["allowed_domains"]:
        _keys(item, ("domain", "reason", "expires"), "domain exception")
        _expiry(item, reference)
        domain = item.get("domain")
        if not isinstance(domain, str) or len(domain) > 253 or "." not in domain or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
            raise ConfigError("Use an exact lowercase hostname, without URL, port, or wildcard")
        if domain in seen:
            raise ConfigError("Duplicate allowed domain")
        seen.add(domain)
    seen = set()
    for item in cfg["exceptions"]:
        _keys(item, ("id", "rule_id", "path", "line", "reason", "expires"), "finding exception")
        _expiry(item, reference)
        if not isinstance(item.get("id"), str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", item["id"]):
            raise ConfigError("Exception id must be a short ASCII identifier")
        if item["id"] in seen:
            raise ConfigError("Duplicate exception id")
        seen.add(item["id"])
        if item.get("rule_id") not in RULE_IDS or type(item.get("line")) is not int or item["line"] < 1:
            raise ConfigError("Exception requires rule_id and positive line")
        p = item.get("path")
        if not isinstance(p, str) or not p or "\\" in p or ":" in p or any(x in p.split("/") for x in ("..", ".", "")) or PurePosixPath(p).is_absolute() or any(x in p for x in "*?["):
            raise ConfigError("Exception path must be an exact relative POSIX path")
    return cfg


def config_digest(cfg):
    return hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
