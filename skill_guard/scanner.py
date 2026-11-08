"""Bounded, local, non-executing file traversal and coverage accounting."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import time

from . import RULESET_VERSION, __version__
from .config import config_digest, load_config
from .reporting import OUTPUT_MARKER
from .rules import analyze_text, apply_exceptions

SUPPORTED = {".md", ".py", ".sh", ".ps1", ".json", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
             ".ssh", ".aws", ".azure", ".gnupg", ".config", ".mypy_cache"}
SENSITIVE_NAMES = {"id_rsa", "id_ed25519", "credentials", "credentials.json", "secrets.json"}


class ScanError(ValueError):
    pass


def is_link_or_reparse(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def _root_path(path):
    path = Path(path).absolute()
    try:
        for part in (path, *path.parents):
            if is_link_or_reparse(part.lstat()):
                raise ScanError("Root and its ancestors must not be links/reparse points")
        root = path.resolve(strict=True)
        if not root.is_dir():
            raise ScanError("Scan root must be a directory")
        if root == Path(root.anchor) or root == Path.home().resolve():
            raise ScanError("Choose a specific Skill directory, not a drive root or home directory")
    except OSError:
        raise ScanError("Cannot access scan root") from None
    return root


def scan(root, cfg=None, *, out_dir=None):
    """Only source files beneath root are opened. Never import or execute inputs."""
    start = time.perf_counter()
    timestamp = datetime.now(timezone.utc).isoformat()
    cfg = load_config(data=cfg) if cfg is not None else load_config()
    root = _root_path(root)
    out_path = Path(out_dir).resolve() if out_dir else None
    coverage, findings = [], []
    totals = {"bytes": 0, "attempts": 0, "entries": 0}
    limits = cfg["limits"]

    def record(path, kind, status, reason="", **details):
        rel = path.relative_to(root).as_posix()
        coverage.append({"path": rel, "kind": kind, "status": status, "reason": reason, **details})

    def walk(folder, depth):
        if depth > limits["max_depth"]:
            record(folder, "directory", "skipped", "depth_limit_children_not_enumerated")
            return
        try:
            entries = []
            with os.scandir(folder) as stream:
                for entry in stream:
                    if totals["entries"] + len(entries) >= limits["max_entries"]:
                        record(folder, "directory", "skipped", "entry_limit_children_not_enumerated")
                        totals["entries"] = limits["max_entries"]
                        return
                    entries.append(entry)
            totals["entries"] += len(entries)
        except OSError:
            record(folder, "directory", "skipped", "directory_permission_or_io_error")
            return
        if any(e.name == OUTPUT_MARKER for e in entries):
            record(folder, "directory", "skipped", "generated_output_children_not_enumerated")
            return
        for entry in sorted(entries, key=lambda e: (e.name.casefold(), e.name)):
            path = Path(entry.path)
            entry_kind = "unknown"
            try:
                st = path.lstat()
                entry_kind = "file" if stat.S_ISREG(st.st_mode) else "directory" if stat.S_ISDIR(st.st_mode) else "unknown"
                if is_link_or_reparse(st):
                    record(path, "link", "skipped", "symlink_or_reparse_point")
                    continue
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    record(path, "unknown", "skipped", "outside_root")
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if entry.name.lower() in SKIP_DIRS:
                        record(path, "directory", "skipped", "excluded_directory_children_not_enumerated")
                    elif out_path is not None and resolved == out_path:
                        record(path, "directory", "skipped", "output_directory_children_not_enumerated")
                    else:
                        walk(path, depth + 1)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    record(path, "special", "skipped", "not_regular_file")
                    continue
                if st.st_nlink > 1:
                    record(path, "file", "skipped", "hard_link_not_read")
                    continue
                name = entry.name.lower()
                if name == ".env" or name.startswith(".env.") or name in SENSITIVE_NAMES or path.suffix.lower() in (".pem", ".key"):
                    record(path, "file", "skipped", "sensitive_file_not_read")
                    continue
                if path.suffix.lower() not in SUPPORTED:
                    record(path, "file", "skipped", "unsupported_type")
                    continue
                if totals["attempts"] >= limits["max_files"]:
                    record(path, "file", "skipped", "file_count_limit")
                    continue
                totals["attempts"] += 1
                if st.st_size > limits["max_file_bytes"]:
                    record(path, "file", "skipped", "file_size_limit")
                    continue
                remaining = limits["max_total_bytes"] - totals["bytes"]
                if st.st_size > remaining or remaining <= 0:
                    record(path, "file", "skipped", "total_read_limit")
                    continue
                # Defense in depth, not an atomic filesystem sandbox. See documented TOCTOU limit.
                if is_link_or_reparse(path.lstat()) or not path.resolve(strict=True).is_relative_to(root):
                    record(path, "file", "skipped", "path_changed_before_read")
                    continue
                with path.open("rb") as stream:
                    raw = stream.read(min(st.st_size + 1, limits["max_file_bytes"], remaining))
                    current = os.fstat(stream.fileno())
                totals["bytes"] += len(raw)
                if len(raw) != st.st_size or current.st_size != st.st_size or current.st_mtime_ns != st.st_mtime_ns or current.st_ino != st.st_ino:
                    record(path, "file", "skipped", "file_changed_during_read")
                    continue
                try:
                    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
                    text = raw.decode(encoding)
                    if "\x00" in text:
                        raise UnicodeError("NUL")
                except UnicodeError:
                    record(path, "file", "skipped", "unsupported_encoding_or_binary")
                    continue
                rel = path.relative_to(root).as_posix()
                hits, issues = analyze_text(text, rel, cfg)
                findings.extend(hits)
                record(path, "file", "partial" if issues else "scanned", issues=issues,
                       sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), encoding=encoding,
                       suffix=path.suffix.lower())
            except (OSError, RuntimeError):
                record(path, entry_kind, "skipped", "file_permission_path_or_io_error")

    walk(root, 0)
    findings = apply_exceptions(findings, cfg)
    coverage.sort(key=lambda r: (r["path"], r["status"]))
    scanned = [x for x in coverage if x["status"] in ("scanned", "partial")]
    skipped = [x for x in coverage if x["status"] == "skipped"]
    complete = not skipped and not any(x["status"] == "partial" for x in coverage) and not cfg["disabled_rules"]
    review_count = sum(f["review_required"] for f in findings)
    conclusions = []
    if not complete:
        conclusions.append("存在未覆盖内容")
    if review_count:
        conclusions.append("需人工复核")
    elif findings:
        conclusions.append("仅信息性线索或已有记录的例外")
    elif complete:
        conclusions.append("完整扫描且无规则命中（限声明的静态规则范围）")
    else:
        conclusions.append("已覆盖内容无规则命中")
    used_exceptions = {m["id"] for f in findings for m in f["exception"]["matches"]}
    summary = {
        "files_scanned": len(scanned), "files_partial": sum(x["status"] == "partial" for x in coverage),
        "files_skipped": sum(x["kind"] == "file" for x in skipped),
        "directories_skipped": sum(x["kind"] == "directory" for x in skipped),
        "other_entries_skipped": sum(x["kind"] not in ("file", "directory") for x in skipped),
        "bytes_read": totals["bytes"], "complete": complete, "review_findings": review_count,
        "excepted_findings": sum(f["exception"]["status"] == "applied" for f in findings),
        "finding_count": len(findings), "covered_types": sorted({x["suffix"] for x in scanned}),
        "by_category": dict(sorted(Counter(f["category"] for f in findings).items())),
        "by_rule": dict(sorted(Counter(f["rule_id"] for f in findings).items())),
        "uncovered": [{k: x[k] for k in ("path", "kind", "status", "reason", "issues") if k in x} for x in coverage if x["status"] != "scanned"],
        "conclusion": "；".join(conclusions),
    }
    return {
        "schema_version": "1", "scanner_version": __version__, "ruleset_version": RULESET_VERSION,
        "root_name": root.name, "summary": summary, "coverage": coverage, "findings": findings,
        "config": {"sha256": config_digest(cfg), "limits": cfg["limits"], "disabled_rules": cfg["disabled_rules"],
                   "reference_date": cfg["reference_date"], "include_snippets": cfg["report"]["include_snippets"],
                   "allowed_domain_count": len(cfg["allowed_domains"]), "exact_exception_count": len(cfg["exceptions"]),
                   "unmatched_exception_ids": sorted(x["id"] for x in cfg["exceptions"] if x["id"] not in used_exceptions)},
        "runtime": {"started_at_utc": timestamp, "elapsed_seconds": round(time.perf_counter() - start, 6)},
    }


def scan_exit_code(report):
    if not report["summary"]["complete"]:
        return 4  # Coverage takes precedence; review findings remain in the report.
    return 3 if report["summary"]["review_findings"] else 0
