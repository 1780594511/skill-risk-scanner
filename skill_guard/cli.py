"""CLI entry points; runtime uses only the Python standard library."""

import argparse
from pathlib import Path
import sys

from .config import ConfigError, load_config
from .evaluation import evaluate
from .reporting import prepare_output, write_json, write_report
from .scanner import ScanError, scan, scan_exit_code

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local offline static Skill risk triage; no execution of target content")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Scan an explicitly selected local directory")
    scan_parser.add_argument("root", type=Path)
    scan_parser.add_argument("--config", type=Path)
    scan_parser.add_argument("--out", type=Path, required=True)
    demo_parser = sub.add_parser("demo", help="Scan bundled synthetic examples only")
    demo_parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "reports" / "demo")
    eval_parser = sub.add_parser("evaluate", help="Evaluate trusted synthetic fixtures against handwritten manifest")
    eval_parser.add_argument("--fixtures", type=Path, default=PROJECT_ROOT / "fixtures")
    eval_parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            cfg = load_config(args.config)
            # Validate root before creating output; even an invalid command must not hide sources.
            from .scanner import _root_path
            root = _root_path(args.root)
            out = prepare_output(args.out, root)
            report = scan(root, cfg, out_dir=out)
            write_report(report, out)
            print(report["summary"]["conclusion"])
            print(f"JSON / Markdown: {out}")
            return scan_exit_code(report)
        if args.command == "evaluate":
            result = evaluate(args.fixtures, args.out)
            print(f"Cases: {result['passed_cases']}/{result['case_count']}; TP={result['tp']} FP={result['fp']} FN={result['fn']}")
            return 0 if result["passed_cases"] == result["case_count"] else 1
        fixtures = PROJECT_ROOT / "fixtures"
        out = prepare_output(args.out, fixtures)
        codes = []
        for name in ("01_clean_docs", "18_risky_skill"):
            case_out = prepare_output(out / name, fixtures / name)
            report = scan(fixtures / name, load_config(PROJECT_ROOT / "configs" / "default.json"), out_dir=case_out)
            write_report(report, case_out)
            code = scan_exit_code(report)
            codes.append(code)
            print(f"{name}: {report['summary']['conclusion']}; exit={code}")
        write_json(out / "demo-index.json", {"cases": ["01_clean_docs", "18_risky_skill"], "scan_exit_codes": codes})
        return 4 if 4 in codes else 3 if 3 in codes else 0
    except (ConfigError, ScanError, OSError, ValueError) as error:
        # Don't echo raw file contents, decoder messages, configuration values or secrets.
        print(f"ERROR: {type(error).__name__}; check directory, JSON config, limits, expiry and output permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
