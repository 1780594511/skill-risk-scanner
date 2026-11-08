# Verified project status

Date: 2026-11-08 (Asia/Shanghai). Educational local MVP; development was AI-assisted. This is a working static triage implementation with measured functional evidence, not a production security certification.

## Publication preparation

The repository is a separate portable copy of the original local deliverable. Personal machine paths were removed from documentation; shareable logs use explicit placeholders for interpreter, project, home-directory paths and JUnit hostname. Test results and timestamps are not changed by this normalization.

Runtime output is ignored under `reports/`. Published snapshots are under `examples/` and `evidence/`. The only tracked `.env` is the exact synthetic fixture `fixtures/21_resource_limits/.env`. Git's reserved `.git` directory is created in a temporary automated test instead of being stored in the fixture tree. Two non-UTF-8 encoding fixtures retain their binary bytes through `.gitattributes`.

No global Skill installation, activation, credential creation, system configuration change, or CI deployment has been performed. Repository hosting does not install the Agent Skill wrapper.

## Actual verification

The committed source was exported using `git archive HEAD` into a new directory and tested there. This checks the actual tracked files rather than relying on ignored or uncommitted files. A normal local clone was attempted but the environment blocked its Git/MSYS helper; a successful clone is not claimed.

| Check | Observed result |
| --- | --- |
| Python / platform | Python 3.12.14 on Windows 11 |
| pytest | **89 passed, 2 skipped; 0 failures, 0 errors** |
| Handwritten synthetic benchmark | **24/24 cases; 42 TP, 0 FP, 0 FN** |
| Demo | Expected exit 3; normal and risk-pattern reports generated |
| Exception comparison | Expected exit 3 both times; all 3 findings retained, 2 annotated exceptions |
| Wrapper CLI walkthrough | Expected exit 3; redacted reports generated |
| Host Skill format validation | Previously passed for the identical SKILL.md; content hash and normalized record retained |

Evidence: [verification](evidence/verification.json), [JUnit](evidence/pytest-results.xml), [evaluation](evidence/evaluation.json), [tested source hashes](evidence/tested-source-sha256.json), [wrapper validation](evidence/skill-wrapper-validation.json).

The original local version had 88 passing tests. The portable repository adds one test for temporary `.git` metadata exclusion, producing 89. This is a real additional test, not a reclassification of a skipped test.

## Environment-specific skips

- Real Windows junction creation: PermissionError. Controlled reparse-flag and boundary tests passed, but do not replace this missing real-system check.
- Real hard-link creation: PermissionError. The implementation checks link count, but this environment did not validate an actual created hard link.

The real symbolic-link test ran and passed. Permission-error recovery also uses controlled mocks; comprehensive Windows ACL compatibility is not claimed.

## Scope of the evidence

Counting unit: unique `(case, rule_id, relative_path, 1-based line, context)`. One line can generate multiple rule findings. Expected results were independently written, not generated from scanner output. Zero FP/FN applies only to these finite synthetic cases; it is not a real-world malicious Skill detection rate.

No dynamic sandboxing, cross-file taint analysis, deobfuscation, full shell grammar, complete alias/scope analysis, JS/TS semantics, remote repository scanning, enterprise deployment, or filesystem race resistance is claimed. Exact-position exceptions do not automatically expire when file contents change; reviewers must reassess code changes.

Reproduce with `python scripts/verify.py` after installing development dependencies in an isolated environment. The scanner runtime itself uses only the standard library and is offline.
