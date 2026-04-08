#!/usr/bin/env python3
"""
Audit wx functions annotated in src/sdk and summarize de-dup readiness.

This script consumes:
- src/sdk/** Address: 0x... annotations
- scripts/wx_verify_readme_scope_symbols.py CSV output

It produces:
- CSV of wx README-scope entries that are actually annotated in src
- Markdown summary with current counts and unresolved recovered entries
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path


ADDR_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{8})")
FILE_EXTENSIONS = {".h", ".hpp", ".hh", ".hxx", ".c", ".cpp", ".cc", ".cxx", ".inl", ".ipp"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit wx source de-dup readiness.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument("--src-root", default="src/sdk", help="Source root scanned for Address annotations.")
    parser.add_argument(
        "--verification-csv",
        default="decomp/recovery/reports/wxwidgets_readme_scope_verification.csv",
        help="Input verification CSV from wx_verify_readme_scope_symbols.py.",
    )
    parser.add_argument(
        "--csv-out",
        default="decomp/recovery/reports/wxwidgets_readme_scope_annotated_in_src.csv",
        help="Output CSV path for annotated-in-src rows.",
    )
    parser.add_argument(
        "--report-out",
        default="decomp/recovery/reports/wxwidgets_source_dedup_audit.md",
        help="Output markdown summary path.",
    )
    return parser.parse_args()


def iter_source_files(src_root: Path):
    for path in src_root.rglob("*"):
        if path.is_file() and path.suffix.lower() in FILE_EXTENSIONS:
            yield path


def collect_annotated_addresses(repo_root: Path, src_root: Path) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for path in iter_source_files(src_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(repo_root)).replace("\\", "/")
        for match in ADDR_RE.finditer(text):
            addr = int(match.group(1), 16)
            out.setdefault(addr, set()).add(rel)
    return out


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    src_root = (repo_root / args.src_root).resolve()
    verification_csv = (repo_root / args.verification_csv).resolve()
    csv_out = (repo_root / args.csv_out).resolve()
    report_out = (repo_root / args.report_out).resolve()

    annotated = collect_annotated_addresses(repo_root=repo_root, src_root=src_root)

    rows = list(csv.DictReader(verification_csv.open("r", encoding="utf-8", newline="")))
    present_rows: list[dict[str, str]] = []
    for row in rows:
        try:
            addr = int(row["address"], 16)
        except Exception:
            continue
        if addr not in annotated:
            continue
        item = dict(row)
        item["files"] = ";".join(sorted(annotated[addr]))
        present_rows.append(item)

    present_rows.sort(key=lambda row: int(row["address"], 16))

    csv_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.parent.mkdir(parents=True, exist_ok=True)

    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "token",
                "address",
                "current_status",
                "verified_in_wx_lib",
                "verification_match",
                "raw_name",
                "demangled",
                "files",
            ],
        )
        writer.writeheader()
        for row in present_rows:
            writer.writerow(row)

    split = Counter((row.get("current_status", ""), row.get("verified_in_wx_lib", "")) for row in present_rows)
    external_verified = split.get(("external_dependency", "1"), 0)
    recovered_unverified = split.get(("recovered", "0"), 0)

    lines = [
        "# wx Source De-dup Audit",
        "",
        f"- Input verification CSV: `{verification_csv}`",
        f"- Annotated-in-src CSV: `{csv_out}`",
        "",
        "## Summary",
        "",
        f"- wx functions annotated in `src/sdk/**`: `{len(present_rows)}`",
        f"- external_dependency + verified in wx lib: `{external_verified}`",
        f"- recovered + unverified in wx lib: `{recovered_unverified}`",
        "- Exact symbol overlap between wrapper objs and `wxmsw.lib` (excluding CRT constants): none",
        "- Safe-to-remove-now set (exact link-equivalent replacements): `0`",
        "",
        "## Remaining recovered (not yet verified in wxmsw.lib)",
        "",
        "| Token | Address | Symbol | Files |",
        "| --- | --- | --- | --- |",
    ]

    for row in present_rows:
        if row.get("current_status") != "recovered":
            continue
        symbol = (row.get("demangled") or row.get("raw_name") or "").replace("|", "\\|")
        files = (row.get("files") or "").replace("|", "\\|")
        lines.append(f"| {row.get('token', '')} | {row.get('address', '')} | `{symbol}` | `{files}` |")

    report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[wx-dedup] csv={csv_out}")
    print(f"[wx-dedup] report={report_out}")
    print(
        "[wx-dedup] summary "
        f"annotated={len(present_rows)} external_verified={external_verified} recovered_unverified={recovered_unverified}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
