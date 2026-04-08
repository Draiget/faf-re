#!/usr/bin/env python3
"""
Audit exact compiled symbol overlap between local wx runtime objects and wxmsw.lib.

Goal:
- Prove whether local wx runtime sources define symbols that can be replaced
  directly by wxmsw.lib at link time (exact decorated-name overlap).
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


LIB_SYMBOL_RE = re.compile(r"^\s*[0-9A-Fa-f]+\s+(\S+)$")
OBJ_SYMBOL_RE = re.compile(r"\|\s*(\S+)\s*$")
IGNORED_OVERLAP_PREFIXES = ("__real@", "__xmm@")
IGNORED_OVERLAP_EXACT = {"___local_stdio_scanf_options"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit wx runtime symbol overlap with wxmsw.lib.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument(
        "--wx-lib",
        default="dependencies/wxWindows-2.4.2/lib/wxmsw.lib",
        help="Path to wxmsw static library.",
    )
    parser.add_argument(
        "--runtime-obj",
        action="append",
        default=[
            "buildstage/sdk/Win32/Debug/WxRuntimeTypes.obj",
            "buildstage/sdk/Win32/Debug/WxAppRuntime.obj",
        ],
        help="Runtime object path(s). Repeatable.",
    )
    parser.add_argument(
        "--vcvars-bat",
        default=r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat",
        help="Path to vcvarsamd64_x86.bat for dumpbin environment.",
    )
    parser.add_argument(
        "--report-out",
        default="decomp/recovery/reports/wx_runtime_symbol_overlap_audit.md",
        help="Output markdown report path.",
    )
    parser.add_argument(
        "--dump-dir",
        default="decomp/recovery/reports",
        help="Directory for intermediate symbol dumps.",
    )
    return parser.parse_args()


def run_dumpbin_linkermember2(wx_lib: Path, vcvars_bat: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    script = out_path.with_suffix(".wxlib.cmd")
    script.write_text(
        "\r\n".join(
            [
                "@echo off",
                f"call \"{vcvars_bat}\" >nul",
                f"dumpbin /linkermember:2 \"{wx_lib}\" > \"{out_path}\"",
            ]
        )
        + "\r\n",
        encoding="ascii",
        errors="ignore",
    )
    try:
        subprocess.run(["cmd.exe", "/c", str(script)], check=True)
    finally:
        try:
            script.unlink()
        except OSError:
            pass


def run_dumpbin_symbols(obj_path: Path, vcvars_bat: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    script = out_path.with_suffix(".obj.cmd")
    script.write_text(
        "\r\n".join(
            [
                "@echo off",
                f"call \"{vcvars_bat}\" >nul",
                f"dumpbin /symbols \"{obj_path}\" > \"{out_path}\"",
            ]
        )
        + "\r\n",
        encoding="ascii",
        errors="ignore",
    )
    try:
        subprocess.run(["cmd.exe", "/c", str(script)], check=True)
    finally:
        try:
            script.unlink()
        except OSError:
            pass


def parse_lib_symbols(path: Path) -> set[str]:
    symbols: set[str] = set()
    in_public = False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "public symbols" in line:
            in_public = True
            continue
        if in_public and line.startswith("Archive member name at"):
            break
        if not in_public:
            continue
        match = LIB_SYMBOL_RE.match(line)
        if match:
            symbols.add(match.group(1).strip())
    return symbols


def parse_obj_defined_external_symbols(path: Path) -> set[str]:
    symbols: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "External" not in line:
            continue
        if "UNDEF" in line:
            continue
        match = OBJ_SYMBOL_RE.search(line)
        if not match:
            continue
        symbol = match.group(1).strip()
        if not symbol:
            continue
        symbols.add(symbol)
    return symbols


def is_ignored_overlap(symbol: str) -> bool:
    if symbol in IGNORED_OVERLAP_EXACT:
        return True
    return any(symbol.startswith(prefix) for prefix in IGNORED_OVERLAP_PREFIXES)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    wx_lib = (repo_root / args.wx_lib).resolve()
    vcvars_bat = Path(args.vcvars_bat).resolve()
    report_out = (repo_root / args.report_out).resolve()
    dump_dir = (repo_root / args.dump_dir).resolve()
    runtime_objs = [(repo_root / p).resolve() for p in args.runtime_obj]

    wx_dump = dump_dir / "wxmsw_lib_symbols_for_overlap.txt"
    run_dumpbin_linkermember2(wx_lib=wx_lib, vcvars_bat=vcvars_bat, out_path=wx_dump)
    wx_symbols = parse_lib_symbols(wx_dump)

    per_obj_rows: list[dict[str, object]] = []
    all_defined: set[str] = set()
    all_overlap_raw: set[str] = set()

    for obj_path in runtime_objs:
        if not obj_path.exists():
            per_obj_rows.append(
                {
                    "obj": str(obj_path),
                    "exists": False,
                    "defined_count": 0,
                    "overlap_raw_count": 0,
                    "overlap_effective_count": 0,
                    "overlap_effective": [],
                }
            )
            continue

        out_name = obj_path.name + ".symbols.txt"
        obj_dump = dump_dir / out_name
        run_dumpbin_symbols(obj_path=obj_path, vcvars_bat=vcvars_bat, out_path=obj_dump)
        defined = parse_obj_defined_external_symbols(obj_dump)
        overlap_raw = defined & wx_symbols
        overlap_effective = sorted(sym for sym in overlap_raw if not is_ignored_overlap(sym))

        all_defined.update(defined)
        all_overlap_raw.update(overlap_raw)

        per_obj_rows.append(
            {
                "obj": str(obj_path),
                "exists": True,
                "defined_count": len(defined),
                "overlap_raw_count": len(overlap_raw),
                "overlap_effective_count": len(overlap_effective),
                "overlap_effective": overlap_effective,
            }
        )

    all_overlap_effective = sorted(sym for sym in all_overlap_raw if not is_ignored_overlap(sym))

    report_out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "# wx Runtime Symbol Overlap Audit",
        "",
        "## Inputs",
        "",
        f"- wx library: `{wx_lib}`",
        f"- vcvars: `{vcvars_bat}`",
        f"- wx symbol dump: `{wx_dump}`",
        "",
        "## Runtime Objects",
        "",
    ]
    for row in per_obj_rows:
        lines.append(f"- `{row['obj']}` (exists: `{row['exists']}`)")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- wx public symbols: `{len(wx_symbols)}`",
            f"- runtime defined external symbols (union): `{len(all_defined)}`",
            f"- raw overlap count: `{len(all_overlap_raw)}`",
            f"- effective overlap count (excluding CRT consts): `{len(all_overlap_effective)}`",
            f"- safe-to-remove-now by exact symbol replacement: `{len(all_overlap_effective)}`",
            "",
            "## Per Object",
            "",
            "| Object | Defined External | Raw Overlap | Effective Overlap |",
            "| --- | --- | --- | --- |",
        ]
    )

    for row in per_obj_rows:
        lines.append(
            f"| `{row['obj']}` | `{row['defined_count']}` | `{row['overlap_raw_count']}` | `{row['overlap_effective_count']}` |"
        )

    lines.extend(
        [
            "",
            "## Effective Overlap Symbols",
            "",
        ]
    )
    if all_overlap_effective:
        lines.append("| Symbol |")
        lines.append("| --- |")
        for symbol in all_overlap_effective:
            lines.append(f"| `{symbol}` |")
    else:
        lines.append("- (none)")

    report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[wx-overlap] report={report_out}")
    print(
        "[wx-overlap] summary "
        f"runtime_defined={len(all_defined)} overlap_raw={len(all_overlap_raw)} overlap_effective={len(all_overlap_effective)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
