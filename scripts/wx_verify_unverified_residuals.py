#!/usr/bin/env python3
"""
Resolve residual unverified wx rows from strict README-scope verification.

Input:
- decomp/recovery/reports/wxwidgets_readme_scope_verification.csv
  (from scripts/wx_verify_readme_scope_symbols.py)

Evidence:
- dumpbin /symbols on dependencies/wxWindows-2.4.2/lib/wxmsw.lib
  (defined external symbols only; UNDEF lines are ignored)

Output:
- CSV + Markdown with per-row residual status:
  - alias_match (present in wx with class/method remap)
  - not_present_in_wxmsw
- Queue JSON for alias-matched tokens (optional manual status mark)
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import json
import re
import subprocess
from pathlib import Path


FULL_SYMBOL_LINE_RE = re.compile(r"\|\s*(\S+)(?:\s*\((.*)\))?\s*$")
CLASS_METHOD_RE = re.compile(r"^(?P<class>[A-Za-z_][A-Za-z0-9_:]*)::(?P<method>~?[A-Za-z_][A-Za-z0-9_~]*)$")
ARGS_RE = re.compile(r"\s*\(.*\)\s*$")
ALIAS_SUFFIX_RE = re.compile(r"^(?P<prefix>.*::)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)_(?P<index>\d+)$")
TAIL_DIGITS_RE = re.compile(r"^(?P<name>.*?)(?P<digits>\d+)$")
NESTED_CTOR_RE = re.compile(r"^(?P<outer>[A-Za-z_][A-Za-z0-9_:]*)::(?P<class>[A-Za-z_][A-Za-z0-9_]*)::(?P<ctor>[A-Za-z_][A-Za-z0-9_]*)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve residual unverified wx verification rows.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument(
        "--strict-csv",
        default="decomp/recovery/reports/wxwidgets_readme_scope_verification.csv",
        help="Input strict verification CSV.",
    )
    parser.add_argument(
        "--wx-lib",
        default="dependencies/wxWindows-2.4.2/lib/wxmsw.lib",
        help="Path to wxmsw.lib.",
    )
    parser.add_argument(
        "--vcvars-bat",
        default=r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat",
        help="Path to vcvarsamd64_x86.bat.",
    )
    parser.add_argument(
        "--full-symbol-dump",
        default="decomp/recovery/reports/wxmsw_lib_full_symbols_for_residuals.txt",
        help="Path to dumpbin /symbols output for wxmsw.lib.",
    )
    parser.add_argument(
        "--refresh-full-symbol-dump",
        action="store_true",
        help="Regenerate full symbol dump from wxmsw.lib.",
    )
    parser.add_argument(
        "--csv-out",
        default="decomp/recovery/reports/wxwidgets_residual_verification.csv",
        help="Residual verification CSV output path.",
    )
    parser.add_argument(
        "--report-out",
        default="decomp/recovery/reports/wxwidgets_residual_verification.md",
        help="Residual verification markdown output path.",
    )
    parser.add_argument(
        "--queue-out",
        default="decomp/recovery/queues/wxwidgets_residual_alias_tokens.json",
        help="Queue JSON for alias-match tokens.",
    )
    return parser.parse_args()


def run_dumpbin_symbols(wx_lib: Path, vcvars_bat: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd_path = out_path.with_suffix(".cmd")
    cmd_path.write_text(
        "\r\n".join(
            [
                "@echo off",
                f"call \"{vcvars_bat}\" >nul",
                f"dumpbin /symbols \"{wx_lib}\" > \"{out_path}\"",
            ]
        )
        + "\r\n",
        encoding="ascii",
        errors="ignore",
    )
    try:
        subprocess.run(["cmd.exe", "/c", str(cmd_path)], check=True)
    finally:
        try:
            cmd_path.unlink()
        except OSError:
            pass


def undname_name_only(symbol: str) -> str:
    undec = ctypes.windll.dbghelp.UnDecorateSymbolName
    undec.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
    undec.restype = ctypes.c_uint

    UNDNAME_NAME_ONLY = 0x1000
    UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080
    UNDNAME_NO_MS_KEYWORDS = 0x0002
    UNDNAME_NO_FUNCTION_RETURNS = 0x0004
    flags = (
        UNDNAME_NAME_ONLY
        | UNDNAME_NO_ACCESS_SPECIFIERS
        | UNDNAME_NO_MS_KEYWORDS
        | UNDNAME_NO_FUNCTION_RETURNS
    )

    src = symbol.encode("utf-8", errors="ignore")
    buf = ctypes.create_string_buffer(4096)
    count = undec(src, buf, ctypes.c_uint(len(buf)), ctypes.c_uint(flags))
    if count:
        return buf.value.decode("utf-8", errors="ignore").strip()
    return ""


def parse_defined_name_only(full_symbol_dump: Path) -> tuple[set[str], set[tuple[str, str]]]:
    name_only: set[str] = set()
    class_method: set[tuple[str, str]] = set()

    for line in full_symbol_dump.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "External" not in line:
            continue
        if "UNDEF" in line:
            continue
        match = FULL_SYMBOL_LINE_RE.search(line)
        if not match:
            continue
        decorated = (match.group(1) or "").strip()
        if not decorated.startswith("?"):
            continue

        unmangled = undname_name_only(decorated)
        if not unmangled:
            continue
        name_only.add(unmangled)
        name_only.add(unmangled + "(void)")

        cm = CLASS_METHOD_RE.match(unmangled)
        if cm:
            class_method.add((cm.group("class"), cm.group("method")))

    return name_only, class_method


def normalize_fun_token(token: str | None) -> str | None:
    if not token:
        return None
    raw = token.strip()
    if not raw:
        return None
    raw = raw.split(",")[0].strip()
    raw = re.sub(r"^FUN_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^sub_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^0x", "", raw, flags=re.IGNORECASE)
    if re.fullmatch(r"[0-9A-Fa-f]{6,16}", raw):
        value = int(raw, 16)
    elif re.fullmatch(r"\d+", raw):
        value = int(raw, 10)
    else:
        return None
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def token_sort_key(token: str) -> tuple[int, str]:
    norm = normalize_fun_token(token) or token
    try:
        return (int(norm[4:], 16), norm)
    except Exception:
        return (2**63 - 1, norm)


def parse_class_method(symbol_text: str) -> tuple[str, str] | None:
    text = (symbol_text or "").strip()
    if not text:
        return None
    if text.startswith("j_"):
        text = text[2:]
    text = ARGS_RE.sub("", text)

    nested_ctor = NESTED_CTOR_RE.match(text)
    if nested_ctor:
        cls = nested_ctor.group("class")
        ctor = nested_ctor.group("ctor")
        if cls == ctor:
            return cls, ctor

    dtr = re.match(r"^(?P<class>[A-Za-z_][A-Za-z0-9_:]*)::dtr$", text)
    if dtr:
        cls = dtr.group("class")
        return cls, "~" + cls.split("::")[-1]

    match = re.match(r"^(?P<class>[A-Za-z_][A-Za-z0-9_:]*)::(?P<method>~?[A-Za-z_][A-Za-z0-9_~]*)$", text)
    if not match:
        return None
    return match.group("class"), match.group("method")


def class_variants(class_name: str) -> list[tuple[str, str]]:
    """
    Returns ordered variants as (candidate_class, reason_fragment).
    """
    variants: list[tuple[str, str]] = [(class_name, "class_exact")]
    seen = {class_name}

    # deterministic class aliases observed in wx2.4.2 symbol set
    alias_map = {
        "wxMenu": "wxMenuBase",
        "wxMenuBase": "wxMenu",
        "wxTopLevelWindow": "wxTopLevelWindowMSW",
        "wxTopLevelWindowMSW": "wxTopLevelWindow",
        "wxSlider": "wxSlider95",
        "wxSlider95": "wxSlider",
        "wxWindowMSW": "wxWindow",
        "wxWindow": "wxWindowMSW",
        "wxFrameBase": "wxFrame",
        "wxFrame": "wxFrameBase",
        "wxList": "wxListBase",
        "wxListBase": "wxList",
    }

    mapped = alias_map.get(class_name)
    if mapped and mapped not in seen:
        variants.append((mapped, "class_alias_map"))
        seen.add(mapped)

    suffixes = ["Base", "MSW", "95", "Generic"]
    for suffix in suffixes:
        if class_name.endswith(suffix):
            candidate = class_name[: -len(suffix)]
            if candidate and candidate not in seen:
                variants.append((candidate, f"class_suffix_strip_{suffix}"))
                seen.add(candidate)
        else:
            candidate = class_name + suffix
            if candidate not in seen:
                variants.append((candidate, f"class_suffix_add_{suffix}"))
                seen.add(candidate)

    if "_as_wxClientDataContainer" in class_name:
        candidate = class_name.replace("_as_wxClientDataContainer", "")
        if candidate and candidate not in seen:
            variants.append((candidate, "class_clientdata_strip"))
            seen.add(candidate)

    return variants


def method_variants(method_name: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = [(method_name, "method_exact")]
    seen = {method_name}

    tail_digits = TAIL_DIGITS_RE.match(method_name)
    if tail_digits:
        stripped = tail_digits.group("name")
        if stripped and stripped not in seen:
            variants.append((stripped, "method_tail_digits_strip"))
            seen.add(stripped)

    alias_suffix = ALIAS_SUFFIX_RE.match(method_name)
    if alias_suffix:
        stripped = alias_suffix.group("name")
        if stripped and stripped not in seen:
            variants.append((stripped, "method_alias_suffix_strip"))
            seen.add(stripped)

    if method_name == "operator+" and "operator+=" not in seen:
        variants.append(("operator+=", "method_operator_plus_to_plus_eq"))
        seen.add("operator+=")

    return variants


def choose_alias_match(
    symbol_text: str,
    class_method_set: set[tuple[str, str]],
) -> tuple[bool, str, str]:
    parsed = parse_class_method(symbol_text)
    if not parsed:
        return False, "", ""
    cls, method = parsed

    for cls_candidate, cls_reason in class_variants(cls):
        for method_candidate, method_reason in method_variants(method):
            if (cls_candidate, method_candidate) in class_method_set:
                reason = f"{cls_reason}+{method_reason}"
                mapped = f"{cls_candidate}::{method_candidate}"
                return True, reason, mapped
    return False, "", ""


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    strict_csv = (repo_root / args.strict_csv).resolve()
    wx_lib = (repo_root / args.wx_lib).resolve()
    vcvars_bat = Path(args.vcvars_bat).resolve()
    full_symbol_dump = (repo_root / args.full_symbol_dump).resolve()
    csv_out = (repo_root / args.csv_out).resolve()
    report_out = (repo_root / args.report_out).resolve()
    queue_out = (repo_root / args.queue_out).resolve()

    if args.refresh_full_symbol_dump:
        run_dumpbin_symbols(wx_lib=wx_lib, vcvars_bat=vcvars_bat, out_path=full_symbol_dump)

    if not full_symbol_dump.exists():
        run_dumpbin_symbols(wx_lib=wx_lib, vcvars_bat=vcvars_bat, out_path=full_symbol_dump)

    _, class_method_set = parse_defined_name_only(full_symbol_dump)

    strict_rows = list(csv.DictReader(strict_csv.open("r", encoding="utf-8", newline="")))
    residual_rows = [row for row in strict_rows if str(row.get("verified_in_wx_lib", "")).strip() != "1"]

    out_rows: list[dict[str, str]] = []
    alias_tokens: list[str] = []
    alias_count = 0
    missing_count = 0

    for row in residual_rows:
        token = row.get("token", "")
        symbol_text = (row.get("demangled") or row.get("raw_name") or "").strip()
        found, reason, mapped = choose_alias_match(symbol_text=symbol_text, class_method_set=class_method_set)
        if found:
            status = "alias_match"
            alias_count += 1
            if token:
                alias_tokens.append(token)
        else:
            status = "not_present_in_wxmsw"
            missing_count += 1
        out_rows.append(
            {
                "token": token,
                "address": row.get("address", ""),
                "raw_name": row.get("raw_name", ""),
                "demangled": row.get("demangled", ""),
                "current_status": row.get("current_status", ""),
                "residual_status": status,
                "alias_reason": reason,
                "alias_target": mapped,
            }
        )

    out_rows.sort(key=lambda row: token_sort_key(row.get("token", "")))
    alias_tokens = sorted({tok for tok in alias_tokens if tok}, key=token_sort_key)

    csv_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.parent.mkdir(parents=True, exist_ok=True)
    queue_out.parent.mkdir(parents=True, exist_ok=True)

    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "token",
                "address",
                "raw_name",
                "demangled",
                "current_status",
                "residual_status",
                "alias_reason",
                "alias_target",
            ],
        )
        writer.writeheader()
        for row in out_rows:
            writer.writerow(row)

    queue_payload = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "external_dependency",
        "note": "Residual alias matches from wx verification (manual review recommended).",
        "count": len(alias_tokens),
        "functions": alias_tokens,
    }
    queue_out.write_text(json.dumps(queue_payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# wx Residual Verification (Previously Unverified Rows)",
        "",
        "## Inputs",
        "",
        f"- Strict verification CSV: `{strict_csv}`",
        f"- wx full symbol dump: `{full_symbol_dump}`",
        f"- wx library: `{wx_lib}`",
        "",
        "## Summary",
        "",
        f"- Residual rows processed: `{len(residual_rows)}`",
        f"- alias_match: `{alias_count}`",
        f"- not_present_in_wxmsw: `{missing_count}`",
        f"- Alias queue: `{queue_out}` (`{len(alias_tokens)}` tokens)",
        f"- CSV: `{csv_out}`",
        "",
        "## Alias Match Samples",
        "",
        "| Token | Address | Symbol | Alias Target | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]

    sample_alias = [row for row in out_rows if row["residual_status"] == "alias_match"][:40]
    for row in sample_alias:
        symbol = (row.get("demangled") or row.get("raw_name") or "").replace("|", "\\|")
        alias_target = (row.get("alias_target") or "").replace("|", "\\|")
        alias_reason = (row.get("alias_reason") or "").replace("|", "\\|")
        lines.append(
            f"| {row['token']} | {row['address']} | `{symbol}` | `{alias_target}` | `{alias_reason}` |"
        )

    lines.extend(
        [
            "",
            "## Not Present Samples",
            "",
            "| Token | Address | Symbol | Current Status |",
            "| --- | --- | --- | --- |",
        ]
    )
    sample_missing = [row for row in out_rows if row["residual_status"] == "not_present_in_wxmsw"][:60]
    for row in sample_missing:
        symbol = (row.get("demangled") or row.get("raw_name") or "").replace("|", "\\|")
        status = row.get("current_status", "").replace("|", "\\|")
        lines.append(f"| {row['token']} | {row['address']} | `{symbol}` | `{status}` |")

    report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[wx-residual] csv={csv_out}")
    print(f"[wx-residual] report={report_out}")
    print(f"[wx-residual] queue={queue_out} count={len(alias_tokens)}")
    print(
        "[wx-residual] summary "
        f"processed={len(residual_rows)} alias_match={alias_count} not_present={missing_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
