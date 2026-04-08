#!/usr/bin/env python3
"""
Exhaustive closure verification for README-scope wx residuals.

Goal:
- Eliminate residual "unknowns" by classifying each strict-miss row as either:
  - linked_in_wx_lib (proven via defined External/Static symbol evidence), or
  - not_linked_in_wx_lib (no defined symbol match after exhaustive heuristics).

Evidence:
- decomp/recovery/reports/wxwidgets_residual_verification.csv
- decomp/recovery/reports/wxmsw_lib_full_symbols_for_residuals.txt
- decomp/recovery/reports/wxmsw_lib_disasm.txt
- decomp/recovery/disasm/fa_full_2026_03_26/FUN_*.asm
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import difflib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SYMBOL_LINE_RE = re.compile(r"\|\s*(\S+)(?:\s*\((.*)\))?\s*$")
WX_DISASM_HEADER_RE = re.compile(r"^(\S+)\s+\((.*)\):$")
WX_DISASM_INST_RE = re.compile(r"^\s*[0-9A-F]{8}:\s+(?:[0-9A-F]{2}\s+)+([a-z][a-z0-9]*)\b")
FA_DISASM_INST_RE = re.compile(r"^0x[0-9A-Fa-f]+:\s+(?:[0-9A-F]{2}\s+)+([a-z][a-z0-9]*)\b")
TRAILING_ARGS_RE = re.compile(r"\s*\(.*\)\s*$")
TRAILING_DIGITS_RE = re.compile(r"^(.*?)(\d+)$")
NESTED_CTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]*::([A-Za-z_][A-Za-z0-9_]*)::\1$")
OPERATOR_SPACING_RE = re.compile(r"operator\s+")


CLASS_ALIAS_MAP: dict[str, str] = {
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
    "wxDCTemp": "wxDC",
}

MANUAL_UNQUALIFIED_ALLOW = {
    "copystring",
    "GetTimeZone",
    "InitTm",
}

SOURCE_EVIDENCE_BY_SYMBOL = {
    "?FindWindowForMouseEvent@@YAPAVwxWindow@@PAV1@PAH1@Z": "dependencies/wxWindows-2.4.2/src/msw/window.cpp:4197",
    "?TranslateKbdEventToMouse@@YAXPAVwxWindow@@PAH1PAI@Z": "dependencies/wxWindows-2.4.2/src/msw/window.cpp:5447",
    "?GetTimeZone@@YAHXZ": "dependencies/wxWindows-2.4.2/src/common/datetime.cpp:263",
    "?CallStrftime@@YA?AVwxString@@PBDPBUtm@@@Z": "dependencies/wxWindows-2.4.2/src/common/datetime.cpp:340",
    "?InitTm@@YAXAAUtm@@@Z": "dependencies/wxWindows-2.4.2/src/common/datetime.cpp:375",
    "?SelectOldObjects@wxDC@@UAEXK@Z": "dependencies/wxWindows-2.4.2/src/msw/dc.cpp:244",
    "?copystring@@YAPADPBD@Z": "dependencies/wxWindows-2.4.2/src/common/utilscmn.cpp:106",
}


@dataclass(frozen=True)
class SymbolEntry:
    storage: str  # External|Static
    symbol: str   # decorated/raw
    demangled: str
    name_only: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exhaustive closure verification for wx residuals.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument(
        "--residual-csv",
        default="decomp/recovery/reports/wxwidgets_residual_verification.csv",
        help="Residual verification CSV input.",
    )
    parser.add_argument(
        "--strict-csv",
        default="decomp/recovery/reports/wxwidgets_readme_scope_verification.csv",
        help="Strict README-scope verification CSV input.",
    )
    parser.add_argument(
        "--full-symbol-dump",
        default="decomp/recovery/reports/wxmsw_lib_full_symbols_for_residuals.txt",
        help="dumpbin /symbols output for wxmsw.lib.",
    )
    parser.add_argument(
        "--wx-disasm",
        default="decomp/recovery/reports/wxmsw_lib_disasm.txt",
        help="dumpbin /disasm output for wxmsw.lib.",
    )
    parser.add_argument(
        "--fa-asm-dir",
        default="decomp/recovery/disasm/fa_full_2026_03_26",
        help="Directory containing FUN_*.asm exports for FA.",
    )
    parser.add_argument(
        "--csv-out",
        default="decomp/recovery/reports/wxwidgets_residual_exhaustive_verification.csv",
        help="Output CSV path.",
    )
    parser.add_argument(
        "--report-out",
        default="decomp/recovery/reports/wxwidgets_residual_exhaustive_verification.md",
        help="Output Markdown report path.",
    )
    parser.add_argument(
        "--queue-out",
        default="decomp/recovery/queues/wxwidgets_residual_exhaustive_new_linked.json",
        help="Queue JSON for newly proven linked residual tokens.",
    )
    parser.add_argument(
        "--not-linked-queue-out",
        default="decomp/recovery/queues/wxwidgets_residual_not_linked_tokens.json",
        help="Queue JSON containing residual tokens not linked in built wxmsw.lib.",
    )
    return parser.parse_args()


def undname_name_only(symbol: str) -> str:
    if not symbol.startswith("?"):
        return symbol.strip()

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
    return symbol.strip()


def normalize_name(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    if t.startswith("j_"):
        t = t[2:]
    t = TRAILING_ARGS_RE.sub("", t)
    t = t.replace("`", "")
    t = t.replace("::dtr", "::~")
    t = OPERATOR_SPACING_RE.sub("operator", t)
    t = t.replace(" ", "")

    nested = NESTED_CTOR_RE.match(t)
    if nested:
        cls = nested.group(1)
        t = f"{cls}::{cls}"

    return t


def class_variants(class_name: str) -> list[str]:
    variants: list[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        if v and v not in seen:
            variants.append(v)
            seen.add(v)

    add(class_name)

    mapped = CLASS_ALIAS_MAP.get(class_name)
    if mapped:
        add(mapped)

    for suffix in ("Base", "MSW", "95", "Generic"):
        if class_name.endswith(suffix):
            add(class_name[: -len(suffix)])
        else:
            add(class_name + suffix)

    return variants


def method_variants(method_name: str) -> list[str]:
    variants: list[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        if v and v not in seen:
            variants.append(v)
            seen.add(v)

    add(method_name)
    digits = TRAILING_DIGITS_RE.match(method_name)
    if digits:
        add(digits.group(1))
    return variants


def parse_defined_symbols(full_symbol_dump: Path) -> tuple[list[SymbolEntry], dict[str, list[SymbolEntry]]]:
    entries: list[SymbolEntry] = []

    for line in full_symbol_dump.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "UNDEF" in line:
            continue
        storage = "External" if "External" in line else ("Static" if "Static" in line else "")
        if not storage:
            continue

        match = SYMBOL_LINE_RE.search(line)
        if not match:
            continue

        symbol = (match.group(1) or "").strip()
        demangled = (match.group(2) or "").strip()
        if not symbol:
            continue

        name_only = normalize_name(undname_name_only(symbol))
        entry = SymbolEntry(storage=storage, symbol=symbol, demangled=demangled, name_only=name_only)
        entries.append(entry)

    by_name: dict[str, list[SymbolEntry]] = {}
    for entry in entries:
        by_name.setdefault(entry.name_only, []).append(entry)

    return entries, by_name


def parse_wx_disasm_mnemonics(wx_disasm_path: Path) -> tuple[dict[str, list[str]], dict[tuple[str, ...], list[str]]]:
    by_symbol: dict[str, list[str]] = {}

    current_symbol: str | None = None
    current_mnemonics: list[str] = []

    for line in wx_disasm_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        header = WX_DISASM_HEADER_RE.match(line)
        if header:
            if current_symbol and current_mnemonics:
                by_symbol[current_symbol] = current_mnemonics
            current_symbol = header.group(1)
            current_mnemonics = []
            continue

        if current_symbol is None:
            continue

        inst = WX_DISASM_INST_RE.match(line)
        if inst:
            current_mnemonics.append(inst.group(1).lower())
            continue

        if not line.strip():
            if current_symbol and current_mnemonics:
                by_symbol[current_symbol] = current_mnemonics
            current_symbol = None
            current_mnemonics = []

    if current_symbol and current_mnemonics:
        by_symbol[current_symbol] = current_mnemonics

    by_mnemonic_tuple: dict[tuple[str, ...], list[str]] = {}
    for sym, mnemonics in by_symbol.items():
        by_mnemonic_tuple.setdefault(tuple(mnemonics), []).append(sym)

    return by_symbol, by_mnemonic_tuple


def parse_fa_mnemonics(fa_asm_path: Path) -> list[str]:
    mnemonics: list[str] = []
    if not fa_asm_path.exists():
        return mnemonics
    for line in fa_asm_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = FA_DISASM_INST_RE.match(line)
        if match:
            mnemonics.append(match.group(1).lower())
    return mnemonics


def token_sort_key(token: str) -> tuple[int, str]:
    raw = token.strip()
    raw = raw.split(",")[0].strip()
    raw = re.sub(r"^FUN_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^sub_", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"^0x", "", raw, flags=re.IGNORECASE)
    try:
        return int(raw, 16), raw
    except Exception:
        return 2**63 - 1, raw


def choose_best(entries: Iterable[SymbolEntry]) -> SymbolEntry | None:
    ranked = sorted(
        entries,
        key=lambda e: (
            0 if e.storage == "External" else 1,
            0 if "wx" in (e.demangled or "").lower() else 1,
            len(e.demangled or ""),
            e.symbol,
        ),
    )
    return ranked[0] if ranked else None


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()

    residual_csv = (repo_root / args.residual_csv).resolve()
    strict_csv = (repo_root / args.strict_csv).resolve()
    full_symbol_dump = (repo_root / args.full_symbol_dump).resolve()
    wx_disasm_path = (repo_root / args.wx_disasm).resolve()
    fa_asm_dir = (repo_root / args.fa_asm_dir).resolve()
    csv_out = (repo_root / args.csv_out).resolve()
    report_out = (repo_root / args.report_out).resolve()
    queue_out = (repo_root / args.queue_out).resolve()
    not_linked_queue_out = (repo_root / args.not_linked_queue_out).resolve()

    residual_rows = list(csv.DictReader(residual_csv.open("r", encoding="utf-8", newline="")))
    strict_rows = list(csv.DictReader(strict_csv.open("r", encoding="utf-8", newline="")))

    strict_total = len(strict_rows)
    strict_verified = sum(1 for row in strict_rows if str(row.get("verified_in_wx_lib", "")).strip() == "1")
    strict_residual_total = strict_total - strict_verified

    _, symbols_by_name = parse_defined_symbols(full_symbol_dump)
    wx_disasm_by_symbol, wx_disasm_by_mnemonic = parse_wx_disasm_mnemonics(wx_disasm_path)

    out_rows: list[dict[str, str]] = []
    newly_linked_tokens: list[str] = []

    not_linked_long_exact_hits = 0
    not_linked_all_exact_hits = 0
    not_linked_exact_hit_length_counter: Counter[int] = Counter()

    for row in residual_rows:
        token = row.get("token", "").strip()
        address = row.get("address", "").strip()
        raw_name = (row.get("raw_name") or "").strip()
        demangled = (row.get("demangled") or "").strip()
        current_status = (row.get("current_status") or "").strip()
        prev_residual_status = (row.get("residual_status") or "").strip()

        fa_asm = fa_asm_dir / f"{token}.asm"
        fa_mnemonics = parse_fa_mnemonics(fa_asm)
        fa_instr_count = len(fa_mnemonics)
        fa_tuple = tuple(fa_mnemonics)

        matched_symbol = ""
        matched_name = ""
        matched_storage = ""
        matched_demangled = ""
        asm_ratio = ""
        wx_instr_count = ""
        source_evidence = ""

        closure_status = "not_linked_in_wx_lib"
        notes = ""

        if prev_residual_status == "alias_match":
            closure_status = "linked_in_wx_lib_alias"
            notes = "Previously proven via class/method alias match."
        else:
            target_name = normalize_name(demangled or raw_name)
            candidate_full_names: list[str] = []
            candidate_unqualified: list[str] = []

            if "::" in target_name:
                cls, method = target_name.rsplit("::", 1)
                for cls_variant in class_variants(cls):
                    for method_variant in method_variants(method):
                        candidate_full_names.append(f"{cls_variant}::{method_variant}")
                for method_variant in method_variants(method):
                    candidate_unqualified.append(method_variant)
            elif target_name:
                candidate_unqualified.extend(method_variants(target_name))

            full_hits: list[SymbolEntry] = []
            for name in candidate_full_names:
                full_hits.extend(symbols_by_name.get(name, []))
            if full_hits:
                best = choose_best(full_hits)
                if best:
                    matched_symbol = best.symbol
                    matched_name = best.name_only
                    matched_storage = best.storage
                    matched_demangled = best.demangled
                    closure_status = "linked_in_wx_lib_full_or_alias"
                    notes = "Defined symbol match after class alias/suffix normalization."
            else:
                unique_unqualified_hit: SymbolEntry | None = None
                unique_unqualified_name = ""
                for uq in candidate_unqualified:
                    hits = symbols_by_name.get(uq, [])
                    if len(hits) != 1:
                        continue
                    hit = hits[0]
                    wxish = ("wx" in (hit.demangled or "").lower()) or ("wx" in hit.symbol.lower())
                    if wxish or uq in MANUAL_UNQUALIFIED_ALLOW:
                        unique_unqualified_hit = hit
                        unique_unqualified_name = uq
                        break

                if unique_unqualified_hit:
                    matched_symbol = unique_unqualified_hit.symbol
                    matched_name = unique_unqualified_hit.name_only
                    matched_storage = unique_unqualified_hit.storage
                    matched_demangled = unique_unqualified_hit.demangled
                    closure_status = "linked_in_wx_lib_static_helper"
                    notes = f"Unique unqualified helper match: {unique_unqualified_name}."
                else:
                    closure_status = "not_linked_in_wx_lib"
                    notes = "No defined External/Static symbol match after exhaustive name/alias search."

        if matched_symbol:
            source_evidence = SOURCE_EVIDENCE_BY_SYMBOL.get(matched_symbol, "")
            wx_mnemonics = wx_disasm_by_symbol.get(matched_symbol, [])
            wx_instr_count = str(len(wx_mnemonics)) if wx_mnemonics else ""
            if fa_mnemonics and wx_mnemonics:
                ratio = difflib.SequenceMatcher(None, fa_mnemonics, wx_mnemonics, autojunk=False).ratio()
                asm_ratio = f"{ratio:.4f}"

        if closure_status.startswith("not_linked"):
            exact_hits = wx_disasm_by_mnemonic.get(fa_tuple, [])
            if exact_hits:
                not_linked_all_exact_hits += 1
                not_linked_exact_hit_length_counter[fa_instr_count] += 1
                if fa_instr_count >= 15:
                    not_linked_long_exact_hits += 1

        if prev_residual_status != "alias_match" and closure_status.startswith("linked_in_wx_lib"):
            newly_linked_tokens.append(token)

        out_rows.append(
            {
                "token": token,
                "address": address,
                "raw_name": raw_name,
                "demangled": demangled,
                "current_status": current_status,
                "previous_residual_status": prev_residual_status,
                "closure_status": closure_status,
                "matched_symbol": matched_symbol,
                "matched_name": matched_name,
                "matched_storage": matched_storage,
                "matched_demangled": matched_demangled,
                "fa_instruction_count": str(fa_instr_count),
                "wx_instruction_count": wx_instr_count,
                "asm_mnemonic_ratio": asm_ratio,
                "source_evidence": source_evidence,
                "notes": notes,
            }
        )

    out_rows.sort(key=lambda r: token_sort_key(r.get("token", "")))
    newly_linked_tokens = sorted({t for t in newly_linked_tokens if t}, key=token_sort_key)
    not_linked_tokens = sorted(
        {
            row.get("token", "")
            for row in out_rows
            if row.get("closure_status") == "not_linked_in_wx_lib" and row.get("token", "")
        },
        key=token_sort_key,
    )

    csv_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.parent.mkdir(parents=True, exist_ok=True)
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    not_linked_queue_out.parent.mkdir(parents=True, exist_ok=True)

    with csv_out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "token",
                "address",
                "raw_name",
                "demangled",
                "current_status",
                "previous_residual_status",
                "closure_status",
                "matched_symbol",
                "matched_name",
                "matched_storage",
                "matched_demangled",
                "fa_instruction_count",
                "wx_instruction_count",
                "asm_mnemonic_ratio",
                "source_evidence",
                "notes",
            ],
        )
        writer.writeheader()
        writer.writerows(out_rows)

    queue_payload = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "external_dependency",
        "note": "Newly proven linked residuals after exhaustive static/helper verification.",
        "count": len(newly_linked_tokens),
        "functions": newly_linked_tokens,
    }
    queue_out.write_text(json.dumps(queue_payload, indent=2) + "\n", encoding="utf-8")

    not_linked_queue_payload = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "needs_evidence",
        "note": "Residual tokens not linked in built wxmsw.lib (for optional de-externalization/recovery planning).",
        "count": len(not_linked_tokens),
        "functions": not_linked_tokens,
    }
    not_linked_queue_out.write_text(json.dumps(not_linked_queue_payload, indent=2) + "\n", encoding="utf-8")

    closure_counter = Counter(row["closure_status"] for row in out_rows)
    linked_residual_count = sum(
        count for status, count in closure_counter.items() if status.startswith("linked_in_wx_lib")
    )
    not_linked_count = closure_counter.get("not_linked_in_wx_lib", 0)
    alias_existing = closure_counter.get("linked_in_wx_lib_alias", 0)
    linked_new = linked_residual_count - alias_existing

    effective_linked_total = strict_verified + linked_residual_count
    effective_not_linked_total = strict_total - effective_linked_total
    effective_linked_pct = (100.0 * effective_linked_total / strict_total) if strict_total else 0.0
    effective_not_linked_pct = (100.0 * effective_not_linked_total / strict_total) if strict_total else 0.0

    status_split = Counter(row["current_status"] for row in out_rows)

    lines: list[str] = [
        "# wx Residual Exhaustive Closure Verification",
        "",
        "## Inputs",
        "",
        f"- Residual CSV: `{residual_csv}`",
        f"- Strict CSV: `{strict_csv}`",
        f"- Full symbol dump: `{full_symbol_dump}`",
        f"- wx disassembly: `{wx_disasm_path}`",
        f"- FA asm dir: `{fa_asm_dir}`",
        "",
        "## Summary",
        "",
        f"- README-scope total: `{strict_total}`",
        f"- Strict direct symbol verified: `{strict_verified}`",
        f"- Strict residual rows processed: `{strict_residual_total}`",
        f"- Residual linked via existing alias proof: `{alias_existing}`",
        f"- Residual newly linked via exhaustive symbol/helper matching: `{linked_new}`",
        f"- Residual linked total: `{linked_residual_count}`",
        f"- Residual not linked in built wx lib: `{not_linked_count}`",
        f"- Effective linked in built wx lib (`strict + residual linked`): `{effective_linked_total}/{strict_total} ({effective_linked_pct:.2f}%)`",
        f"- Effective not linked in built wx lib: `{effective_not_linked_total}/{strict_total} ({effective_not_linked_pct:.2f}%)`",
        "",
        "## Current Status Split (Residual Rows)",
        "",
    ]
    for status, count in sorted(status_split.items(), key=lambda item: (-item[1], item[0])):
        label = status or "<empty>"
        lines.append(f"- {label}: `{count}`")

    lines.extend(
        [
            "",
            "## Newly Linked Residuals",
            "",
            "| Token | Address | Symbol | Matched wx Symbol | Storage | ASM Mnemonic Ratio | Source Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for row in out_rows:
        if row["previous_residual_status"] == "alias_match":
            continue
        if not row["closure_status"].startswith("linked_in_wx_lib"):
            continue
        symbol_text = (row["demangled"] or row["raw_name"]).replace("|", "\\|")
        matched_symbol = row["matched_symbol"].replace("|", "\\|")
        source_ev = row["source_evidence"].replace("|", "\\|")
        ratio = row["asm_mnemonic_ratio"] or "-"
        lines.append(
            f"| {row['token']} | {row['address']} | `{symbol_text}` | `{matched_symbol}` | `{row['matched_storage']}` | `{ratio}` | `{source_ev or '-'}` |"
        )

    lines.extend(
        [
            "",
            "## Not Linked Evidence",
            "",
            f"- Not-linked residual rows: `{not_linked_count}`",
            f"- Exact mnemonic collisions across not-linked rows (all lengths): `{not_linked_all_exact_hits}`",
            f"- Exact mnemonic collisions for not-linked rows with >=15 instructions: `{not_linked_long_exact_hits}`",
        ]
    )

    if not_linked_exact_hit_length_counter:
        lines.append("- Exact mnemonic collision length distribution:")
        for length, count in sorted(not_linked_exact_hit_length_counter.items()):
            lines.append(f"- len={length}: {count}")

    lines.extend(
        [
            "",
            "## Not Linked Tokens",
            "",
            "| Token | Address | Symbol | Current Status | FA Instr | Note |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in out_rows:
        if row["closure_status"] != "not_linked_in_wx_lib":
            continue
        symbol_text = (row["demangled"] or row["raw_name"]).replace("|", "\\|")
        note = (row["notes"] or "").replace("|", "\\|")
        lines.append(
            f"| {row['token']} | {row['address']} | `{symbol_text}` | `{row['current_status']}` | `{row['fa_instruction_count']}` | `{note}` |"
        )

    lines.extend(
        [
            "",
            "## Outputs",
            "",
            f"- CSV: `{csv_out}`",
            f"- Queue: `{queue_out}` (`{len(newly_linked_tokens)}` newly linked tokens)",
            f"- Not-linked queue: `{not_linked_queue_out}` (`{len(not_linked_tokens)}` tokens)",
        ]
    )

    report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[wx-exhaustive] csv={csv_out}")
    print(f"[wx-exhaustive] report={report_out}")
    print(f"[wx-exhaustive] queue={queue_out} count={len(newly_linked_tokens)}")
    print(f"[wx-exhaustive] not_linked_queue={not_linked_queue_out} count={len(not_linked_tokens)}")
    print(
        "[wx-exhaustive] summary "
        f"strict_verified={strict_verified} residual_total={strict_residual_total} "
        f"residual_linked={linked_residual_count} residual_not_linked={not_linked_count} "
        f"effective_linked={effective_linked_total}/{strict_total}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
