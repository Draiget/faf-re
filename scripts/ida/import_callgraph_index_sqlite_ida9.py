#!/usr/bin/env python3
"""
Import full static callgraph edges from _callgraph_index.sqlite into IDA.

This imports ALL edges from table `call_edges` as user call xrefs:
  caller_function_start -> callee_function_start

Why:
  Runtime discovery captures only executed paths (e.g. 108 edges).
  This script loads full binary callgraph evidence (typically 100k+ edges).

Usage (inside IDA):
  1) Set env var CALLGRAPH_DB_PATH, or edit DEFAULT_DB_PATH below.
  2) Optional: set CALLGRAPH_IMPORT_MAX_EDGES for a test pass.
  3) Run via File -> Script file...
"""

import os
import sqlite3
from pathlib import Path

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_xref


DEFAULT_DB_PATH = r"G:\projects\faf-main\decomp\recovery\disasm\fa_full_2026_03_26\_callgraph_index.sqlite"


def parse_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw, 10)
    except ValueError:
        return default
    return value if value >= 0 else default


def parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def get_func_start(ea: int):
    f = ida_funcs.get_func(ea)
    if f is None and ea > 0:
        f = ida_funcs.get_func(ea - 1)
    return f.start_ea if f is not None else None


def has_exact_func_start(ea: int) -> bool:
    f = ida_funcs.get_func(ea)
    return f is not None and f.start_ea == ea


def ensure_func_defined(start_ea: int, end_ea: int):
    """Returns (func_start_or_none, created_flag, failed_flag)."""
    if has_exact_func_start(start_ea):
        return start_ea, False, False

    add_end = ida_idaapi.BADADDR
    if end_ea and end_ea > start_ea and end_ea != ida_idaapi.BADADDR:
        add_end = end_ea

    ok = ida_funcs.add_func(start_ea, add_end)
    if not ok and has_exact_func_start(start_ea):
        return start_ea, False, False
    if not ok:
        return None, False, True
    if has_exact_func_start(start_ea):
        return start_ea, True, False
    return start_ea, True, False


def main():
    db_path = Path(os.getenv("CALLGRAPH_DB_PATH", "").strip() or DEFAULT_DB_PATH)
    max_edges = parse_int_env("CALLGRAPH_IMPORT_MAX_EDGES", 0)
    prepare_functions = parse_bool_env("CALLGRAPH_PREPARE_FUNCTIONS", True)
    dot_path_raw = os.getenv("CALLGRAPH_DOT_PATH", "").strip()
    dot_path = Path(dot_path_raw) if dot_path_raw else None

    if not db_path.exists():
        ida_kernwin.msg(f"[callgraph-sqlite] DB not found: {db_path}\n")
        return

    ida_kernwin.msg(f"[callgraph-sqlite] Loading DB: {db_path}\n")

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()

    func_rows = [
        (int(start_ea), int(end_ea))
        for start_ea, end_ea in cur.execute(
            "SELECT start_ea, end_ea FROM functions ORDER BY start_ea"
        )
    ]
    func_end_by_start = {start_ea: end_ea for start_ea, end_ea in func_rows}
    ida_kernwin.msg(f"[callgraph-sqlite] functions total={len(func_rows)}\n")

    pre_created = 0
    pre_existing = 0
    pre_failed = 0

    if prepare_functions:
        total_funcs = len(func_rows)
        ida_kernwin.msg(
            f"[callgraph-sqlite] preparing function starts in IDA: total={total_funcs}\n"
        )
        for idx, (start_ea, end_ea) in enumerate(func_rows, 1):
            if (idx % 5000) == 0 or idx == total_funcs:
                ida_kernwin.msg(f"\r[callgraph-sqlite] prepare {idx}/{total_funcs} ...")

            if has_exact_func_start(start_ea):
                pre_existing += 1
                continue

            _, created, failed = ensure_func_defined(start_ea, end_ea)
            if created:
                pre_created += 1
            elif failed:
                pre_failed += 1
            else:
                pre_existing += 1

        ida_kernwin.msg("\n")
        ida_kernwin.msg(
            "[callgraph-sqlite] function prepare done: "
            f"created={pre_created}, existing={pre_existing}, failed={pre_failed}\n"
        )

    total_edges = cur.execute("SELECT COUNT(*) FROM call_edges").fetchone()[0]
    limit = min(total_edges, max_edges) if max_edges > 0 else total_edges
    ida_kernwin.msg(
        f"[callgraph-sqlite] call_edges total={total_edges}, import_limit={limit}\n"
    )

    q = "SELECT src_ea, dst_ea, src_token, dst_token FROM call_edges ORDER BY src_ea, dst_ea"
    if max_edges > 0:
        q += f" LIMIT {max_edges}"

    imported = 0
    already = 0
    skipped_missing_src = 0
    skipped_missing_dst = 0
    created_src = 0
    created_dst = 0
    create_src_failed = 0
    create_dst_failed = 0

    dot_fp = None
    if dot_path is not None:
        try:
            dot_path.parent.mkdir(parents=True, exist_ok=True)
            dot_fp = dot_path.open("w", encoding="utf-8")
            dot_fp.write("digraph static_callgraph {\n")
            dot_fp.write("  rankdir=LR;\n")
            dot_fp.write("  node [shape=box, fontsize=10];\n")
        except Exception as ex:
            ida_kernwin.msg(f"[callgraph-sqlite] warning: DOT disabled ({ex})\n")
            dot_fp = None

    for idx, (src_ea, dst_ea, src_token, dst_token) in enumerate(cur.execute(q), 1):
        if (idx % 2000) == 0 or idx == limit:
            ida_kernwin.msg(f"\r[callgraph-sqlite] processing {idx}/{limit} ...")

        src_ea = int(src_ea)
        dst_ea = int(dst_ea)

        src_start = get_func_start(src_ea)
        if src_start is None and src_ea in func_end_by_start:
            src_start, created, failed = ensure_func_defined(
                src_ea, func_end_by_start[src_ea]
            )
            if created:
                created_src += 1
            elif failed:
                create_src_failed += 1

        if src_start is None:
            skipped_missing_src += 1
            continue

        dst_start = get_func_start(dst_ea)
        if dst_start is None and dst_ea in func_end_by_start:
            dst_start, created, failed = ensure_func_defined(
                dst_ea, func_end_by_start[dst_ea]
            )
            if created:
                created_dst += 1
            elif failed:
                create_dst_failed += 1

        if dst_start is None:
            skipped_missing_dst += 1
            continue

        ok = ida_xref.add_cref(src_start, dst_start, ida_xref.fl_CN | ida_xref.XREF_USER)
        if ok:
            imported += 1
        else:
            # Existing xref or rejected duplicate.
            already += 1

        if dot_fp is not None:
            dot_fp.write(f'  "0x{src_start:08X}" -> "0x{dst_start:08X}";\n')

    if dot_fp is not None:
        dot_fp.write("}\n")
        dot_fp.close()

    conn.close()
    ida_kernwin.msg("\n")
    ida_kernwin.msg(
        "[callgraph-sqlite] done: "
        f"processed={limit}, imported={imported}, already_present={already}, "
        f"skipped_missing_src={skipped_missing_src}, skipped_missing_dst={skipped_missing_dst}, "
        f"created_src={created_src}, created_dst={created_dst}, "
        f"create_src_failed={create_src_failed}, create_dst_failed={create_dst_failed}\n"
    )
    if dot_path is not None:
        ida_kernwin.msg(f"[callgraph-sqlite] wrote DOT graph: {dot_path}\n")


if __name__ == "__main__":
    main()
