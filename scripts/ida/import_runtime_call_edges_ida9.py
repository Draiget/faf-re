#!/usr/bin/env python3
"""
Import runtime-discovered call edges into IDA as user code xrefs.

Supported inputs:
1) Progress JSON with "edges": [{"caller_ret":"0xXXXXXXXX","callee":"FUN_XXXXXXXX","count":N}, ...]
2) NDJSON event log lines with "caller_ret" + "callee"

Usage (inside IDA):
  1. Edit INPUT_PATH below, or set environment variable RUNTIME_EDGES_PATH.
  2. Run script via File -> Script file...
  3. Open call graph/xrefs for enriched runtime call relationships.
"""

import json
import os
import re
from collections import defaultdict
from pathlib import Path

import ida_funcs
import ida_kernwin
import ida_name
import ida_nalt
import ida_xref
import idc


# Optional fallback path if env var is not set.
INPUT_PATH = r"G:\projects\faf-main\tmp\_runtime_discovery_progress.json"


HEX_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{1,8})$")
FUN_RE = re.compile(r"^FUN_([0-9a-fA-F]{8})$")


def parse_hex_u32(text):
    if text is None:
        return None
    s = str(text).strip()
    m = HEX_RE.match(s)
    if not m:
        return None
    return int(m.group(1), 16) & 0xFFFFFFFF


def parse_callee(text):
    if text is None:
        return None
    s = str(text).strip()
    m = FUN_RE.match(s)
    if m:
        return int(m.group(1), 16) & 0xFFFFFFFF
    return parse_hex_u32(s)


def normalize_caller_func_start(caller_ret):
    f = ida_funcs.get_func(caller_ret)
    if f is None and caller_ret > 0:
        f = ida_funcs.get_func(caller_ret - 1)
    return f.start_ea if f is not None else None


def iter_edges_from_progress_json(path):
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    for edge in obj.get("edges", []):
        caller_ret = parse_hex_u32(edge.get("caller_ret"))
        callee = parse_callee(edge.get("callee"))
        count = int(edge.get("count", 1) or 1)
        if caller_ret is None or callee is None:
            continue
        yield caller_ret, callee, count


def iter_edges_from_ndjson(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "caller_ret" not in rec or "callee" not in rec:
                continue
            caller_ret = parse_hex_u32(rec.get("caller_ret"))
            callee = parse_callee(rec.get("callee"))
            if caller_ret is None or callee is None:
                continue
            yield caller_ret, callee, 1


def load_edge_counts(path):
    by_pair = defaultdict(int)
    lower = path.lower()
    if lower.endswith(".json"):
        edge_iter = iter_edges_from_progress_json(path)
    else:
        edge_iter = iter_edges_from_ndjson(path)

    for caller_ret, callee, count in edge_iter:
        caller_start = normalize_caller_func_start(caller_ret)
        if caller_start is None:
            continue
        by_pair[(caller_start, callee)] += int(count)
    return by_pair


def ensure_function_name(ea):
    name = ida_name.get_name(ea)
    if name:
        return name
    generated = f"FUN_{ea:08X}"
    ida_name.set_name(ea, generated, ida_name.SN_NOWARN)
    return generated


def main():
    path = os.getenv("RUNTIME_EDGES_PATH", "").strip() or INPUT_PATH
    if not path:
        ida_kernwin.msg("[runtime-edges] No input path configured.\n")
        return
    if not os.path.exists(path):
        ida_kernwin.msg(f"[runtime-edges] Input not found: {path}\n")
        return

    ida_kernwin.msg(f"[runtime-edges] Loading edges from: {path}\n")
    edges = load_edge_counts(path)
    total = len(edges)
    if total == 0:
        ida_kernwin.msg("[runtime-edges] No usable edges found.\n")
        return

    imported = 0
    skipped_missing_callee = 0
    updated_comments = 0
    caller_comment_lines = defaultdict(list)
    imported_pairs = []

    for idx, ((caller_start, callee), count) in enumerate(edges.items(), 1):
        # Progress in IDA output window with carriage return style.
        ida_kernwin.msg(f"\r[runtime-edges] processing {idx}/{total} ...")

        callee_func = ida_funcs.get_func(callee)
        if callee_func is None:
            skipped_missing_callee += 1
            continue
        callee_start = callee_func.start_ea

        # Synthetic user call xref: caller function entry -> callee function entry.
        ok = ida_xref.add_cref(caller_start, callee_start, ida_xref.fl_CN | ida_xref.XREF_USER)
        if not ok:
            # If add_cref returns False because it already exists, still treat as imported.
            pass
        imported += 1
        imported_pairs.append((caller_start, callee_start, count))

        caller_name = ensure_function_name(caller_start)
        callee_name = ensure_function_name(callee_start)
        caller_comment_lines[caller_start].append(f"{callee_name} (0x{callee_start:08X}) count={count}")

    ida_kernwin.msg("\n")

    # Attach compact repeatable comments on caller entries for quick browsing.
    for caller_start, lines in caller_comment_lines.items():
        lines = sorted(set(lines))
        header = f"[runtime-call-edges] observed callees={len(lines)}"
        body = "\n".join(lines[:50])
        if len(lines) > 50:
            body += f"\n... ({len(lines) - 50} more)"
        text = f"{header}\n{body}"
        idc.set_cmt(caller_start, text, 1)
        updated_comments += 1

    # Emit a global graph artifact so users can inspect a whole-program view.
    dot_path = Path(path).with_suffix(".runtime_callgraph.dot")
    try:
        with dot_path.open("w", encoding="utf-8") as f:
            f.write("digraph runtime_callgraph {\n")
            f.write("  rankdir=LR;\n")
            f.write("  node [shape=box, fontsize=10];\n")
            for caller_start, callee_start, count in imported_pairs:
                caller_name = ensure_function_name(caller_start)
                callee_name = ensure_function_name(callee_start)
                f.write(
                    f'  "{caller_name}\\n0x{caller_start:08X}" -> '
                    f'"{callee_name}\\n0x{callee_start:08X}" '
                    f'[label="{count}"];\n'
                )
            f.write("}\n")
    except Exception as ex:
        ida_kernwin.msg(f"[runtime-edges] warning: failed to write DOT: {ex}\n")
    else:
        ida_kernwin.msg(f"[runtime-edges] wrote DOT graph: {dot_path}\n")

    ida_kernwin.msg(
        "[runtime-edges] done: "
        f"pairs={total}, imported={imported}, skipped_missing_callee={skipped_missing_callee}, "
        f"caller_comments={updated_comments}\n"
    )


if __name__ == "__main__":
    main()
