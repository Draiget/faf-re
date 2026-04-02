# export_function_meta_batch_ida9.py
# IDA 9.x, Python 3
#
# Export metadata for many functions in one IDA session.
# Designed to amortize IDA startup/shutdown overhead across large batches.

import argparse
import datetime as dt
import json
import os
import re
import sys

import ida_auto
import ida_funcs
import ida_kernwin
import ida_nalt
import idaapi
import idc


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import export_function_code_ida9 as fx  # noqa: E402


def utc_now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_script_args():
    argv = []
    try:
        argv = list(idc.ARGV)
    except Exception:
        argv = []
    if not argv:
        return []
    return argv[1:]


def normalize_fun_token(token):
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


def load_function_tokens(path, max_count):
    tokens = []
    with open(path, "r", encoding="utf-8-sig") as handle:
        for line in handle:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            first = re.split(r"[,\s]+", text, maxsplit=1)[0]
            token = normalize_fun_token(first)
            if token:
                tokens.append(token)
                if max_count > 0 and len(tokens) >= max_count:
                    break
    return tokens


def resolve_target(selector, token):
    if selector == "ea":
        ea = fx.parse_ea_token(token)
        if ea is None:
            raise ValueError(f"Invalid token: {token}")
        fn = ida_funcs.get_func(ea)
        if not fn:
            raise ValueError(f"No function found at {token}")
        return fn.start_ea

    if selector == "name":
        args = argparse.Namespace(ea=None, name=token, contains=None)
        return fx.resolve_target_function(args)

    if selector == "contains":
        args = argparse.Namespace(ea=None, name=None, contains=token)
        return fx.resolve_target_function(args)

    raise ValueError(f"Unsupported selector: {selector}")


def build_meta_payload(target):
    fn = ida_funcs.get_func(target)
    if not fn:
        raise ValueError(f"Function not found at {fx.fmt_ea(target)}")

    callers = fx.collect_callers(target)
    callees = fx.collect_callees(target)
    xref_rows = fx.collect_incoming_xrefs(target)
    xref_code_count = sum(1 for row in xref_rows if row["kind"] == "code")
    xref_data_count = len(xref_rows) - xref_code_count
    data_refs = fx.collect_outgoing_data_refs(target)
    string_refs = fx.collect_string_refs(data_refs)
    fn_sha256, hashed_size, hashed_insn_count = fx.function_sha256(target)

    target_node = fx.edge_node_for_ea(target)
    target_name = target_node.get("name", "")
    target_demangled = target_node.get("demangled", "")
    target_meaningful = not fx.name_is_placeholder(target_name) or (
        target_demangled and not fx.name_is_placeholder(target_demangled)
    )

    return {
        "schema_version": 1,
        "generated_utc": utc_now_iso(),
        "input_file": ida_nalt.get_input_file_path(),
        "idb_file": idaapi.get_path(idaapi.PATH_TYPE_IDB),
        "target": {
            **target_node,
            "start_ea": int(fn.start_ea),
            "start_hex": fx.fmt_ea(fn.start_ea),
            "end_ea": int(fn.end_ea),
            "end_hex": fx.fmt_ea(fn.end_ea),
            "span_bytes": int(fn.end_ea - fn.start_ea),
            "has_meaningful_name": bool(target_meaningful),
        },
        "metrics": {
            "instructions": int(hashed_insn_count),
            "asm_rendered_instructions": int(hashed_insn_count),
            "function_code_bytes": int(hashed_size),
            "function_sha256": fn_sha256,
            "callers_count": len(callers),
            "callees_count": len(callees),
            "incoming_xrefs_count": len(xref_rows),
            "incoming_xrefs_code_count": xref_code_count,
            "incoming_xrefs_data_count": xref_data_count,
            "data_refs_count": len(data_refs),
            "string_refs_count": len(string_refs),
        },
        "callers": [fx.edge_node_for_ea(ea) for ea in callers],
        "callees": [fx.edge_node_for_ea(ea) for ea in callees],
        "incoming_xrefs": xref_rows,
        "data_refs": data_refs,
        "string_refs": string_refs,
    }


def write_text(path, lines):
    if not path:
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def main():
    ida_auto.auto_wait()

    parser = argparse.ArgumentParser(description="Export FUN_*.meta.json for a function list in one IDA session.")
    parser.add_argument("--list", required=True, help="Path to function token list (FUN_xxxxxxxx per line).")
    parser.add_argument("--out-dir", required=True, help="Output directory for FUN_*.meta.json files.")
    parser.add_argument("--selector", choices=["ea", "name", "contains"], default="ea", help="Token selector mode.")
    parser.add_argument("--max-count", type=int, default=0, help="Optional limit of tokens from list.")
    parser.add_argument("--overwrite-meta", action="store_true", help="Overwrite existing FUN_*.meta.json files.")
    parser.add_argument("--summary-out", help="Optional summary JSON output path.")
    parser.add_argument("--log-out", help="Optional append-only text log output path.")
    args = parser.parse_args(get_script_args())

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    list_path = os.path.abspath(args.list)
    tokens = load_function_tokens(list_path, max(args.max_count, 0))
    if not tokens:
        raise ValueError(f"No valid function tokens in list: {list_path}")

    requested_count = len(tokens)
    exported_count = 0
    skipped_existing_count = 0
    failed_count = 0
    failures = []
    log_lines = []

    for index, token in enumerate(tokens, start=1):
        try:
            target = resolve_target(args.selector, token)
            norm_token = fx.fun_token_from_ea(target) or normalize_fun_token(token) or token
            out_path = os.path.join(out_dir, f"{norm_token}.meta.json")
            if os.path.exists(out_path) and not args.overwrite_meta:
                skipped_existing_count += 1
                if (index % 250) == 0:
                    log_lines.append(f"[{utc_now_iso()}] SKIP {index}/{requested_count} {norm_token} (exists)")
                continue

            payload = build_meta_payload(target)
            fx.write_json_file(out_path, payload)
            exported_count += 1

            if (index % 100) == 0:
                log_lines.append(f"[{utc_now_iso()}] DONE {index}/{requested_count} {norm_token}")
                if args.log_out:
                    write_text(args.log_out, log_lines)
                    log_lines = []
        except Exception as exc:
            failed_count += 1
            failures.append({"token": token, "error": str(exc)})
            log_lines.append(f"[{utc_now_iso()}] FAIL {index}/{requested_count} {token} error={exc}")
            if args.log_out:
                write_text(args.log_out, log_lines)
                log_lines = []

    if log_lines and args.log_out:
        write_text(args.log_out, log_lines)

    summary = {
        "schema_version": 1,
        "generated_utc": utc_now_iso(),
        "input_file": ida_nalt.get_input_file_path(),
        "idb_file": idaapi.get_path(idaapi.PATH_TYPE_IDB),
        "list_path": list_path,
        "out_dir": out_dir,
        "selector": args.selector,
        "overwrite_meta": bool(args.overwrite_meta),
        "requested_count": requested_count,
        "exported_count": exported_count,
        "skipped_existing_count": skipped_existing_count,
        "failed_count": failed_count,
        "failures": failures,
    }

    if args.summary_out:
        fx.write_json_file(os.path.abspath(args.summary_out), summary)

    ida_kernwin.msg(
        "[meta-batch] "
        f"requested={requested_count} exported={exported_count} skipped={skipped_existing_count} failed={failed_count}\n"
    )

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    exit_code = 0
    try:
        exit_code = int(main())
    except SystemExit as exc:
        code = getattr(exc, "code", 0)
        try:
            exit_code = int(code) if code is not None else 0
        except Exception:
            exit_code = 1
    except Exception as exc:
        ida_kernwin.msg(f"[meta-batch] ERROR: {exc}\n")
        exit_code = 1
    finally:
        try:
            idc.qexit(exit_code)
        except Exception:
            raise

