# export_function_code_ida9.py
# IDA 9.1, Python 3
#
# Export one function as:
#   - raw disassembly text
#   - Hex-Rays pseudocode text (if available)
#   - optional Markdown bundle with both
#
# Headless example:
#   ida.exe -A -S"scripts/ida/export_function_code_ida9.py --ea FUN_00579590 --asm-out out.asm --c-out out.c --md-out out.md" <idb-or-binary>

import argparse
import datetime as dt
import hashlib
import json
import os
import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import idaapi
import idautils
import idc


DEMANGLER_FLAGS = ida_name.MNG_NODEFINIT | ida_name.MNG_NORETTYPE | ida_name.MNG_NOECSU


def _get_inf():
    try:
        return idaapi.get_inf_structure()
    except Exception:
        return idaapi.cvar.inf


def addr_width():
    inf = _get_inf()
    try:
        return 16 if inf.is_64bit() else 8
    except Exception:
        return 8


def fmt_ea(ea):
    return f"0x{ea:0{addr_width()}X}"


def utc_now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def fun_token_from_ea(ea):
    if ea is None:
        return None
    try:
        value = int(ea)
    except Exception:
        return None
    if value < 0 or value == idaapi.BADADDR:
        return None
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"FUN_{value:0{width}X}"


def demangle(name):
    if not name:
        return ""
    return ida_name.demangle_name(name, DEMANGLER_FLAGS) or ""


def name_components(ea):
    raw = ida_name.get_name(ea) or idc.get_func_name(ea) or ""
    dm = demangle(raw)
    return raw, dm


def get_script_args():
    argv = []
    try:
        argv = list(idc.ARGV)
    except Exception:
        argv = []
    if not argv:
        return []
    return argv[1:]


def parse_ea_token(token):
    if token is None:
        return None
    s = token.strip()
    if not s:
        return None

    s = re.sub(r"^FUN_", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^sub_", "", s, flags=re.IGNORECASE)

    if s.lower().startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None

    if re.fullmatch(r"[0-9A-Fa-f]{6,16}", s):
        try:
            return int(s, 16)
        except ValueError:
            return None

    try:
        return int(s, 10)
    except ValueError:
        return None


def normalize_text(s):
    return (s or "").strip().lower()


def function_name_candidates(ea):
    raw = ida_name.get_name(ea) or idc.get_func_name(ea) or ""
    dm = demangle(raw)
    out = [raw]
    if dm:
        out.append(dm)
        if "::" in dm:
            out.append(dm.split("::")[-1])
    return [x for x in out if x]


def find_functions_exact_name(token):
    needle = normalize_text(token)
    hits = []
    for fea in idautils.Functions():
        for candidate in function_name_candidates(fea):
            if normalize_text(candidate) == needle:
                hits.append(fea)
                break
    return sorted(set(hits))


def find_functions_contains(token):
    needle = normalize_text(token)
    hits = []
    for fea in idautils.Functions():
        for candidate in function_name_candidates(fea):
            if needle in normalize_text(candidate):
                hits.append(fea)
                break
    return sorted(set(hits))


def resolve_target_function(args):
    selectors = [args.ea is not None, args.name is not None, args.contains is not None]
    if sum(1 for x in selectors if x) != 1:
        raise ValueError("Set exactly one selector: --ea, --name, or --contains.")

    if args.ea is not None:
        ea = parse_ea_token(args.ea)
        if ea is None:
            raise ValueError(f"Invalid --ea token: {args.ea}")
        fn = ida_funcs.get_func(ea)
        if not fn:
            raise ValueError(f"No function found at {fmt_ea(ea)}")
        return fn.start_ea

    if args.name is not None:
        maybe_ea = parse_ea_token(args.name)
        if maybe_ea is not None:
            fn = ida_funcs.get_func(maybe_ea)
            if fn:
                return fn.start_ea
        hits = find_functions_exact_name(args.name)
        if not hits:
            raise ValueError(f"No function matched --name '{args.name}'")
        if len(hits) > 1:
            preview = ", ".join(fmt_ea(x) for x in hits[:10])
            raise ValueError(
                f"Ambiguous --name '{args.name}', {len(hits)} matches. First: {preview}"
            )
        return hits[0]

    hits = find_functions_contains(args.contains)
    if not hits:
        raise ValueError(f"No function matched --contains '{args.contains}'")
    if len(hits) > 1:
        preview = ", ".join(fmt_ea(x) for x in hits[:10])
        raise ValueError(
            f"Ambiguous --contains '{args.contains}', {len(hits)} matches. First: {preview}"
        )
    return hits[0]


def code_line_for_ea(ea):
    size = max(idc.get_item_size(ea), 1)
    raw = ida_bytes.get_bytes(ea, size) or b""
    hex_bytes = " ".join(f"{b:02X}" for b in raw)
    dis = idc.generate_disasm_line(ea, 0) or ""
    dis = ida_lines.tag_remove(dis)
    return f"{fmt_ea(ea)}: {hex_bytes:<40} {dis}"


def collect_callers(func_start):
    callers = set()
    for xref_ea in idautils.CodeRefsTo(func_start, False):
        owner = ida_funcs.get_func(xref_ea)
        callers.add(owner.start_ea if owner else xref_ea)
    return sorted(callers)


def collect_callees(func_start):
    fn = ida_funcs.get_func(func_start)
    if not fn:
        return []
    callees = set()
    for item_ea in idautils.FuncItems(fn.start_ea):
        if not idc.is_code(idc.get_full_flags(item_ea)):
            continue
        for tgt in idautils.CodeRefsFrom(item_ea, False):
            target_fn = ida_funcs.get_func(tgt)
            if not target_fn:
                continue
            if target_fn.start_ea == fn.start_ea:
                continue
            callees.add(target_fn.start_ea)
    return sorted(callees)


def disasm_for_ea(ea):
    line = idc.generate_disasm_line(ea, 0) or ""
    return ida_lines.tag_remove(line)


def xref_kind(src_ea):
    # Treat source item code/data as stable xref kind across IDA xref type enums.
    return "code" if idc.is_code(idc.get_full_flags(src_ea)) else "data"


def collect_incoming_xrefs(target_ea):
    rows = []
    for x in idautils.XrefsTo(target_ea, 0):
        src = x.frm
        owner = ida_funcs.get_func(src)
        owner_start = owner.start_ea if owner else idaapi.BADADDR
        rows.append(
            {
                "kind": xref_kind(src),
                "from_ea": int(src),
                "from_hex": fmt_ea(src),
                "from_token": fun_token_from_ea(src),
                "to_ea": int(x.to),
                "to_hex": fmt_ea(x.to),
                "to_token": fun_token_from_ea(x.to),
                "type": int(x.type),
                "owner_ea": int(owner_start) if owner_start != idaapi.BADADDR else None,
                "owner_hex": fmt_ea(owner_start) if owner_start != idaapi.BADADDR else "<none>",
                "owner_token": fun_token_from_ea(owner_start) if owner_start != idaapi.BADADDR else None,
                "from_name": name_for_listing(src),
                "owner_name": name_for_listing(owner_start) if owner_start != idaapi.BADADDR else "<none>",
                "line": disasm_for_ea(src),
            }
        )

    rows.sort(key=lambda r: (r["kind"], r["from_ea"]))
    return rows


def render_xref_report(target_ea, rows):
    code_count = sum(1 for r in rows if r["kind"] == "code")
    data_count = len(rows) - code_count

    out = []
    out.append(f"input_file: {ida_nalt.get_input_file_path()}")
    out.append(f"idb_file: {idaapi.get_path(idaapi.PATH_TYPE_IDB)}")
    out.append(f"target: {fmt_ea(target_ea)}")
    out.append(f"target_name: {name_for_listing(target_ea)}")
    out.append(f"xrefs_total: {len(rows)}")
    out.append(f"xrefs_code: {code_count}")
    out.append(f"xrefs_data: {data_count}")
    out.append("")
    out.append("[xrefs]")

    if not rows:
        out.append("<none>")
        return out, code_count, data_count

    for r in rows:
        owner_text = r["owner_hex"]
        out.append(
            f"{r['kind']:4} from={r['from_hex']} owner={owner_text} "
            f"type={r['type']:2d} from_name={r['from_name']} owner_name={r['owner_name']}"
        )
        out.append(f"      {r['line']}")

    return out, code_count, data_count


def name_for_listing(ea):
    raw, dm = name_components(ea)
    if dm:
        return f"{raw} [{dm}]"
    if raw:
        return raw
    return "<unnamed>"


def name_is_placeholder(name):
    if not name:
        return True
    return bool(re.match(r"^(sub|FUN|loc|byte|word|dword|qword|off)_[0-9A-Fa-f]+$", name))


def edge_node_for_ea(ea):
    raw, dm = name_components(ea)
    return {
        "ea": int(ea),
        "ea_hex": fmt_ea(ea),
        "token": fun_token_from_ea(ea),
        "name": raw,
        "demangled": dm,
        "listing_name": name_for_listing(ea),
    }


def render_disassembly(func_start, max_insns):
    fn = ida_funcs.get_func(func_start)
    if not fn:
        raise ValueError(f"Function not found at {fmt_ea(func_start)}")

    lines = []
    insn_count = 0
    for item_ea in idautils.FuncItems(fn.start_ea):
        if not idc.is_code(idc.get_full_flags(item_ea)):
            continue
        lines.append(code_line_for_ea(item_ea))
        insn_count += 1
        if max_insns and insn_count >= max_insns:
            lines.append(f"... truncated at {max_insns} instructions ...")
            break

    return lines, insn_count


def render_pseudocode(func_start):
    try:
        import ida_hexrays
    except Exception:
        return None, "Hex-Rays module not available in this IDA build."

    if not ida_hexrays.init_hexrays_plugin():
        return None, "Hex-Rays plugin not available for this database."

    try:
        cfunc = ida_hexrays.decompile(func_start)
    except Exception as exc:
        return None, f"Decompilation failed: {exc}"

    if not cfunc:
        return None, "Decompilation returned no output."

    out = []
    for line in cfunc.get_pseudocode():
        out.append(ida_lines.tag_remove(line.line))
    return out, None


def write_text_file(path, lines):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def write_json_file(path, payload):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def function_sha256(func_start):
    fn = ida_funcs.get_func(func_start)
    if not fn:
        raise ValueError(f"Function not found at {fmt_ea(func_start)}")

    hasher = hashlib.sha256()
    hashed_size = 0
    insn_count = 0
    for item_ea in idautils.FuncItems(fn.start_ea):
        if not idc.is_code(idc.get_full_flags(item_ea)):
            continue
        size = max(idc.get_item_size(item_ea), 1)
        blob = ida_bytes.get_bytes(item_ea, size)
        if blob is None:
            blob = b"\x00" * size
        hasher.update(blob)
        hashed_size += len(blob)
        insn_count += 1

    return hasher.hexdigest(), hashed_size, insn_count


def collect_outgoing_data_refs(func_start):
    fn = ida_funcs.get_func(func_start)
    if not fn:
        return []

    rows = {}
    for item_ea in idautils.FuncItems(fn.start_ea):
        if not idc.is_code(idc.get_full_flags(item_ea)):
            continue
        for xref in idautils.XrefsFrom(item_ea, 0):
            target_ea = xref.to
            target_flags = idc.get_full_flags(target_ea)
            if idc.is_code(target_flags):
                continue
            key = (item_ea, target_ea, int(xref.type))
            if key in rows:
                continue
            rows[key] = {
                "from_ea": item_ea,
                "from_hex": fmt_ea(item_ea),
                "from_token": fun_token_from_ea(item_ea),
                "from_name": name_for_listing(item_ea),
                "to_ea": target_ea,
                "to_hex": fmt_ea(target_ea),
                "to_token": fun_token_from_ea(target_ea),
                "to_name": name_for_listing(target_ea),
                "to_segment": idc.get_segm_name(target_ea) or "",
                "ref_type": int(xref.type),
                "to_is_code": bool(idc.is_code(target_flags)),
                "to_is_data": bool(idc.is_data(target_flags)),
            }

    return sorted(rows.values(), key=lambda r: (r["from_ea"], r["to_ea"], r["ref_type"]))


def decode_string_preview(ea, max_chars=160):
    try:
        str_type = idc.get_str_type(ea)
    except Exception:
        return None
    if str_type is None or int(str_type) < 0:
        return None

    try:
        raw = idc.get_strlit_contents(ea, -1, str_type)
    except Exception:
        return None
    if raw is None:
        return None

    if isinstance(raw, bytes):
        text = None
        for encoding in ("utf-8", "cp1252", "latin-1"):
            try:
                text = raw.decode(encoding)
                break
            except Exception:
                continue
        if text is None:
            text = raw.decode("latin-1", errors="replace")
        byte_len = len(raw)
    else:
        text = str(raw)
        byte_len = len(text.encode("utf-8", errors="ignore"))

    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > max_chars:
        text = text[:max_chars] + "...(truncated)"

    return {
        "string_preview": text,
        "string_byte_len": byte_len,
        "str_type": int(str_type),
    }


def collect_string_refs(data_refs):
    out = []
    for row in data_refs:
        decoded = decode_string_preview(row["to_ea"])
        if not decoded:
            continue
        item = dict(row)
        item.update(decoded)
        out.append(item)
    return out


def main():
    ida_auto.auto_wait()

    parser = argparse.ArgumentParser(description="Export one function ASM and pseudocode from IDA.")
    parser.add_argument("--ea", help="Function address token (0x..., FUN_xxx, sub_xxx).")
    parser.add_argument("--name", help="Exact function name or demangled name.")
    parser.add_argument("--contains", help="Unique substring in raw or demangled function name.")
    parser.add_argument("--asm-out", help="Output path for assembly listing.")
    parser.add_argument("--c-out", help="Output path for pseudocode text.")
    parser.add_argument("--md-out", help="Output path for combined markdown bundle.")
    parser.add_argument("--xrefs-out", help="Optional output path for full incoming xref report.")
    parser.add_argument("--meta-out", help="Optional output path for structured JSON metadata.")
    parser.add_argument("--skip-pseudocode", action="store_true", help="Skip Hex-Rays pseudocode even if markdown output is requested.")
    parser.add_argument("--max-insns", type=int, default=0, help="Optional instruction cap for ASM export.")
    args = parser.parse_args(get_script_args())

    if not any([args.asm_out, args.c_out, args.md_out, args.xrefs_out, args.meta_out]):
        raise ValueError("No outputs requested. Provide at least one of --asm-out/--c-out/--md-out/--xrefs-out/--meta-out.")

    target = resolve_target_function(args)
    max_insns = max(args.max_insns, 0)
    asm_lines = []
    asm_insn_count = 0
    need_asm_listing = bool(args.asm_out or args.md_out)
    if need_asm_listing:
        asm_lines, asm_insn_count = render_disassembly(target, max_insns)
    fn = ida_funcs.get_func(target)
    if not fn:
        raise ValueError(f"Function not found at {fmt_ea(target)}")

    callers = collect_callers(target)
    callees = collect_callees(target)
    fn_sha256, hashed_size, hashed_insn_count = function_sha256(target)

    xref_rows = []
    xref_code_count = 0
    xref_data_count = 0
    if args.xrefs_out or args.md_out or args.meta_out:
        xref_rows = collect_incoming_xrefs(target)
        xref_code_count = sum(1 for r in xref_rows if r["kind"] == "code")
        xref_data_count = len(xref_rows) - xref_code_count

    data_refs = []
    string_refs = []
    if args.md_out or args.meta_out:
        data_refs = collect_outgoing_data_refs(target)
        string_refs = collect_string_refs(data_refs)

    if args.asm_out:
        header = [
            f"input_file: {ida_nalt.get_input_file_path()}",
            f"idb_file: {idaapi.get_path(idaapi.PATH_TYPE_IDB)}",
            f"function_start: {fmt_ea(fn.start_ea)}",
            f"function_end: {fmt_ea(fn.end_ea)}",
            f"function_name: {name_for_listing(fn.start_ea)}",
            f"function_sha256: {fn_sha256}",
            f"function_code_bytes: {hashed_size}",
            "",
            "[disassembly]",
        ]
        write_text_file(args.asm_out, header + asm_lines + [""])

    if args.xrefs_out:
        xref_lines, xref_code_count, xref_data_count = render_xref_report(target, xref_rows)
        write_text_file(args.xrefs_out, xref_lines)

    pseudo_lines = None
    pseudo_error = None
    should_render_pseudocode = (args.c_out or args.md_out) and not args.skip_pseudocode
    if should_render_pseudocode:
        pseudo_lines, pseudo_error = render_pseudocode(target)
    elif args.skip_pseudocode:
        pseudo_error = "Skipped by --skip-pseudocode."

    if args.c_out:
        if pseudo_lines is not None:
            write_text_file(args.c_out, pseudo_lines)
        else:
            write_text_file(args.c_out, [f"/* {pseudo_error or 'Pseudocode unavailable.'} */"])

    if args.meta_out:
        target_node = edge_node_for_ea(target)
        target_name = target_node.get("name", "")
        target_demangled = target_node.get("demangled", "")
        target_meaningful = not name_is_placeholder(target_name) or (
            target_demangled and not name_is_placeholder(target_demangled)
        )

        meta_payload = {
            "schema_version": 1,
            "generated_utc": utc_now_iso(),
            "input_file": ida_nalt.get_input_file_path(),
            "idb_file": idaapi.get_path(idaapi.PATH_TYPE_IDB),
            "target": {
                **target_node,
                "start_ea": int(fn.start_ea),
                "start_hex": fmt_ea(fn.start_ea),
                "end_ea": int(fn.end_ea),
                "end_hex": fmt_ea(fn.end_ea),
                "span_bytes": int(fn.end_ea - fn.start_ea),
                "has_meaningful_name": bool(target_meaningful),
            },
            "metrics": {
                "instructions": int(hashed_insn_count),
                "asm_rendered_instructions": int(asm_insn_count),
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
            "callers": [edge_node_for_ea(ea) for ea in callers],
            "callees": [edge_node_for_ea(ea) for ea in callees],
            "incoming_xrefs": xref_rows,
            "data_refs": data_refs,
            "string_refs": string_refs,
        }
        write_json_file(args.meta_out, meta_payload)

    if args.md_out:
        md = []
        md.append(f"# Function {name_for_listing(target)}")
        md.append("")
        md.append(f"- start: `{fmt_ea(fn.start_ea)}`")
        md.append(f"- end: `{fmt_ea(fn.end_ea)}`")
        md.append(f"- instructions: `{hashed_insn_count}`")
        md.append(f"- function_code_bytes: `{hashed_size}`")
        md.append(f"- function_sha256: `{fn_sha256}`")
        md.append(f"- callers: `{len(callers)}`")
        md.append(f"- callees: `{len(callees)}`")
        md.append(f"- incoming_xrefs: `{len(xref_rows)}`")
        md.append(f"- incoming_xrefs_code: `{xref_code_count}`")
        md.append(f"- incoming_xrefs_data: `{xref_data_count}`")
        md.append(f"- data_refs: `{len(data_refs)}`")
        md.append(f"- string_refs: `{len(string_refs)}`")
        if args.meta_out:
            md.append(f"- meta_report: `{args.meta_out}`")
        md.append("")
        md.append("## Decompiled (Hex-Rays)")
        md.append("")
        if pseudo_lines is not None:
            md.append("```c")
            md.extend(pseudo_lines)
            md.append("```")
        else:
            md.append(f"_Unavailable: {pseudo_error or 'Pseudocode unavailable.'}_")
        md.append("")
        md.append("## Raw ASM")
        md.append("")
        md.append("```asm")
        md.extend(asm_lines)
        md.append("```")
        md.append("")
        md.append("## Callers")
        md.append("")
        if callers:
            for ea in callers:
                md.append(f"- `{fmt_ea(ea)}` {name_for_listing(ea)}")
        else:
            md.append("- <none>")
        md.append("")
        md.append("## Callees")
        md.append("")
        if callees:
            for ea in callees:
                md.append(f"- `{fmt_ea(ea)}` {name_for_listing(ea)}")
        else:
            md.append("- <none>")
        md.append("")
        md.append("## Incoming Xrefs")
        md.append("")
        if args.xrefs_out:
            md.append(f"- report: `{args.xrefs_out}`")
        if xref_rows:
            preview_limit = 20
            md.append(f"- preview_count: `{min(len(xref_rows), preview_limit)}` / `{len(xref_rows)}`")
            md.append("")
            md.append("```text")
            for row in xref_rows[:preview_limit]:
                md.append(
                    f"{row['kind']:4} from={row['from_hex']} owner={row['owner_hex']} "
                    f"type={row['type']:2d} from_name={row['from_name']}"
                )
            md.append("```")
        else:
            md.append("- <none>")
        md.append("")
        md.append("## Data Refs")
        md.append("")
        if data_refs:
            preview_limit = 20
            md.append(f"- preview_count: `{min(len(data_refs), preview_limit)}` / `{len(data_refs)}`")
            for row in data_refs[:preview_limit]:
                md.append(
                    f"- from `{row['from_hex']}` -> `{row['to_hex']}` type=`{row['ref_type']}` seg=`{row['to_segment']}` {row['to_name']}"
                )
        else:
            md.append("- <none>")
        md.append("")
        md.append("## String Refs")
        md.append("")
        if string_refs:
            preview_limit = 20
            md.append(f"- preview_count: `{min(len(string_refs), preview_limit)}` / `{len(string_refs)}`")
            for row in string_refs[:preview_limit]:
                md.append(
                    f"- `{row['to_hex']}` len=`{row['string_byte_len']}` type=`{row['str_type']}` `{row['string_preview']}`"
                )
        else:
            md.append("- <none>")

        write_text_file(args.md_out, md)

    msg_parts = []
    if args.asm_out:
        msg_parts.append(f"asm={os.path.abspath(args.asm_out)}")
    if args.meta_out:
        msg_parts.append(f"meta={os.path.abspath(args.meta_out)}")
    if args.xrefs_out:
        msg_parts.append(f"xrefs_out={os.path.abspath(args.xrefs_out)}")
    msg_parts.append(f"pseudo={'yes' if pseudo_lines is not None else 'no'}")
    msg_parts.append(f"callers={len(callers)}")
    msg_parts.append(f"callees={len(callees)}")
    msg_parts.append(f"xrefs={len(xref_rows)}")
    msg_parts.append(f"data_refs={len(data_refs)}")
    msg_parts.append(f"string_refs={len(string_refs)}")
    ida_kernwin.msg("[export-code] " + " ".join(msg_parts) + "\n")


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as exc:
        code = getattr(exc, "code", 0)
        try:
            exit_code = int(code) if code is not None else 0
        except Exception:
            exit_code = 1
    except Exception as exc:
        ida_kernwin.msg(f"[export-code] ERROR: {exc}\n")
        exit_code = 1
    finally:
        try:
            idc.qexit(exit_code)
        except Exception:
            raise
