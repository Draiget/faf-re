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


def demangle(name):
    if not name:
        return ""
    return ida_name.demangle_name(name, DEMANGLER_FLAGS) or ""


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


def name_for_listing(ea):
    raw = ida_name.get_name(ea) or idc.get_func_name(ea) or ""
    dm = demangle(raw)
    if dm:
        return f"{raw} [{dm}]"
    if raw:
        return raw
    return "<unnamed>"


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


def main():
    ida_auto.auto_wait()

    parser = argparse.ArgumentParser(description="Export one function ASM and pseudocode from IDA.")
    parser.add_argument("--ea", help="Function address token (0x..., FUN_xxx, sub_xxx).")
    parser.add_argument("--name", help="Exact function name or demangled name.")
    parser.add_argument("--contains", help="Unique substring in raw or demangled function name.")
    parser.add_argument("--asm-out", required=True, help="Output path for assembly listing.")
    parser.add_argument("--c-out", help="Output path for pseudocode text.")
    parser.add_argument("--md-out", help="Output path for combined markdown bundle.")
    parser.add_argument("--max-insns", type=int, default=0, help="Optional instruction cap for ASM export.")
    args = parser.parse_args(get_script_args())

    target = resolve_target_function(args)
    max_insns = max(args.max_insns, 0)
    asm_lines, insn_count = render_disassembly(target, max_insns)
    callers = collect_callers(target)
    callees = collect_callees(target)
    fn = ida_funcs.get_func(target)

    header = [
        f"input_file: {ida_nalt.get_input_file_path()}",
        f"idb_file: {idaapi.get_path(idaapi.PATH_TYPE_IDB)}",
        f"function_start: {fmt_ea(fn.start_ea)}",
        f"function_end: {fmt_ea(fn.end_ea)}",
        f"function_name: {name_for_listing(fn.start_ea)}",
        "",
        "[disassembly]",
    ]
    write_text_file(args.asm_out, header + asm_lines + [""])

    pseudo_lines = None
    pseudo_error = None
    if args.c_out or args.md_out:
        pseudo_lines, pseudo_error = render_pseudocode(target)
        if args.c_out:
            if pseudo_lines is not None:
                write_text_file(args.c_out, pseudo_lines)
            else:
                write_text_file(args.c_out, [f"/* {pseudo_error} */"])

    if args.md_out:
        md = []
        md.append(f"# Function {name_for_listing(target)}")
        md.append("")
        md.append(f"- start: `{fmt_ea(fn.start_ea)}`")
        md.append(f"- end: `{fmt_ea(fn.end_ea)}`")
        md.append(f"- instructions: `{insn_count}`")
        md.append(f"- callers: `{len(callers)}`")
        md.append(f"- callees: `{len(callees)}`")
        md.append("")
        md.append("## Decompiled (Hex-Rays)")
        md.append("")
        if pseudo_lines is not None:
            md.append("```c")
            md.extend(pseudo_lines)
            md.append("```")
        else:
            md.append(f"_Unavailable: {pseudo_error}_")
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

        write_text_file(args.md_out, md)

    ida_kernwin.msg(
        f"[export-code] asm={os.path.abspath(args.asm_out)}"
        f" pseudo={'yes' if pseudo_lines is not None else 'no'}"
        f" callers={len(callers)} callees={len(callees)}\n"
    )


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
