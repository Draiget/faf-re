# list_xrefs_ida9.py
# IDA 9.1, Python 3
#
# Enumerate code+data xrefs to an address/function and write a text report.
#
# Headless example:
#   idat.exe -A -S"scripts/ida/list_xrefs_ida9.py --ea 0x0040A290 --out out.txt" <idb>

import argparse
import os
import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_xref
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


def parse_ea_token(token):
    if token is None:
        return None
    s = token.strip()
    if not s:
        return None

    s = re.sub(r"^FUN_", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^sub_", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^off_", "", s, flags=re.IGNORECASE)

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

    return None


def get_script_args():
    argv = []
    try:
        argv = list(idc.ARGV)
    except Exception:
        argv = []
    if not argv:
        return []
    return argv[1:]


def demangle(name):
    if not name:
        return ""
    return ida_name.demangle_name(name, DEMANGLER_FLAGS) or ""


def name_for_ea(ea):
    raw = ida_name.get_name(ea) or idc.get_name(ea, ida_name.GN_VISIBLE) or ""
    dm = demangle(raw)
    if dm:
        return f"{raw} [{dm}]"
    if raw:
        return raw
    return "<unnamed>"


def disasm_for_ea(ea):
    line = idc.generate_disasm_line(ea, 0) or ""
    return ida_lines.tag_remove(line)


def resolve_target(token):
    ea = parse_ea_token(token)
    if ea is not None:
        return ea

    by_name = ida_name.get_name_ea(idaapi.BADADDR, token)
    if by_name != idaapi.BADADDR:
        return by_name

    return None


def xref_kind(x):
    # True code xref when source item is code; this keeps behavior stable across IDA xref type enums.
    return "code" if idc.is_code(idc.get_full_flags(x.frm)) else "data"


def collect_xrefs(target_ea):
    rows = []
    for x in idautils.XrefsTo(target_ea, 0):
        src = x.frm
        owner = ida_funcs.get_func(src)
        owner_start = owner.start_ea if owner else idaapi.BADADDR
        rows.append(
            {
                "kind": xref_kind(x),
                "from": src,
                "to": x.to,
                "type": int(x.type),
                "owner": owner_start,
                "from_name": name_for_ea(src),
                "owner_name": name_for_ea(owner_start) if owner_start != idaapi.BADADDR else "<none>",
                "line": disasm_for_ea(src),
            }
        )
    rows.sort(key=lambda r: (r["kind"], r["from"]))
    return rows


def render_report(target_ea):
    rows = collect_xrefs(target_ea)
    code_count = sum(1 for r in rows if r["kind"] == "code")
    data_count = len(rows) - code_count

    out = []
    out.append(f"input_file: {ida_nalt.get_input_file_path()}")
    out.append(f"idb_file: {idaapi.get_path(idaapi.PATH_TYPE_IDB)}")
    out.append(f"target: {fmt_ea(target_ea)}")
    out.append(f"target_name: {name_for_ea(target_ea)}")
    out.append(f"xrefs_total: {len(rows)}")
    out.append(f"xrefs_code: {code_count}")
    out.append(f"xrefs_data: {data_count}")
    out.append("")

    out.append("[xrefs]")
    if not rows:
        out.append("<none>")
        return out

    for r in rows:
        out.append(
            f"{r['kind']:4} from={fmt_ea(r['from'])} owner={fmt_ea(r['owner']) if r['owner'] != idaapi.BADADDR else '<none>'} "
            f"type={r['type']:2d} from_name={r['from_name']} owner_name={r['owner_name']}"
        )
        out.append(f"      {r['line']}")

    return out


def write_report(path, lines):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ida_auto.auto_wait()

    parser = argparse.ArgumentParser(description="List code/data xrefs to an EA.")
    parser.add_argument("--ea", required=True, help="Address token (0x..., FUN_xxx, sub_xxx) or exact name.")
    parser.add_argument("--out", required=True, help="Output report path.")
    args = parser.parse_args(get_script_args())

    target = resolve_target(args.ea)
    if target is None:
        raise ValueError(f"Could not resolve target '{args.ea}'")

    report = render_report(target)
    write_report(args.out, report)
    ida_kernwin.msg(f"[list-xrefs] wrote {os.path.abspath(args.out)} for {fmt_ea(target)}\n")


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except Exception as exc:
        ida_kernwin.msg(f"[list-xrefs] ERROR: {exc}\n")
        exit_code = 1
    idc.qexit(exit_code)
