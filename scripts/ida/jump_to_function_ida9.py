# jump_to_function_ida9.py
# IDA 9.1, Python 3
#
# Jump to one function in the current IDB and optionally open pseudocode view.
# Intended for GUI launches: ida.exe -S"scripts/ida/jump_to_function_ida9.py --ea FUN_00579590 --open-pseudocode" <idb-or-binary>

import argparse
import re

import ida_auto
import ida_funcs
import ida_kernwin
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


def open_pseudocode(ea):
    try:
        import ida_hexrays
    except Exception:
        ida_kernwin.msg("[jump-func] Hex-Rays module not available.\n")
        return

    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.msg("[jump-func] Hex-Rays plugin is unavailable for this database.\n")
        return

    try:
        ida_hexrays.open_pseudocode(ea, 0)
    except Exception as exc:
        ida_kernwin.msg(f"[jump-func] Failed to open pseudocode: {exc}\n")


def main():
    ida_auto.auto_wait()
    parser = argparse.ArgumentParser(description="Jump to one function in current IDB.")
    parser.add_argument("--ea", help="Function address token (0x..., FUN_xxx, sub_xxx).")
    parser.add_argument("--name", help="Exact function name or demangled name.")
    parser.add_argument("--contains", help="Unique substring in raw or demangled function name.")
    parser.add_argument(
        "--open-pseudocode",
        action="store_true",
        help="Open pseudocode view (Hex-Rays) after jumping.",
    )

    args = parser.parse_args(get_script_args())
    target = resolve_target_function(args)
    ida_kernwin.jumpto(target)
    ida_kernwin.msg(f"[jump-func] Jumped to {fmt_ea(target)}\n")
    if args.open_pseudocode:
        open_pseudocode(target)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        ida_kernwin.msg(f"[jump-func] ERROR: {exc}\n")
        raise
