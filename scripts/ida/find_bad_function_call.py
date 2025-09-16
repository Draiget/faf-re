# find_bad_function_call.py
# IDA 9.x compatible: find boost::bad_function_call ctor/throw sites by string/RTTI.

import idaapi, idautils, idc, ida_nalt

def ensure_auto_analysis():
    """Wait for autoanalysis to finish (safe if already done)."""
    try:
        idc.auto_wait()
    except Exception:
        pass

def find_string_refs(substr: str):
    """Scan the string list (ASCII + UTF-16) and return EAs of matching strings."""
    hits = set()
    sl = idautils.Strings()
    try:
        # IDA 9.x needs a list for strtypes; include ASCII and UTF-16 just in case.
        sl.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])
        sl.refresh()
    except Exception as e:
        print("[warn] Strings.setup failed, using defaults:", e)
    for s in sl:
        if substr in str(s):
            hits.add(int(s.ea))
    return sorted(hits)

def funcs_from_xrefs(eas):
    """Collect function starts referencing the given EAs."""
    out = set()
    for ea in eas:
        for xr in idautils.XrefsTo(ea, 0):
            f = idc.get_func_attr(xr.frm, idc.FUNCATTR_START)
            if f != idc.BADADDR:
                out.add(f)
    return sorted(out)

def main():
    ensure_auto_analysis()

    # 1) Try the exact message used by boost::function when invoked empty.
    eas = find_string_refs("call to empty boost::function")

    # 2) Fallback: RTTI/typeinfo string if message was stripped/localized.
    if not eas:
        print("[info] Literal not found, trying RTTI...")
        eas = find_string_refs("bad_function_call@boost")

    if not eas:
        print("[fail] No hits. String may be stripped/obfuscated. Try regex on RTTI or manual search.")
        return

    funcs = funcs_from_xrefs(eas)
    if not funcs:
        print("[info] No code xrefs to the string (data-only?)")
        return

    for f in funcs:
        print("0x%X  %s" % (f, idc.get_func_name(f)))

if __name__ == "__main__":
    main()
