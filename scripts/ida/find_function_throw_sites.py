# find_function_throw_sites.py  (IDA 9.x)
# Finds callers of boost::bad_function_call ctor that also throw right after.
import idautils, idc

def is_throw_call(ea):
    if idc.print_insn_mnem(ea) != "call":
        return False
    tgt = idc.get_operand_value(ea, 0)
    name = idc.get_name(tgt, idc.GN_VISIBLE) or ""
    # MSVC throw helper
    return "__CxxThrowException" in name

def main():
    ctor = idc.get_name_ea_simple("??0bad_function_call@boost@@Z")
    if ctor == idc.BADADDR:
        print("ctor not named; put cursor on 0x%X and press 'N' to name it ??0bad_function_call@boost@@Z" % (here(),))
        return
    funcs = set()
    for x in idautils.XrefsTo(ctor, 0):
        f = idc.get_func_attr(x.frm, idc.FUNCATTR_START)
        if f == idc.BADADDR:
            continue
        # проверим, есть ли throw рядом с вызовом ctor
        ea = x.frm
        window = list(idautils.FuncItems(f))
        try:
            i = window.index(ea)
        except ValueError:
            i = -1
        has_throw = any(is_throw_call(p) for p in window[i:i+20])
        funcs.add((f, has_throw))
    for f, has_throw in sorted(funcs):
        print("[function throw sites] 0x%X  %s  %s" % (f, idc.get_func_name(f), "[throw]" if has_throw else ""))

if __name__ == "__main__":
    main()

# 0x4135C0  sub_4135C0  
# 0x413E60  ??Rfunction_void@boost@@QAE@@Z  
# 0x461910  sub_461910  
# 0x4E8220  sub_4E8220  
# 0x7CE8B0  sub_7CE8B0  
# 0x937290  sub_937290  
# 0xAC3260  ??Rfunction0@boost@@QAE@@Z  
# 0xAC4410  ??Rfunction1_void@boost@@QAE@@Z  
# 0xAC4480  cleanup_slots 