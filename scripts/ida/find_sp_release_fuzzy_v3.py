# find_sp_release_fuzzy_v3.py
import idautils, idc

def looks_like_release(f):
    start, end = f, idc.get_func_attr(f, idc.FUNCATTR_END)
    if end-start > 256: 
        return False
    interlocked_like = 0
    vtbl_calls = 0
    for ea in idautils.FuncItems(f):
        m = idc.print_insn_mnem(ea)
        dis = idc.GetDisasm(ea).lower()
        if m == "call":
            name = idc.get_name(idc.get_operand_value(ea,0), idc.GN_VISIBLE) or ""
            if "Interlocked" in name:
                interlocked_like += 1
            if idc.get_operand_type(ea,0) == idc.o_displ:
                vtbl_calls += 1
        if dis.startswith("lock ") and "dword ptr [" in dis and ("dec" in dis or "xadd" in dis):
            interlocked_like += 1
        # бонус: подряд два виртуальных вызова:
        if m == "call" and idc.get_operand_type(ea,0) == idc.o_displ:
            nxt = idc.next_head(ea, end)
            if nxt != idc.BADADDR and idc.print_insn_mnem(nxt) == "call" and idc.get_operand_type(nxt,0) == idc.o_displ:
                vtbl_calls += 1
    return interlocked_like >= 2 and vtbl_calls >= 2

for f in idautils.Functions():
    if looks_like_release(f):
        print("[sp_release-like] 0x%X  %s" % (f, idc.get_func_name(f)))
