# find_sp_release_inline.py  (IDA 9.x)
# Heuristic: within one small function, see >=2 interlocked-like dec/xadd, and >=2 virtual calls.

import idautils, idc

def looks_like_release(f):
    start, end = f, idc.get_func_attr(f, idc.FUNCATTR_END)
    if end - start > 256:
        return False
    interlocked = 0
    vtbl = 0
    for ea in idautils.FuncItems(f):
        m = idc.print_insn_mnem(ea)
        dis = idc.GetDisasm(ea).lower()
        # imported interlocked
        if m == "call":
            name = idc.get_name(idc.get_operand_value(ea,0), idc.GN_VISIBLE) or ""
            if "Interlocked" in name:
                interlocked += 1
            # virtual call: call dword ptr [reg+imm]
            if idc.get_operand_type(ea,0) == idc.o_displ:
                vtbl += 1
        # inlined: "lock dec"/"lock xadd" on memory
        if dis.startswith("lock ") and "dword ptr [" in dis and (" dec " in dis or "xadd" in dis):
            interlocked += 1
        # if two virtual calls go back-to-back, count a bonus
        if m == "call" and idc.get_operand_type(ea,0) == idc.o_displ:
            nxt = idc.next_head(ea, end)
            if nxt != idc.BADADDR and idc.print_insn_mnem(nxt) == "call" and idc.get_operand_type(nxt,0) == idc.o_displ:
                vtbl += 1
    return (interlocked >= 2 and vtbl >= 2)

for f in idautils.Functions():
    if looks_like_release(f):
        print("[sp_release-inline?] 0x%X  %s" % (f, idc.get_func_name(f)))
