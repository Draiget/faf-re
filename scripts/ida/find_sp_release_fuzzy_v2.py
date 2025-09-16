# find_sp_release_fuzzy_v2.py
# Heuristically finds blocks with 2x interlocked dec and 2x virtual calls (dispose/destroy).
import idautils, idc

def func_has_release_shape(f):
    start, end = f, idc.get_func_attr(f, idc.FUNCATTR_END)
    if end - start > 256:
        return False
    interlocked_like = 0
    vtbl_calls = 0
    for ea in idautils.FuncItems(f):
        m = idc.print_insn_mnem(ea)
        dis = idc.GetDisasm(ea).lower()

        # imported interlocked call (any naming)
        if m == "call":
            name = idc.get_name(idc.get_operand_value(ea,0), idc.GN_VISIBLE) or ""
            if "Interlocked" in name:
                interlocked_like += 1
            # virtual: call dword ptr [reg+imm]
            if idc.get_operand_type(ea,0) == idc.o_displ:
                vtbl_calls += 1

        # inlined interlocked (lock xadd/dec)
        if dis.startswith("lock "):
            if ("xadd" in dis or "dec" in dis) and "dword ptr [" in dis:
                interlocked_like += 1

    return (interlocked_like >= 2 and vtbl_calls >= 2)

for f in idautils.Functions():
    if func_has_release_shape(f):
        print("[sp_release-like] 0x%X  %s" % (f, idc.get_func_name(f)))
