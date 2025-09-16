# find_sp_add_ref_lock.py
import idautils, idc
for f in idautils.Functions():
    size = idc.get_func_attr(f, idc.FUNCATTR_END)-f
    if size > 256: 
        continue
    has_cas, has_back = False, False
    for ea in idautils.FuncItems(f):
        if idc.print_insn_mnem(ea) == "call":
            name = idc.get_name(idc.get_operand_value(ea,0), idc.GN_VISIBLE) or ""
            if "InterlockedCompareExchange" in name:
                has_cas = True
        if idc.print_insn_mnem(ea).startswith("j") and idc.get_operand_type(ea,0) == idc.o_near:
            if idc.get_operand_value(ea,0) < ea:
                has_back = True
    if has_cas and has_back:
        print("[sp_counted_base::add_ref_lock ?] 0x%X  %s  size=%d" % (f, idc.get_func_name(f), size))

# [sp_counted_base::add_ref_lock ?] 0xABFD0D  sub_ABFD0D  size=146
