# find_atomic_count_member_ops.py (IDA 9.x)
import idautils, idc

def is_member_interlocked(f):
    ea_list = list(idautils.FuncItems(f))
    size = idc.get_func_attr(f, idc.FUNCATTR_END) - f
    if size > 64: 
        return False, None
    saw_lea, saw_call, glob_like = False, False, False
    for i, ea in enumerate(ea_list):
        m = idc.print_insn_mnem(ea)
        if m == "push" and idc.get_operand_type(ea,0) == idc.o_imm:
            # push offset <global>  -> это не член, выкинем
            glob_like = True
        if m == "lea":
            # ожидаем lea reg, [ecx+imm]
            op1 = idc.print_operand(ea, 1)
            if op1.startswith("ecx"):
                saw_lea = True
        if m == "call":
            name = idc.get_name(idc.get_operand_value(ea,0), idc.GN_VISIBLE) or ""
            if "InterlockedIncrement" in name or "InterlockedDecrement" in name:
                saw_call = True
    return (saw_lea and saw_call and not glob_like), size

for f in idautils.Functions():
    ok, sz = is_member_interlocked(f)
    if ok:
        print("[boost::atomic_count ?] 0x%X  %s  size=%d" % (f, idc.get_func_name(f), sz))
