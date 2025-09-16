# find_lock_ops_near_vtbl.py
import idautils, idc

def has_lock_and_vtbl(f):
    start, end = f, idc.get_func_attr(f, idc.FUNCATTR_END)
    if end - start > 256:
        return False
    locks, vtbls = 0, 0
    for ea in idautils.FuncItems(f):
        dis = idc.GetDisasm(ea).lower()
        if dis.startswith("lock ") and ("dword ptr [" in dis) and ("dec" in dis or "xadd" in dis or "inc" in dis):
            locks += 1
        if idc.print_insn_mnem(ea) == "call" and idc.get_operand_type(ea,0) == idc.o_displ:
            vtbls += 1
    return locks >= 1 and vtbls >= 2

for f in idautils.Functions():
    if has_lock_and_vtbl(f):
        print("[lock+vtbl] 0x%X  %s" % (f, idc.get_func_name(f)))
