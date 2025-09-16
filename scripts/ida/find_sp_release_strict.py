# find_sp_release_strict.py
import idautils, idc

def calls_imp(ea, frag):
    if idc.print_insn_mnem(ea) != "call": return False
    name = idc.get_name(idc.get_operand_value(ea,0), idc.GN_VISIBLE) or ""
    return frag in name

for f in idautils.Functions():
    size = idc.get_func_attr(f, idc.FUNCATTR_END)-f
    if not (24 <= size <= 192): 
        continue
    decs, vcalls, disp_calls = 0, 0, []
    for ea in idautils.FuncItems(f):
        m = idc.print_insn_mnem(ea)
        if m == "call" and idc.get_operand_type(ea,0) == idc.o_displ:
            vcalls += 1
            disp_calls.append(ea)
        if m == "call" and (calls_imp(ea,"InterlockedDecrement") or calls_imp(ea,"InterlockedExchangeAdd")):
            decs += 1
    # хотим 2 атомарных декремента и 2 виртуальных call'а
    if decs >= 2 and vcalls >= 2:
        print("[sp_counted_base::release ?] 0x%X  %s  size=%d" % (f, idc.get_func_name(f), size))
