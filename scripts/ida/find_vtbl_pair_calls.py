# find_vtbl_pair_calls.py  (IDA 9.x)
# Pattern: load vptr -> call [vptr] ... call [vptr+4] within a small window.

import idautils, idc

def find_vtbl_pair_in_func(f):
    start, end = f, idc.get_func_attr(f, idc.FUNCATTR_END)
    last_vptr_reg = None
    last_mov_ea = None
    for ea in idautils.FuncItems(f):
        m = idc.print_insn_mnem(ea)
        if m == "mov" and idc.get_operand_type(ea,0) == idc.o_reg and idc.get_operand_type(ea,1) == idc.o_displ:
            # mov reg, [base+off]  (vptr candidate)
            last_vptr_reg = idc.get_operand_value(ea,0)
            last_mov_ea = ea
        if m == "call" and idc.get_operand_type(ea,0) == idc.o_displ and last_vptr_reg is not None:
            # call dword ptr [reg+imm]
            reg = idc.get_operand_value(ea,0) & 0xF  # low nibble keeps reg id in many IDA builds
            if reg == last_vptr_reg:
                # look ahead for second virtual call off same vptr within small window
                look = idc.next_head(ea, end)
                hops = 0
                while look != idc.BADADDR and look < ea + 64 and hops < 16:
                    if idc.print_insn_mnem(look) == "call" and idc.get_operand_type(look,0) == idc.o_displ:
                        reg2 = idc.get_operand_value(look,0) & 0xF
                        if reg2 == last_vptr_reg:
                            return True, last_mov_ea, ea, look
                    look = idc.next_head(look, end); hops += 1
    return False, None, None, None

for f in idautils.Functions():
    ok, mov_ea, c1, c2 = find_vtbl_pair_in_func(f)
    if ok:
        print("[vtbl pair] 0x%X  %s  (mov@0x%X, calls@0x%X/0x%X)" %
              (f, idc.get_func_name(f), mov_ea or 0, c1 or 0, c2 or 0))
