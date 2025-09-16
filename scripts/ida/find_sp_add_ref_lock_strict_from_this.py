# find_sp_add_ref_lock_strict_from_this.py  (IDA 9.x)
# Find InterlockedCompareExchange where Destination = lea(...,[ecx+imm]) and there's a CAS loop.

import idautils, idc, ida_bytes

def prev_push_regs(ea, n=3):
    """Collect up to n previous 'push reg' insns before 'ea', return list (nearest first)."""
    res = []
    i = 0
    cur = ea
    while i < 64 and len(res) < n:
        cur = idc.prev_head(cur)
        if cur == idc.BADADDR:
            break
        if idc.print_insn_mnem(cur) == "push" and idc.get_operand_type(cur,0) == idc.o_reg:
            res.append((cur, idc.get_operand_value(cur,0)))
        i += 1
    return res  # [(ea, regid), ...]

def def_is_lea_from_ecx(func_ea, reg, use_ea, window=20):
    """Walk backwards up to 'window' insns looking for 'lea reg, [ecx+imm]'."""
    i = 0
    cur = use_ea
    while i < window:
        cur = idc.prev_head(cur)
        if cur < func_ea or cur == idc.BADADDR:
            break
        if idc.print_insn_mnem(cur) == "lea" and idc.get_operand_type(cur,0) == idc.o_reg:
            if idc.get_operand_value(cur,0) == reg:
                op1 = idc.print_operand(cur,1).lower()
                if op1.startswith("ecx+") or ("ecx+" in op1) or ("[ecx+" in op1):
                    return True
        i += 1
    return False

def has_back_edge(func_ea):
    for ea in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(ea).startswith("j") and idc.get_operand_type(ea,0) == idc.o_near:
            if idc.get_operand_value(ea,0) < ea:
                return True
    return False

for f in idautils.Functions():
    size = idc.get_func_attr(f, idc.FUNCATTR_END)-f
    if size > 384:
        continue
    ok = False
    for ea in idautils.FuncItems(f):
        if idc.print_insn_mnem(ea) != "call":
            continue
        tgt = idc.get_operand_value(ea,0)
        name = idc.get_name(tgt, idc.GN_VISIBLE) or ""
        if "CompareExchange" not in name:  # catch __imp__InterlockedCompareExchange@12 too
            continue
        pushes = prev_push_regs(ea, 3)
        if len(pushes) < 1:
            continue
        # In MSVC stdcall order we often see: push Comperand, push Exchange, push Destination
        dest_push_ea, dest_reg = pushes[-1]  # the farthest of three pushes
        if def_is_lea_from_ecx(f, dest_reg, dest_push_ea):
            ok = True
            break
    if ok and has_back_edge(f):
        print("[sp_add_ref_lock candidate] 0x%X  %s  size=%d" % (f, idc.get_func_name(f), size))
