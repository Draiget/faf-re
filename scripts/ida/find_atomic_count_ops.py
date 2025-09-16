# find_atomic_count_ops.py
import idautils, idc
def has_single_interlocked_call(f):
    cnt, last = 0, None
    for ea in idautils.FuncItems(f):
        if idc.print_insn_mnem(ea) == "call":
            tgt = idc.get_operand_value(ea, 0)
            name = idc.get_name(tgt, idc.GN_VISIBLE) or ""
            if "InterlockedIncrement" in name or "InterlockedDecrement" in name:
                cnt += 1; last = name
    return cnt == 1, last

for f in idautils.Functions():
    size = idc.get_func_attr(f, idc.FUNCATTR_END)-f
    if size <= 64:
        ok, which = has_single_interlocked_call(f)
        if ok:
            print("[atomic_count op] 0x%X  %s -> %s" % (f, idc.get_func_name(f), which))

# [atomic_count op] 0x9483C0  gpg::gal::StateManagerD3D9::Release -> __imp_InterlockedDecrement
# [atomic_count op] 0xABF81C  ??0_Init_locks@@QAE@@Z -> __imp_InterlockedIncrement
# [atomic_count op] 0xB14520  _ADXFIC_Init -> __imp_InterlockedIncrement
# [atomic_count op] 0xC0B428  ??1_Init_atexit@iosptrs@@QAE@@Z -> __imp_InterlockedDecrement
# [atomic_count op] 0xC0B432  ??1_Init_locks@@QAE@@Z -> __imp_InterlockedDecrement