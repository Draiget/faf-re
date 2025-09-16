# export_moho_rtti_vtable_to_json_ida9.py
# IDA 9.1, Python 3
#
# Collect MSVC8 RTTI & vtables → JSON (x86 PE)

import json
import re
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_segment
import idaapi
import idautils

# ----- IDA inf helpers (9.x-safe) -----
def _get_inf():
    """Return IDA inf structure in a 9.x-safe way."""
    try:
        return idaapi.get_inf_structure()
    except Exception:
        return idaapi.cvar.inf

def is_64():
    """True if current IDB is 64-bit."""
    inf = _get_inf()
    try:
        return inf.is_64bit()
    except Exception:
        # Fallback: assume 32-bit
        return False

def ptrsize():
    """Pointer size for current IDB."""
    inf = _get_inf()
    try:
        return inf.get_ptrsize()
    except Exception:
        return 8 if is_64() else 4

# ----- Generic helpers -----
def rd_ptr(ea):
    return ida_bytes.get_qword(ea) if is_64() else ida_bytes.get_dword(ea)

def get_seg_bounds_contains(substrs):
    """Find first segment whose name contains any of substrs (case-insensitive)."""
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        nm = ida_segment.get_segm_name(seg) or ""
        low = nm.lower()
        if any(ss in low for ss in substrs):
            return seg.start_ea, seg.end_ea
    return None, None

def try_read_c_string(ea, maxlen=0x800):
    out = []
    for i in range(maxlen):
        b = ida_bytes.get_wide_byte(ea + i)
        if b in (None, 0):
            break
        if b < 0x20 or b > 0x7E:
            return None
        out.append(chr(b))
    return "".join(out) if out else None

# ----- MSVC8 x86 RTTI validators -----
def is_valid_typedesc(td_ea):
    # x86 TypeDescriptor layout: name at +8
    name_ea = td_ea + 8
    s = try_read_c_string(name_ea)
    if not s:
        return None
    if not s.startswith(".?A"):
        return None
    if "@@" not in s:
        return None
    return name_ea

def is_valid_col(col_ea):
    # x86 COL: pTypeDescriptor at +12
    if not ida_bytes.is_loaded(col_ea):
        return False
    td = rd_ptr(col_ea + 12)
    name_ea = is_valid_typedesc(td)
    return name_ea is not None

def demangle(msvc_name):
    if not msvc_name:
        return None
    return ida_name.demangle_name(msvc_name,
                                  ida_name.MNG_NODEFINIT | ida_name.MNG_NORETTYPE | ida_name.MNG_NOECSU)

def tiny_hash(ea, n=64):
    bs = ida_bytes.get_bytes(ea, n) or b""
    return bs.hex()

def resolve_final_target(ea):
    """Follow simple compiler-generated thunks to the real method entry.
       Works on IDA 9.1 without ida_funcs.get_thunk_target()."""
    f = ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        # Try modern API first
        try:
            tgt = idaapi.get_thunk_target(f)
            if tgt != idaapi.BADADDR and ida_bytes.is_loaded(tgt):
                return tgt
        except Exception:
            pass
        # Fallback: take the first non-flow code ref from function start (e.g., 'jmp real')
        try:
            for x in idautils.CodeRefsFrom(f.start_ea, False):
                if x != idaapi.BADADDR and ida_bytes.is_loaded(x):
                    return x
        except Exception:
            pass
    return ea

def is_code_ptr(ea):
    if not ida_bytes.is_loaded(ea):
        return False
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    nm = (ida_segment.get_segm_name(seg) or "").lower()
    return ".text" in nm

def collect_vtable_slots(vt_ea):
    """Walk vtable entries until a non-code pointer is hit."""
    slots = []
    idx = 0
    ps = ptrsize()
    while True:
        fptr = rd_ptr(vt_ea + idx * ps)
        if not is_code_ptr(fptr):
            break
        tgt = resolve_final_target(fptr)
        cur_name = ida_name.get_name(tgt) or ""
        dm = demangle(cur_name) if cur_name else None
        slots.append({
            "index": idx,
            "ea": tgt,
            "name": cur_name,
            "demangled": dm,
            "hash": tiny_hash(tgt, 64),
        })
        idx += 1
        if idx > 4096:
            break
    return slots

def pretty_class_from_typedesc(mangled):
    # ".?AVgpg::RType@@" → "gpg::RType"
    if not mangled:
        return ""
    s = re.sub(r'^\.\?A[UV]', '', mangled)
    return s.rstrip("@@")

def find_all_vtables_in_rdata():
    rlo, rhi = get_seg_bounds_contains([".rdata"])
    if not rlo:
        rlo, rhi = get_seg_bounds_contains([".data"])
    if not rlo:
        ida_kernwin.msg("No data segment found for vtables.\n")
        return []

    items = []
    ps = ptrsize()
    ea = rlo + ps  # so ea-ps is valid
    while ea < rhi:
        col = rd_ptr(ea - ps)
        if is_valid_col(col):
            td = rd_ptr(col + 12)
            name_ea = td + 8
            mangled = try_read_c_string(name_ea) or ""
            cls = pretty_class_from_typedesc(mangled)
            slots = collect_vtable_slots(ea)
            signature = ida_bytes.get_dword(col + 0)
            offset    = ida_bytes.get_dword(col + 4)
            cdOffset  = ida_bytes.get_dword(col + 8)
            items.append({
                "vtable_ea": ea,
                "col_ea": col,
                "typedesc_ea": td,
                "typedesc_name_ea": name_ea,
                "mangled_type": mangled,
                "class": cls,
                "col": { "signature": signature, "offset": offset, "cdOffset": cdOffset },
                "slots": slots
            })
            ea += max(1, len(slots)) * ps
        ea += ps
    return items

def main():
    if is_64():
        ida_kernwin.warning("This exporter targets 32-bit MSVC8 layouts. Current IDB looks 64-bit.")
    out_path = ida_kernwin.ask_file(True, "*.json", "Save Moho RTTI/vtable export JSON")
    if not out_path:
        return
    items = find_all_vtables_in_rdata()
    payload = {
        "format": "moho-rtti-vtables-1",
        "compiler": "msvc8-x86",
        "ptrsize": ptrsize(),
        "count": len(items),
        "items": items,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    ida_kernwin.msg(f"[export] vtables: {len(items)} → {out_path}\n")

if __name__ == "__main__":
    main()
