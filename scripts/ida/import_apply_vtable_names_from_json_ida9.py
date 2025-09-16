# import_apply_vtable_names_from_json_ida9.py
# IDA 9.1, Python 3
#
# Apply names to vtable slot targets by matching TypeDescriptor strings from JSON.
# Renaming policy (config at top):
#  - By default, rename ONLY if current name looks auto-generated (sub_..., j_sub_..., nullsub_..., etc).
#  - Skip if current name already looks meaningful.
#  - Skip if the new candidate name itself looks auto-generated.

import json
import re
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_segment
import idaapi
import idautils

# -------------------- Config --------------------

VERIFY_HASH = False  # require tiny hash match before renaming
RENAME_ONLY_AUTO = True  # rename only functions that currently have auto-like names
SKIP_IF_NEWNAME_AUTO = True  # do not assign new name if candidate looks auto-like too

# Heuristics for IDA auto-generated names (extend if needed)
AUTO_NAME_PATTERNS = [
    r"^sub_[0-9A-Fa-f]{6,}$",
    r"^j_sub_[0-9A-Fa-f]{6,}$",
    r"^nullsub_[0-9A-Fa-f]{1,}$",
    r"^unknown_libname_.*$",
    r"^j__.*$",         # j___xxx thunks
    r"^__imp__.*$",     # import pointer thunk-ish
    r"^thunk_.*$",
    r"^locret_[0-9A-Fa-f]{6,}$",
    r"^loc_[0-9A-Fa-f]{6,}$",
    r"^off_[0-9A-Fa-f]{6,}$",
    r"^byte_[0-9A-Fa-f]{6,}$",
    r"^word_[0-9A-Fa-f]{6,}$",
    r"^dword_[0-9A-Fa-f]{6,}$",
]
AUTO_NAME_RE = re.compile("|".join(AUTO_NAME_PATTERNS))

# -------------------- IDA inf helpers (9.x-safe) --------------------

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
        return False

def ptrsize():
    """Pointer size for current IDB."""
    inf = _get_inf()
    try:
        return inf.get_ptrsize()
    except Exception:
        return 8 if is_64() else 4

# -------------------- Helpers --------------------

def rd_ptr(ea):
    """Read pointer-sized value at ea."""
    return ida_bytes.get_qword(ea) if is_64() else ida_bytes.get_dword(ea)

def try_read_c_string(ea, maxlen=0x800):
    """Read ASCII string; return None if non-printables encountered."""
    out = []
    for i in range(maxlen):
        b = ida_bytes.get_wide_byte(ea + i)
        if b in (None, 0):
            break
        if b < 0x20 or b > 0x7E:
            return None
        out.append(chr(b))
    return "".join(out) if out else None

def is_valid_typedesc(td_ea):
    """Validate x86 MSVC TypeDescriptor by checking name at +8."""
    name_ea = td_ea + 8
    s = try_read_c_string(name_ea)
    if not s or not s.startswith(".?A") or "@@" not in s:
        return None
    return name_ea

def is_valid_col(col_ea):
    """Validate CompleteObjectLocator by checking that +12 points to a valid TypeDescriptor."""
    if not ida_bytes.is_loaded(col_ea):
        return False
    td = rd_ptr(col_ea + 12)
    name_ea = is_valid_typedesc(td)
    return name_ea is not None

def find_strings_exact(sval):
    """Return EAs of exact ASCII string matches."""
    hits = []
    for s in idautils.Strings():
        if str(s) == sval:
            hits.append(s.ea)
    return hits

def find_td_by_mangled(mangled):
    """Locate TypeDescriptor by its mangled name (string is at td+8)."""
    for sea in find_strings_exact(mangled):
        td = sea - 8
        if is_valid_typedesc(td):
            return td
    return idaapi.BADADDR

def collect_cols_for_td(td_ea):
    """Find all COLs that reference this TypeDescriptor at +12."""
    cols = set()
    for x in idautils.DataRefsTo(td_ea):
        col = x - 12
        if is_valid_col(col):
            cols.add(col)
    return sorted(cols)

def resolve_final_target(ea):
    """Follow simple compiler-generated thunks to the real method entry (IDA 9.1-safe)."""
    f = ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        # Try API if present
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
    """Heuristic: code pointer if it's in a .text-like segment."""
    if not ida_bytes.is_loaded(ea):
        return False
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    nm = (ida_segment.get_segm_name(seg) or "").lower()
    return ".text" in nm

def find_vtables_by_col(col_ea):
    """Find vtables where [vtable - ptrsize] == col (x86 layout)."""
    vts = set()
    ps = ptrsize()
    for x in idautils.DataRefsTo(col_ea):
        vt = x + ps  # vtable starts right after COL ptr cell
        if ida_bytes.is_loaded(vt):
            first = rd_ptr(vt)
            if is_code_ptr(first):
                vts.add(vt)
    return sorted(vts)

def sanitize_method_name(class_name, slot_demangled, idx):
    """Build a readable symbol: 'Namespace__Class__Method'."""
    base = slot_demangled or f"vfunc_{idx}"
    tail = base.split("::")[-1]
    fq = f"{class_name}::{tail}" if class_name else tail
    sym = fq.replace("::", "__")
    sym = re.sub(r'[^0-9A-Za-z_]', "_", sym)
    return sym

def tiny_hash(ea, n=64):
    """Tiny hex hash of the first n bytes of function body."""
    bs = ida_bytes.get_bytes(ea, n) or b""
    return bs.hex()

def is_auto_generated_name(name: str) -> bool:
    """Check if a name looks like IDA's auto-generated placeholder."""
    if not name:
        return True
    return AUTO_NAME_RE.match(name) is not None

def maybe_rename_func(ea, newname):
    """Apply name with policy:
       - If RENAME_ONLY_AUTO: rename only when current name is auto-like.
       - If SKIP_IF_NEWNAME_AUTO: don't assign if new name is auto-like too.
    """
    if not newname:
        return False
    if SKIP_IF_NEWNAME_AUTO and is_auto_generated_name(newname):
        return False

    cur = ida_name.get_name(ea) or ""
    if RENAME_ONLY_AUTO:
        if cur and not is_auto_generated_name(cur):
            # Already meaningful → skip
            return False

    if cur == newname:
        return False

    # Try to set name; on collision, append address
    if ida_name.set_name(ea, newname, ida_name.SN_FORCE | ida_name.SN_NOCHECK):
        return True
    return ida_name.set_name(ea, f"{newname}__{ea:08X}", ida_name.SN_FORCE | ida_name.SN_NOCHECK)

# -------------------- Core --------------------

def apply_item(item):
    """Apply names for a single class' vtable slots."""
    mangled = item.get("mangled_type", "")
    cls = item.get("class", "")
    td = find_td_by_mangled(mangled)
    if td == idaapi.BADADDR:
        ida_kernwin.msg(f"[WARN] TypeDescriptor not found: {mangled}\n")
        return 0

    total = 0
    ps = ptrsize()
    for col in collect_cols_for_td(td):
        for vt in find_vtables_by_col(col):
            for slot in item.get("slots", []):
                idx = slot["index"]
                fptr = rd_ptr(vt + idx * ps)
                if not is_code_ptr(fptr):
                    continue
                tgt = resolve_final_target(fptr)

                if VERIFY_HASH:
                    want = slot.get("hash", "")
                    got  = tiny_hash(tgt, 64)
                    if want and want != got:
                        continue

                dem = slot.get("demangled") or slot.get("name") or f"vfunc_{idx}"
                newname = sanitize_method_name(cls, dem, idx)
                if maybe_rename_func(tgt, newname):
                    total += 1
    return total

def main():
    if is_64():
        ida_kernwin.warning("Importer expects 32-bit MSVC8 RTTI layout; current IDB looks 64-bit.")
    path = ida_kernwin.ask_file(False, "*.json", "Open Moho RTTI/vtable JSON")
    if not path:
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("format") != "moho-rtti-vtables-1":
        ida_kernwin.warning("Unexpected JSON format.")
        return
    items = data.get("items", [])
    renamed = 0
    for it in items:
        renamed += apply_item(it)
    ida_kernwin.msg(f"[import] Renamed ~{renamed} functions across {len(items)} classes.\n")

if __name__ == "__main__":
    main()
