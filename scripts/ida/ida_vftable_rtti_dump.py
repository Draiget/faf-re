# ida_emit_cpp_from_vtables.py
# IDA 9.x (IDAPython, Python 3)
#
# Emits C++ headers from MSVC VFTABLEs & RTTI and Markdown reports.
# Additions in this version:
# - Case-insensitive engine_tree routing; match by source hints and by class name (Mesh.cpp/.h)
# - Lua function classes: Foo_LuaFuncDef and FooBar -> owner Foo, method Bar; place near owner
# - Robust destructor detection for Dtr/dtr; robust template type handling
# - Anonymous namespace stripped from emitted namespaces
# - Output root is ./emit
# - refine_owner_candidate() ensures CAiPersonalityGetXxx_LuaFuncDef attaches to CAiPersonality
# - TRY_WITHOUT_LEADING_C flag (default False). When True, also try owner/file mapping without leading 'C'.
# - NEW: Proper display of template specializations (e.g., CScrLuaMetatableFactory<Moho::CAiNavigatorImpl>).
#
# Comments are in English.

import os
import re
import hashlib
from collections import defaultdict

import idaapi
import idc
import idautils
import ida_bytes
import ida_funcs
import ida_segment
import ida_name
import ida_nalt

# ---------- Config ----------
SKIP_STL = False
MAX_PATH_TOTAL = 240
INDENT_UNIT = "  "
COLLAPSE_STD_STRINGS = False  # keep std::basic_string/ostream forms intact
TRY_WITHOUT_LEADING_C = False # do not drop leading 'C' when resolving owners/files by default
LUA_SUBDIR_NAME = "lua"       # place *_LuaDef headers under this subfolder

# ---------- Global ----------
INF = None
PTR_SIZE = 4
TEXT_START = TEXT_END = None
RDATA_START = RDATA_END = None

# ---------- String helpers ----------

def _read_c_string_raw(ea: int, maxlen: int = 4096) -> str:
    if not ida_segment.getseg(ea):
        return ""
    out = bytearray()
    for i in range(maxlen):
        b = ida_bytes.get_byte(ea + i)
        if b is None or b == 0:
            break
        out.append(b)
    if not out:
        return ""
    try:
        return out.decode("utf-8", errors="ignore")
    except Exception:
        return out.decode("latin-1", errors="ignore")

def _get_ascii_string_at(ea: int) -> str:
    try:
        s = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if s:
            return s.decode("utf-8", errors="ignore") if isinstance(s, (bytes, bytearray)) else str(s)
    except Exception:
        pass
    try:
        s2 = idc.get_strlit_contents(ea, -1, idc.ASCSTR_C) if hasattr(idc, "get_strlit_contents") else idc.GetString(ea, -1, idc.ASCSTR_C)
        if s2:
            return s2.decode("utf-8", errors="ignore") if isinstance(s2, (bytes, bytearray)) else str(s2)
    except Exception:
        pass
    return _read_c_string_raw(ea)

# ---------- Demangle / name helpers ----------

def _demangle_msvc(name: str) -> str:
    if not name:
        return name
    try:
        dm = ida_name.demangle_name(name, ida_name.DQT_FULL)
        if dm:
            return dm
    except Exception:
        pass
    try:
        demangle = getattr(idc, "demangle_name", None) or getattr(idc, "Demangle", None)
        if demangle:
            if hasattr(idc, "get_inf_attr") and hasattr(idc, "INF_SHORT_DN"):
                flags = idc.get_inf_attr(idc.INF_SHORT_DN)
            elif hasattr(idc, "GetLongPrm") and hasattr(idc, "INF_SHORT_DN"):
                flags = idc.GetLongPrm(idc.INF_SHORT_DN)
            else:
                flags = 0
            dm = demangle(name, flags)
            if dm:
                return dm
    except Exception:
        pass
    return name

def _strip_class_struct_prefix(dm: str) -> str:
    if not dm:
        return dm
    return re.sub(r'^(?:class|struct|enum)\s+', '', dm).strip()

def _split_qualified_no_templates(qualified: str):
    tokens, cur, depth, i = [], [], 0, 0
    while i < len(qualified):
        ch = qualified[i]
        if ch == '<':
            depth += 1; cur.append(ch); i += 1; continue
        if ch == '>':
            depth = max(0, depth - 1); cur.append(ch); i += 1; continue
        if depth == 0 and qualified.startswith("::", i):
            tokens.append("".join(cur)); cur = []; i += 2; continue
        cur.append(ch); i += 1
    if cur: tokens.append("".join(cur))
    return [t for t in tokens if t]

def _split_namespace_and_class(qualified: str):
    parts = _split_qualified_no_templates(qualified)
    if not parts:
        return [], qualified
    return parts[:-1], parts[-1]

ID_SAFE_RE = re.compile(r'[^A-Za-z0-9_~]')

def _sanitize_identifier(s: str, allow_tilde=False) -> str:
    if not s:
        return "Unknown"
    s2 = s if allow_tilde else s.replace("~", "_dtor_")
    s2 = ID_SAFE_RE.sub("_", s2)
    s2 = re.sub(r"_+", "_", s2).strip("_")
    if s2 and s2[0].isdigit():
        s2 = "_" + s2
    return s2 or "Unknown"

def _sanitize_class_from_td(td_name: str) -> str:
    if not td_name:
        return "Unknown"
    t = td_name.replace(">", "").replace("<", "").replace(",", " ")
    t = t.replace("::", "__")
    t = re.sub(r"\s+", "_", t.strip())
    t = ID_SAFE_RE.sub("_", t)
    t = re.sub(r"_+", "_", t).strip("_")
    if t and t[0].isdigit():
        t = "_" + t
    return t or "Unknown"

def _infer_class_from_vtable_symbol(vt_ea: int):
    sym = idc.get_name(vt_ea) or ""
    dm = _demangle_msvc(sym)
    if not dm:
        return [], "", ""
    m = re.search(r'^(?:const\s+)?(.+?)::`vftable\'$', dm)
    if not m:
        return [], "", ""
    qualified = _strip_class_struct_prefix(m.group(1))
    ns_chain, cls = _split_namespace_and_class(qualified)
    sanitized = _sanitize_class_from_td(cls)
    return ns_chain, sanitized, qualified

# ---------- Windows-safe path helpers ----------

_WIN_INVALID = set('<>:"/\\|?*')
_WIN_RESERVED = {f"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1,10)} | {f"lpt{i}" for i in range(1,10)}

def _sanitize_path_component(name: str, maxlen: int = 100) -> str:
    if not name:
        name = "global"
    s = "".join(ch for ch in name if ch not in _WIN_INVALID)
    s = s.rstrip(" .")
    if not s:
        s = "ns"
    if s.lower() in _WIN_RESERVED:
        s = "_" + s
    if len(s) > maxlen:
        h = hashlib.md5(s.encode("utf-8")).hexdigest()[:8]
        s = s[:maxlen-9] + "_" + h
    return s

def _ns_path(root: str, ns_chain: list) -> str:
    if not ns_chain:
        return os.path.join(root, "global")
    safe_parts = [_sanitize_path_component(p) for p in ns_chain]
    return os.path.join(root, *safe_parts)

def _shorten_filename_if_needed(dirpath: str, filename: str, ext: str, max_total: int = MAX_PATH_TOTAL) -> str:
    core = filename
    full = os.path.join(dirpath, core + ext)
    if len(full) <= max_total:
        return core + ext
    h = hashlib.md5(core.encode("utf-8")).hexdigest()[:8]
    keep = max(16, max_total - len(dirpath) - len(ext) - 1 - 8)
    core2 = core[:keep] + "_" + h
    return core2 + ext

# ---------- Env / memory ----------

def _imagebase() -> int:
    return idaapi.get_imagebase()

def _get_seg_bounds_candidates(names):
    for n in names:
        seg = ida_segment.get_segm_by_name(n)
        if seg:
            return int(seg.start_ea), int(seg.end_ea)
    return None, None

def _seg_name(ea: int) -> str:
    seg = ida_segment.getseg(ea)
    return ida_segment.get_segm_name(seg) if seg else ""

def _is_in_text(ea: int) -> bool:
    if TEXT_START is not None:
        return TEXT_START <= ea < TEXT_END
    sn = _seg_name(ea).lower()
    return sn.startswith(".text") or sn == "code"

def _is_in_rdata(ea: int) -> bool:
    if RDATA_START is not None:
        return RDATA_START <= ea < RDATA_END
    sn = _seg_name(ea).lower()
    return ".rdata" in sn or "const" in sn or "rel.ro" in sn

def _read_ptr(ea: int) -> int:
    try:
        if PTR_SIZE == 4:
            return ida_bytes.get_dword(ea) & 0xFFFFFFFF
        else:
            return ida_bytes.get_qword(ea) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return 0

def _as_ea_from_rva(rva: int) -> int:
    if rva == 0:
        return 0
    ea = (rva & 0xFFFFFFFF) + _imagebase()
    return ea if ida_segment.getseg(ea) else 0

def _resolve_maybe_rva(ptr: int) -> int:
    if ptr == 0:
        return 0
    if ida_segment.getseg(ptr):
        return ptr
    ea = _as_ea_from_rva(ptr)
    return ea if ida_segment.getseg(ea) else 0

# ---------- RTTI parsing ----------

def _is_anon_ns_token(tok: str) -> bool:
    return "anonymous namespace" in tok.replace("`", "").lower()

class MSVC_COL:
    def __init__(self, ea):
        self.ea = ea
        self.signature = None
               # offset within object; not used now
        self.offset = None
        self.cd_offset = None
        self.pTypeDescriptor = 0
        self.pClassHierarchyDescriptor = 0

def parse_complete_object_locator(ea: int) -> MSVC_COL or None:
    try:
        col = MSVC_COL(ea)
        col.signature = ida_bytes.get_dword(ea + 0)
        col.offset    = ida_bytes.get_dword(ea + 4)
        col.cd_offset = ida_bytes.get_dword(ea + 8)
        col.pTypeDescriptor = _as_ea_from_rva(ida_bytes.get_dword(ea + 12))
        col.pClassHierarchyDescriptor = _as_ea_from_rva(ida_bytes.get_dword(ea + 16))
        if not ida_segment.getseg(col.pTypeDescriptor):
            return None
        if col.pClassHierarchyDescriptor and not ida_segment.getseg(col.pClassHierarchyDescriptor):
            col.pClassHierarchyDescriptor = 0
        return col
    except Exception:
        return None

def parse_type_descriptor_name(td_ea: int) -> str:
    name_off = PTR_SIZE * 2
    return _get_ascii_string_at(td_ea + name_off)

def parse_chd_bases(chd_ea: int) -> list:
    if not chd_ea:
        return []
    try:
        num = ida_bytes.get_dword(chd_ea + 8)
        pArr = _as_ea_from_rva(ida_bytes.get_dword(chd_ea + 12))
        if not ida_segment.getseg(pArr) or num == 0 or num > 4096:
            return []
        bases, seen = [], set()
        for i in range(num):
            bdesc_rva = ida_bytes.get_dword(pArr + 4 * i)
            bdesc = _as_ea_from_rva(bdesc_rva)
            if not ida_segment.getseg(bdesc):
                continue
            tdp = _as_ea_from_rva(ida_bytes.get_dword(bdesc + 0))
            if ida_segment.getseg(tdp):
                m = parse_type_descriptor_name(tdp)
                dm = _strip_class_struct_prefix(_demangle_msvc(m))
                if dm and dm not in seen:
                    seen.add(dm); bases.append(dm)
        return bases
    except Exception:
        return []

# ---------- Immediate base heuristic ----------
def _choose_immediate_bases(c) -> list:
    """
    Heuristic: MSVC RTTI base array usually starts with 'self', then direct base(s).
    1) Try to locate 'self' by qualified or simple name.
    2) If found and there is a next entry -> pick that (immediate base).
    3) If not found but array has >= 2 entries -> pick bases[1].
    4) Else if array has >= 1 and it's not self -> pick bases[0].
    """
    bases = c.get("bases", []) or []
    if not bases:
        return []
    self_q = (c.get("qualified", "") or "").strip()
    self_simple = _class_simple_from_qualified(self_q, c.get("sanitized_class",""))
    # try to find exact/self-like token
    self_idx = -1
    for i, b in enumerate(bases):
        if b == self_q or b.split("::")[-1] == self_simple:
            self_idx = i
            break
    # primary: immediate after self
    if self_idx >= 0 and self_idx + 1 < len(bases):
        cand = bases[self_idx + 1]
        if cand != bases[self_idx]:
            return [cand]
    # secondary fallbacks
    if len(bases) >= 2:
        return [bases[1]]
    if len(bases) == 1 and bases[0] != self_q:
        return [bases[0]]
    # last resort: first non-self anywhere in the list
    for b in bases:
        if b != self_q and b.split("::")[-1] != self_simple:
            return [b]
    return []

# ---------- VFTABLE discovery ----------

def discover_vftables_by_name():
    vts = []
    for ea, name in idautils.Names():
        if name.startswith("??_7"):
            vts.append(int(ea))
    return sorted(set(vts))

def is_probable_vftable(ea: int) -> bool:
    if ea < PTR_SIZE:
        return False
    col_ptr = _read_ptr(ea - PTR_SIZE)
    col_ea  = _resolve_maybe_rva(col_ptr)
    if not col_ea or not _is_in_rdata(col_ea):
        return False
    col = parse_complete_object_locator(col_ea)
    if not col:
        return False
    td_mangled = parse_type_descriptor_name(col.pTypeDescriptor)
    return td_mangled.startswith(".?A")

def discover_vftables_by_scan():
    vts = []
    for seg in idautils.Segments():
        s = ida_segment.getseg(seg)
        sname = ida_segment.get_segm_name(s).lower()
        if not (".rdata" in sname or "const" in sname or "rel.ro" in sname or sname == "_data"):
            continue
        ea = int(s.start_ea) + PTR_SIZE
        end = int(s.end_ea)
        while ea < end:
            try:
                if is_probable_vftable(ea):
                    vts.append(ea)
                    p = ea
                    while True:
                        tgt = _read_ptr(p)
                        if not _is_in_text(tgt):
                            break
                        p += PTR_SIZE
                    ea = p + PTR_SIZE
                    continue
            except Exception:
                pass
            ea += PTR_SIZE
    return sorted(set(vts))

# ---------- Function/string extraction ----------

SRC_RE = re.compile(r'[/\\]src[/\\][^ \n\r\t"\'<>|?*]+?\.(?:c|cc|cpp|cxx)\b', re.IGNORECASE)
LOG_RE = re.compile(r'\b(?:E\d{4}:|ERROR|WARN|INFO|ASSERT|FATAL|TRACE)\b', re.IGNORECASE)

def strings_used_by_function(fn_start_ea: int) -> list:
    res, seen = [], set()
    f = ida_funcs.get_func(fn_start_ea)
    if not f:
        return res
    for insn_ea in idautils.FuncItems(f.start_ea):
        for x in idautils.DataRefsFrom(insn_ea):
            if x in seen:
                continue
            s = _get_ascii_string_at(x)
            if s:
                seen.add(x); res.append(s)
    return res

def source_hints_from_strings(strlist: list) -> list:
    hints, seen = [], set()
    for s in strlist:
        if SRC_RE.search(s) or s.lower().endswith((".cpp", ".cxx", ".cc", ".c")):
            if s not in seen:
                seen.add(s); hints.append(s)
    return hints

def log_hints_from_strings(strlist: list) -> list:
    hints, seen = [], set()
    for s in strlist:
        if LOG_RE.search(s) or (':' in s and len(s) < 200 and any(k in s for k in ("Illegal", "invalid", "failed", "error"))):
            if s not in seen:
                seen.add(s); hints.append(s)
    return hints

def enum_vtable_functions(vt_ea: int):
    out = []
    slot = 0
    p = vt_ea
    while True:
        tgt = _read_ptr(p)
        if not _is_in_text(tgt):
            break
        name = idc.get_name(tgt) or ""
        dm = _demangle_msvc(name)
        out.append((slot, tgt, name, dm))
        slot += 1; p += PTR_SIZE
    return out

# ---------- Signature parsing & cleaning ----------

ACCESS_RE = re.compile(r'^(?:\s*(?:public|protected|private):\s*)+', re.IGNORECASE)
CALLCONV_RE = r'(?:__thiscall|__cdecl|__stdcall|__fastcall|__vectorcall)'

def _collapse_std_basic(s: str) -> str:
    if COLLAPSE_STD_STRINGS:
        s = re.sub(r'\bstd::basic_string\s*<\s*char\b([^<>]|<(?:[^<>]|<[^<>]*>)*>)*>', 'std::string', s)
        s = re.sub(r'\bstd::basic_string\s*<\s*wchar_t\b([^<>]|<(?:[^<>]|<[^<>]*>)*>)*>', 'std::wstring', s)
        s = re.sub(r'\bstd::basic_ostream\s*<\s*char\b([^<>]|<(?:[^<>]|<[^<>]*>)*>)*>', 'std::ostream', s)
        s = re.sub(r'\bstd::basic_istream\s*<\s*char\b([^<>]|<(?:[^<>]|<[^<>]*>)*>)*>', 'std::istream', s)
        s = re.sub(r'\bstd::basic_iostream\s*<\s*char\b([^<>]|<(?:[^<>]|<[^<>]*>)*>)*>', 'std::iostream', s)
    return s

def _clean_cpp_type(t: str) -> str:
    s = t.strip()
    s = _collapse_std_basic(s)
    s = re.sub(r'\b(class|struct|enum)\s+', '', s)
    s = re.sub(r'\b(__ptr64|__unaligned|__restrict|__w64)\b', '', s)
    s = re.sub(r'\bnear\b|\bfar\b', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'\s*\*\s*', ' *', s)
    s = re.sub(r'\s*&\s*', ' &', s)
    return s

def _split_params_no_templates(argstr: str):
    items, cur, depth = [], [], 0
    for ch in argstr:
        if ch == '<': depth += 1; cur.append(ch); continue
        if ch == '>': depth = max(0, depth-1); cur.append(ch); continue
        if ch == ',' and depth == 0:
            items.append("".join(cur).strip()); cur = []; continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail: items.append(tail)
    return items

def _find_last_scope_before(s: str, pos: int) -> int:
    depth = 0
    i = pos - 1
    while i >= 1:
        ch = s[i]
        if ch == '>': depth += 1
        elif ch == '<': depth = max(0, depth-1)
        elif depth == 0 and s[i-1] == ':' and ch == ':':
            return i-1
        i -= 1
    return -1

def parse_demangled_signature(dm: str):
    if not dm:
        return None
    s = dm.strip()
    s = ACCESS_RE.sub('', s)
    s = re.sub(r'^(?:\s*(?:virtual|static|inline|explicit|constexpr|friend)\s+)+', '', s, flags=re.IGNORECASE)
    cv = ''
    mcv = re.search(r'\)\s*(const|volatile|const volatile)\s*$', s)
    if mcv:
        cv = mcv.group(1)
        s = s[:mcv.start()+1]
    p = s.rfind('(')
    if p == -1:
        name_only = s.split("::")[-1]
        owner = s[:-len(name_only)].rstrip(":: ")
        owner = _strip_class_struct_prefix(owner.strip())
        return {"name": name_only, "owner": owner, "ret": "", "args": [], "cv": ""}
    q = s.find(')', p)
    args_s = s[p+1:q] if q != -1 else ''
    idx = _find_last_scope_before(s, p)
    if idx == -1:
        return None
    name = s[idx+2:p].strip()
    j = idx-1
    depth = 0
    while j >= 0:
        ch = s[j]
        if ch == '>': depth += 1
        elif ch == '<': depth = max(0, depth-1)
        elif depth == 0 and ch.isspace():
            break
        j -= 1
    owner = s[j+1:idx].strip()
    owner = _strip_class_struct_prefix(owner)
    ret = s[:j+1].strip()
    ret = re.sub(rf'\b{CALLCONV_RE}\b', '', ret).strip()
    ret = _clean_cpp_type(ret)
    args = []
    if args_s and args_s.lower() != 'void':
        args = [_clean_cpp_type(x) for x in _split_params_no_templates(args_s)]
    return {"name": name, "owner": owner, "ret": ret, "args": args, "cv": cv}

# ---------- Type usage → includes / fwd ----------

def std_headers_for_types(types: list) -> set:
    headers = set()
    joined = " ".join(types)
    if "std::string" in joined or "std::wstring" in joined or "std::basic_string<" in joined:
        headers.add("<string>")
    if "std::vector<" in joined: headers.add("<vector>")
    if "std::map<" in joined: headers.add("<map>")
    if "std::unordered_map<" in joined: headers.add("<unordered_map>")
    if "std::set<" in joined: headers.add("<set>")
    if "std::unordered_set<" in joined: headers.add("<unordered_set>")
    if "std::unique_ptr<" in joined or "std::shared_ptr<" in joined or "std::weak_ptr<" in joined:
        headers.add("<memory>")
    if "std::function<" in joined: headers.add("<functional>")
    if "std::optional<" in joined: headers.add("<optional>")
    if "std::pair<" in joined: headers.add("<utility>")
    if "std::tuple<" in joined: headers.add("<tuple>")
    if "std::ostream" in joined or "std::basic_ostream<" in joined: headers.add("<ostream>")
    if "std::istream" in joined or "std::basic_istream<" in joined: headers.add("<istream>")
    if "std::iostream" in joined or "std::basic_iostream<" in joined: headers.add("<iostream>")
    return headers

QN_RE = re.compile(r'\b([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)\b')

def extract_user_types(type_strings: list) -> set:
    qns = set()
    for t in type_strings:
        outer = re.sub(r'<[^<>]*>', '', t)
        for m in QN_RE.finditer(outer):
            qn = m.group(1)
            if qn.startswith("std::"):
                continue
            qns.add(qn)
    return qns

def group_by_namespace(qnames: set) -> dict:
    groups = defaultdict(set)
    for q in qnames:
        ns, cls = _split_namespace_and_class(q)
        if not cls: continue
        groups[tuple(ns)].add(cls)
    return groups

# ---------- LuaPlus forwards helpers ----------

def luaplus_qnames_in_methods(c) -> set:
    """Collect LuaPlus qualified names that appear in ret/args/demangled text."""
    q = set()
    for fn in c.get("functions", []):
        parts = []
        if fn.get("ret"): parts.append(fn["ret"])
        for a in fn.get("args", []): parts.append(a)
        if fn.get("demangled"): parts.append(fn["demangled"])
        blob = " ".join(parts)
        if "LuaPlus::LuaState" in blob: q.add("LuaPlus::LuaState")
        if "LuaPlus::LuaObject" in blob: q.add("LuaPlus::LuaObject")
    return q

# ---------- Heuristics: owners from Lua names ----------

def infer_owner_from_lua_suffix(cls_name: str) -> str or None:
    m = re.match(r'^([A-Za-z_]\w+?)_LuaFuncDef\b', cls_name)
    if m:
        return m.group(1)
    m2 = re.match(r'^([A-Za-z_]\w+?)_Lua\w+\b', cls_name)
    if m2:
        return m2.group(1)
    return None

def infer_owner_from_concat_prefix(cls_name: str, known_class_names: set) -> str or None:
    """
    Infer owner when class name starts with an existing class name (case-insensitive),
    typical for FooBar / FooBar_LuaFuncDef -> owner Foo, method Bar.
    Choose the longest matching owner prefix with next char being uppercase (or end/_).
    """
    lname = cls_name.lower()
    best = None
    for k in known_class_names:
        lk = k.lower()
        if lname.startswith(lk):
            # forbid exact match (self is not an owner)
            if len(cls_name) == len(k):
                continue
            nxt = cls_name[len(k):len(k)+1]
            if not (nxt and (nxt.isupper() or nxt == "_")):
                continue
            if best is None or len(k) > len(best):
                best = k
    return best

# ensure owner candidate resolves to an existing class name; optionally try without leading 'C'
def refine_owner_candidate(owner_candidate: str, known_class_names: set) -> str or None:
    """Pick best owner from candidate using longest known-class prefix (case-insensitive).
       If TRY_WITHOUT_LEADING_C is True, also try a version without a leading 'C'."""
    if not owner_candidate:
        return None
    if owner_candidate in known_class_names:
        return owner_candidate
    ln = owner_candidate.lower()
    best = None
    for k in known_class_names:
        lk = k.lower()
        if ln.startswith(lk):
            # boundary looks like start of method (Uppercase or '_') or exact
            if len(owner_candidate) == len(k) or owner_candidate[len(k):len(k)+1].isupper() or owner_candidate[len(k):len(k)+1] == "_":
                if best is None or len(k) > len(best):
                    best = k
    if best:
        return best
    if TRY_WITHOUT_LEADING_C and len(owner_candidate) >= 2 and owner_candidate[0] == 'C' and owner_candidate[1].isupper():
        no_c = owner_candidate[1:]
        if no_c in known_class_names:
            return no_c
        lnc = no_c.lower()
        best2 = None
        for k in known_class_names:
            lk = k.lower()
            if lnc.startswith(lk):
                if len(no_c) == len(k) or no_c[len(k):len(k)+1].isupper() or no_c[len(k):len(k)+1] == "_":
                    if best2 is None or len(k) > len(best2):
                        best2 = k
        if best2:
            return best2
    return None

# ---------- Misc helpers ----------

def _class_simple_from_qualified(qualified: str, fallback: str) -> str:
    if not qualified:
        return fallback
    ns, tail = _split_namespace_and_class(qualified)
    simple = re.sub(r'<.*>', '', tail)
    return simple.split("::")[-1].strip() or fallback

def _is_dtr_name(name: str) -> bool:
    return name.lower() in ("dtr", "dtor", "destructor")

# ---------- Destructor detection ----------

def is_destructor(parsed, dm_name: str, raw_name: str, class_simple: str) -> bool:
    if parsed and parsed["name"].startswith("~"):
        return True
    if raw_name.startswith("??_G") or raw_name.startswith("??_E"):
        return True
    nm = (parsed["name"] if parsed else "").strip()
    if _is_dtr_name(nm):
        return True
    if dm_name and dm_name.lower().endswith("::dtr"):
        return True
    if nm and class_simple and nm.lower() == "dtr":
        return True
    return False

# ---------- Engine tree parsing (case-insensitive) ----------

def parse_engine_tree(root_dir: str):
    """
    Parse engine_tree.txt (case-insensitive).
    Returns:
      file_to_dirs: {'mesh.cpp': {'moho/mesh', ...}}
      all_dirs: {'moho', 'moho/mesh', ...}
      leaf_map_ci: {'moho': {'moho', 'foo/moho'}, 'mesh': {'moho/mesh', ...}}
    """
    path = os.path.join(root_dir, "engine_tree.txt")
    file_to_dirs = defaultdict(set)
    all_dirs = set()
    if not os.path.exists(path):
        return file_to_dirs, all_dirs, defaultdict(set)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    stack = []
    for raw in lines:
        line = raw.replace("\t", "    ").rstrip("\r\n")
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        name = line.strip()
        is_dir = name.endswith("/")
        if is_dir:
            name = name.rstrip("/")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if is_dir:
            stack.append((indent, name))
            dirpath = "/".join([d for _, d in stack])
            all_dirs.add(dirpath)
        else:
            dirpath = "/".join([d for _, d in stack]) if stack else ""
            file_to_dirs[name.lower()].add(dirpath)
    leaf_map_ci = defaultdict(set)
    for d in all_dirs:
        leaf = d.split("/")[-1].lower()
        leaf_map_ci[leaf].add(d)
    return file_to_dirs, all_dirs, leaf_map_ci

# ---------- Placement (engine tree + heuristics) ----------

def _class_file_candidates(cls_simple: str):
    base = cls_simple
    cands = [f"{base}.cpp", f"{base}.c", f"{base}.hpp", f"{base}.h"]
    if TRY_WITHOUT_LEADING_C and len(base) >= 2 and base[0] == 'C' and base[1].isupper():
        base2 = base[1:]
        cands += [f"{base2}.cpp", f"{base2}.c", f"{base2}.hpp", f"{base2}.h"]
    return cands

def choose_emit_subdir_for_class(c, file_to_dirs, leaf_map_ci, classes_by_name):
    """
    Choose emit subdir using (in order):
      1) source hints filenames -> engine_tree path (case-insensitive)
      2) owner anchor:
         - From Foo_LuaFuncDef/Foo_Lua* OR from concat prefix of full class name,
           then refined by known classes (and optionally by dropping leading 'C')
         - If owner class exists -> owner's folder; else Owner.{cpp,h} in engine_tree
      3) class name itself: Mesh.{cpp,h} in engine_tree
      4) first namespace token -> match engine_tree leaf (case-insensitive)
      5) None -> fall back to namespace-based path
    """
    known_names = set(classes_by_name.keys())

    # 1) source hints by basename
    for s in c.get("source_hints", []):
        bn = s.replace("\\", "/").split("/")[-1].lower()
        if bn in file_to_dirs and file_to_dirs[bn]:
            return sorted(file_to_dirs[bn])[0]

    # 2) owner anchors with refinement
    cls_name = c.get("sanitized_class","")
    owner_raw = infer_owner_from_lua_suffix(cls_name)
    owner = refine_owner_candidate(owner_raw, known_names) if owner_raw else None
    if not owner:
        owner = infer_owner_from_concat_prefix(cls_name, known_names)

    if owner:
        owner_cls = classes_by_name.get(owner)
        if owner_cls and owner_cls.get("header_rel"):
            return os.path.dirname(owner_cls["header_rel"]).replace("\\","/")
        # else try owner.{cpp,h} in engine tree
        for cand in _class_file_candidates(owner.lower()):
            if cand in file_to_dirs and file_to_dirs[cand]:
                return sorted(file_to_dirs[cand])[0]

    # 2.5) template base mapping: CPullTask<Moho::X> -> CPullTask.{hpp,cpp} location
    q = c.get("qualified") or c.get("original_td") or ""
    base, args = _extract_template_from_qualified(q)
    if base:
        # If base class itself is present, reuse its folder
        base_sanitized = _sanitize_class_from_td(base)
        base_cls = classes_by_name.get(base_sanitized)
        if base_cls and base_cls.get("header_rel"):
            return os.path.dirname(base_cls["header_rel"]).replace("\\","/")
        # else try engine_tree by base name
        for cand in _class_file_candidates(base.lower()):
            if cand in file_to_dirs and file_to_dirs[cand]:
                return sorted(file_to_dirs[cand])[0]

    # 3) class name itself -> Mesh.cpp/.h etc.
    cls_simple = c.get("sanitized_class","")
    for cand in _class_file_candidates(cls_simple.lower()):
        if cand in file_to_dirs and file_to_dirs[cand]:
            dirs = sorted(file_to_dirs[cand])
            if c.get("ns_chain"):
                leaf = c["ns_chain"][0].lower()
                prefer = [d for d in dirs if d.split("/")[-1].lower() == leaf]
                if prefer:
                    return prefer[0]
            return dirs[0]

    # 4) map by first namespace token to leaf
    ns_chain = c.get("ns_chain", [])
    if ns_chain:
        leaf = ns_chain[0].lower()
        if leaf in leaf_map_ci and leaf_map_ci[leaf]:
            return sorted(leaf_map_ci[leaf])[0]

    return None

# ---------- Template display helpers ----------

def _extract_template_from_qualified(qualified: str):
    """
    Given qualified name like 'Moho::CScrLuaMetatableFactory<class Moho::CAiNavigatorImpl>'
    return (base='CScrLuaMetatableFactory', args='Moho::CAiNavigatorImpl') or (None, None) if not a specialization.
    """
    if not qualified:
        return None, None
    ns, tail = _split_namespace_and_class(qualified)
    tail = _strip_class_struct_prefix(tail)
    if '<' not in tail or '>' not in tail:
        return None, None
    # find first '<' and its matching '>' with nesting
    i = tail.find('<')
    depth = 0
    end = -1
    for j, ch in enumerate(tail[i:], start=i):
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth -= 1
            if depth == 0:
                end = j
                break
    if i == -1 or end == -1:
        return None, None
    base = tail[:i].strip()
    args = tail[i+1:end].strip()
    # strip 'class/struct/enum' keywords inside args
    args = re.sub(r'\b(class|struct|enum)\s+', '', args)
    return base, args

def _display_class_name_for_emit(c):
    """
    Prefer 'template<> class Base<Args>' when RTTI shows specialization, otherwise 'class Sanitized'.
    """
    qualified = c.get("qualified") or c.get("original_td") or ""
    base, args = _extract_template_from_qualified(qualified)
    if base and args:
        return f"template<> class {base}<{args}>", base, args
    # fallback to sanitized name
    return f"class {c['sanitized_class']}", c['sanitized_class'], None

# ---------- Collect ----------

def collect_all():
    print("[*] Discovering VFTABLEs…")
    vt_named = discover_vftables_by_name()
    vt_scanned = discover_vftables_by_scan()
    vt_all = sorted(set(vt_named + vt_scanned))
    print(f"    Named:  {len(vt_named)}")
    print(f"    Scanned:{len(vt_scanned)}")
    print(f"    Total:  {len(vt_all)}")

    classes = []

    for vt_ea in vt_all:
        entry = {
            "vftable_ea": vt_ea,
            "col_ea": 0,
            "qualified": "",
            "sanitized_class": "",
            "ns_chain": [],
            "original_td": "",
            "bases": [],
            "functions": [],
            "source_hints": [],
            "log_hints": [],
            "header_rel": "",
            "hdr_abs": "",
        }

        col_ptr = _read_ptr(vt_ea - PTR_SIZE)
        col_ea = _resolve_maybe_rva(col_ptr)
        col = parse_complete_object_locator(col_ea) if col_ea else None
        if col_ea:
            entry["col_ea"] = col_ea

        if col:
            td_mangled = parse_type_descriptor_name(col.pTypeDescriptor)
            td_dem = _strip_class_struct_prefix(_demangle_msvc(td_mangled))
            entry["original_td"] = td_dem or td_mangled
            ns_chain, cls = _split_namespace_and_class(td_dem) if td_dem else ([], "")
            ns_chain = [t for t in ns_chain if not _is_anon_ns_token(t)]
            entry["ns_chain"] = ns_chain
            entry["qualified"] = td_dem
            entry["sanitized_class"] = _sanitize_class_from_td(cls if cls else td_dem)
            entry["bases"] = parse_chd_bases(col.pClassHierarchyDescriptor)
        else:
            ns_chain, sanitized, qualified = _infer_class_from_vtable_symbol(vt_ea)
            ns_chain = [t for t in ns_chain if not _is_anon_ns_token(t)]
            entry["ns_chain"] = ns_chain
            entry["sanitized_class"] = sanitized or "Unknown"
            entry["qualified"] = qualified or ""

        if SKIP_STL and entry["ns_chain"] and entry["ns_chain"][0] == "std":
            continue

        # Functions & strings
        all_strings = []
        class_simple = _class_simple_from_qualified(entry.get("qualified",""), entry["sanitized_class"])
        for slot, tgt, raw, dem in enum_vtable_functions(vt_ea):
            srefs = strings_used_by_function(tgt)
            all_strings.extend(srefs)

            parsed = parse_demangled_signature(dem) if dem else None
            dtor = is_destructor(parsed, dem or "", raw, class_simple)

            if dtor:
                method_name = f"~{class_simple}"
                ret_type = "void"
                args = []
                cv = ""
            elif parsed:
                method_name = parsed["name"] or f"fn_slot_{slot}"
                ret_type = parsed["ret"] or "void"
                args = parsed["args"]
                cv = parsed["cv"] or ""
            else:
                tail = dem.split("::")[-1] if dem else ""
                method_name = tail if tail else f"fn_slot_{slot}"
                ret_type = "void"
                args = []
                cv = ""

            # Rename CRT purecall placeholders to include the vftable slot index
            raw_lower = (raw or "").lower()
            dm_lower = (dem or "").lower()
            name_lower = (method_name or "").lstrip("_").lower()
            if ("purecall" in dm_lower) or ("purecall" in raw_lower) or (raw_lower in ("_purecall", "__purecall")) or ("purecall" in name_lower):
                # Generate a stable, readable placeholder like purecall0, purecall10, ...
                method_name = f"purecall{slot}"
                # Keep interface-like signature (we don't care about real _purecall prototype here)
                ret_type = "void"
                args = []
                cv = ""

            entry["functions"].append({
                "slot": slot,
                "ea": tgt,
                "raw_name": raw,
                "demangled": dem or "",
                "name": _sanitize_identifier(method_name, allow_tilde=True),
                "ret": ret_type,
                "args": args,
                "cv": cv,
                "is_dtor": bool(dtor),
            })

        entry["source_hints"] = source_hints_from_strings(all_strings)[:16]
        entry["log_hints"] = log_hints_from_strings(all_strings)[:16]

        classes.append(entry)

    return classes

def _is_lua_wrapper_name(s: str) -> bool:
    # Detect Lua wrapper classes by suffix patterns like *_LuaFuncDef, *_LuaXXX
    if not s:
        return False
    return bool(re.search(r'(?:_LuaFuncDef\b|_Lua\w+\b)', s))

# ---------- Emit C++ (two-pass with engine tree) ----------

def _emit_namespace_open(ns_chain, base_indent=""):
    """Emit C++17-style collapsed namespace: namespace a::b { ... }"""
    if not ns_chain:
        return ""
    joined = "::".join(ns_chain)
    return f"{base_indent}namespace {joined} {{\n"

def _emit_namespace_close(ns_chain, base_indent=""):
    """Close a collapsed namespace with a single brace and full comment."""
    if not ns_chain:
        return ""
    joined = "::".join(ns_chain)
    return f"{base_indent}}} // namespace {joined}\n"

def _emit_doc_header(c, indent=""):
    lines = []
    lines.append(f"{indent}/**")
    lines.append(f"{indent} * VFTABLE: 0x{c['vftable_ea']:08X}")
    if c.get("col_ea"):
        lines.append(f"{indent} * COL:  0x{c['col_ea']:08X}")
    if c.get("original_td"):
        lines.append(f"{indent} * Original TD: {c['original_td']}")
    if c.get("source_hints"):
        lines.append(f"{indent} * Source hints:")
        for s in c["source_hints"]:
            lines.append(f"{indent} *  - {s}")
    if c.get("log_hints"):
        lines.append(f"{indent} * Log/code strings:")
        for s in c["log_hints"]:
            lines.append(f"{indent} *  - {s}")
    lines.append(f"{indent} */")
    return "\n".join(lines) + "\n"

def _emit_class_decl(c, indent=""):
    # only immediate base, not the entire ancestry
    bases = _choose_immediate_bases(c)
    base_clause = " : " + ", ".join([f"public {b}" for b in bases]) if bases else ""
    # Decide display name (template specialization vs plain)
    display, base_for_dtor, tmpl_args = _display_class_name_for_emit(c)
    out = []
    # Brace on the next line (Allman-like)
    out.append(f"{indent}{display}{base_clause}")
    out.append(f"{indent}{{")
    out.append(f"{indent}public:")
    emitted_dtor = False
    first_decl = True  # ensure a blank line between declarations
    for fn in c["functions"]:
        # ensure a blank line between function declarations
        if not first_decl:
            out.append("")
        first_decl = False
        if fn["is_dtor"]:
            if emitted_dtor:
                continue
            emitted_dtor = True
            # dtor should use base name (without template args)
            signature = f"virtual ~{base_for_dtor}();"
        else:
            ret = _clean_cpp_type(fn["ret"] or "void") or "void"
            args = ", ".join(fn["args"]) if fn["args"] else ""
            const_suffix = " const" if fn.get("cv", "").startswith("const") else ""
            # Safety net: ensure purecall has slot index even if earlier step failed
            name_for_emit = fn["name"]
            # Strong safety: if purecall name lacks index → add slot index
            if "purecall" in name_for_emit.lower() and not re.search(r'purecall\d+$', name_for_emit, re.IGNORECASE):
                name_for_emit = f"purecall{fn['slot']}"
            signature = f"virtual {ret} {name_for_emit}({args}){const_suffix} = 0;"

        out.append(f"{indent}{INDENT_UNIT}/**")
        out.append(f"{indent}{INDENT_UNIT} * Address: 0x{fn['ea']:08X}")
        out.append(f"{indent}{INDENT_UNIT} * Slot: {fn['slot']}")
        if fn.get("demangled"):
            out.append(f"{indent}{INDENT_UNIT} * Demangled: {fn['demangled']}")
        out.append(f"{indent}{INDENT_UNIT} */")
        out.append(f"{indent}{INDENT_UNIT}{signature}")
    out.append(f"{indent}}};")
    return "\n".join(out) + "\n"

def plan_headers(classes):
    inpath = ida_nalt.get_input_file_path()
    bin_dir = os.path.dirname(inpath)
    root = os.path.join(bin_dir, "emit")
    os.makedirs(root, exist_ok=True)

    file_to_dirs, all_dirs, leaf_map_ci = parse_engine_tree(bin_dir)

    # index by sanitized class name
    classes_by_name = { c.get("sanitized_class",""): c for c in classes }

    # (regular classes get their header paths here)
    for c in classes:
        ns_chain = c.get("ns_chain", [])
        cls_name = c.get("sanitized_class", "Unknown")

        subdir = choose_emit_subdir_for_class(c, file_to_dirs, leaf_map_ci, classes_by_name)
        if subdir:
            parts = [ _sanitize_path_component(p) for p in subdir.split("/") if p ]
            ns_dir = os.path.join(root, *parts) if parts else root
        else:
            ns_dir = _ns_path(root, ns_chain)

        os.makedirs(ns_dir, exist_ok=True)
        safe_cls = _sanitize_path_component(cls_name, maxlen=180)
        # emit .h and .cpp side-by-side
        h_name   = _shorten_filename_if_needed(ns_dir, safe_cls, ".h",   max_total=MAX_PATH_TOTAL)
        hdr_path = os.path.join(ns_dir, h_name)
        cpp_name = _shorten_filename_if_needed(ns_dir, safe_cls, ".cpp", max_total=MAX_PATH_TOTAL)
        cpp_path = os.path.join(ns_dir, cpp_name)

        c["hdr_abs"] = hdr_path
        c["header_rel"] = os.path.relpath(hdr_path, root).replace("\\", "/")
        c["cpp_abs"] = cpp_path
        c["cpp_rel"] = os.path.relpath(cpp_path, root).replace("\\", "/")

    # second pass:
    #  - if Lua wrapper has a resolvable owner WITH A HEADER → keep owner (we'll append inside its namespace, after the class)
    #  - else → reroute wrapper into "moho/lua/" (or "<ns>/lua/") subfolder; filename forced to "*_LuaFuncDef.hpp"
    for c in classes:
        c["is_lua_wrapper"] = _is_lua_wrapper_name(c.get("sanitized_class",""))
        if not c["is_lua_wrapper"]:
            continue
        
        cls_name  = c.get("sanitized_class","")
        owner_raw = infer_owner_from_lua_suffix(cls_name)
        owner = refine_owner_candidate(owner_raw, set(classes_by_name.keys())) if owner_raw else None
        if not owner:
            owner = infer_owner_from_concat_prefix(cls_name, set(classes_by_name.keys()))
        if owner and owner.lower() == cls_name.lower():
            owner = None
        if owner:
            owner_cls = classes_by_name.get(owner)
            # Only keep if owner really has a header to append into
            if owner_cls and owner_cls.get("header_rel"):
                continue

        # No owner found → reroute this Lua wrapper to "<ns>/lua/"
        base_rel_dir = os.path.dirname(c["header_rel"]).replace("\\","/")
        # If we are under Moho namespace, normalize to "moho"
        ns_chain = c.get("ns_chain", [])
        if ns_chain and ns_chain[0].lower() == "moho":
            base_rel_dir = "moho"
        # build "<base>/lua"
        lua_rel_dir = (base_rel_dir + ("/" if base_rel_dir else "") + LUA_SUBDIR_NAME) if base_rel_dir else LUA_SUBDIR_NAME
        lua_abs_dir = os.path.join(root, *lua_rel_dir.split("/")) if lua_rel_dir else root
        os.makedirs(lua_abs_dir, exist_ok=True)

        # normalize filename to "*_LuaFuncDef.hpp" regardless of original suffix
        safe_cls = _sanitize_path_component(cls_name, maxlen=180)
        # strip any trailing "_LuaXXXX"
        base_no_lua = re.sub(r'(?:_Lua\w+)$', '', safe_cls)
        forced = base_no_lua + "_LuaFuncDef"
        # emit .h and .cpp for standalone lua wrappers
        h_name   = _shorten_filename_if_needed(lua_abs_dir, forced, ".h",   max_total=MAX_PATH_TOTAL)
        hdr_path = os.path.join(lua_abs_dir, h_name)
        cpp_name = _shorten_filename_if_needed(lua_abs_dir, forced, ".cpp", max_total=MAX_PATH_TOTAL)
        cpp_path = os.path.join(lua_abs_dir, cpp_name)
        c["hdr_abs"]    = hdr_path
        c["header_rel"] = os.path.relpath(hdr_path, root).replace("\\", "/")
        c["cpp_abs"]    = cpp_path
        c["cpp_rel"]    = os.path.relpath(cpp_path, root).replace("\\", "/")

    # map qualified names → headers (also anon-ns stripped variant)
    def _strip_anon_in_q(q: str) -> str:
        parts = _split_qualified_no_templates(q)
        parts = [p for p in parts if not _is_anon_ns_token(p)]
        return "::".join(parts)

    qname_to_rel = {}
    for c in classes:
        q = c.get("qualified") or ""
        if q:
            qname_to_rel[q] = c["header_rel"]
            q2 = _strip_anon_in_q(q)
            if q2 and q2 not in qname_to_rel:
                qname_to_rel[q2] = c["header_rel"]
        ns = c.get("ns_chain", [])
        comp = "::".join(ns + [c.get("sanitized_class","Unknown")]) if ns else c.get("sanitized_class","Unknown")
        if comp and comp not in qname_to_rel:
            qname_to_rel[comp] = c["header_rel"]

    return root, qname_to_rel

def std_headers_for_class(c):
    all_types = []
    for fn in c["functions"]:
        if not fn["is_dtor"]:
            if fn["ret"]:
                all_types.append(_clean_cpp_type(fn["ret"]))
            for a in fn["args"]:
                all_types.append(a)
    std_includes = std_headers_for_types(all_types)
    user_qtypes  = extract_user_types(all_types)
    # Always add LuaPlus forwards for Lua wrappers (safety net)
    if c.get("is_lua_wrapper"):
        user_qtypes |= {"LuaPlus::LuaState", "LuaPlus::LuaObject"}
    # Also add what we can detect from demangled text
    user_qtypes |= luaplus_qnames_in_methods(c)
    return std_includes, user_qtypes

def _emit_forward_block_for_qnames(qnames: set) -> str:
    """Emit compact forward-decls placed BEFORE the main namespace."""
    if not qnames:
        return ""
    groups = group_by_namespace(qnames)
    out = []
    for ns_tuple, names in sorted(groups.items(), key=lambda kv: (len(kv[0]), kv[0])):
        if ns_tuple:
            joined = "::".join(ns_tuple)
            # stable alphabetical order of names to avoid duplicate-but-reordered lines
            out.append(f"namespace {joined} {{ ")
            for nm in sorted(names):
                out.append(f"class {nm}; ")
            out.append("}")
            out.append(" // forward decl\n")
        else:
            for nm in sorted(names):
                out.append(f"class {nm}; // forward decl\n")
    out.append("\n")
    return "".join(out)

def _header_has_luaplus_forward(text: str) -> bool:
    # any forward for LuaPlus::LuaState / LuaPlus::LuaObject already present
    return bool(re.search(r'namespace\s+LuaPlus\s*{\s*class\s+Lua(State|Object)\s*;', text))

def _strip_luaplus_forward(text: str) -> str:
    # remove any previous LuaPlus forward-decl blocks to avoid duplicates
    return re.sub(
        r'(?:^|\n)namespace\s+LuaPlus\s*{\s*class\s+Lua(?:State|Object)\s*;\s*}\s*//\s*forward\s*decl\s*\n?',
        '\n',
        text
    )

def _ensure_luaplus_forward_at_header_top(filepath: str, qnames: set):
    """Insert (once) LuaPlus forward-decls right after #pragma once / includes."""
    if not qnames:
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = f.read()
    except FileNotFoundError:
        return
    fwd = _emit_forward_block_for_qnames(qnames)
    data = _strip_luaplus_forward(data)
    if _header_has_luaplus_forward(data):
        # already present somewhere (maybe руками), не дублируем
        return
    # find insertion point: after '#pragma once' and following #include/blank lines
    pos = 0
    m = re.search(r'^#pragma\s+once[^\n]*\n', data, flags=re.M)
    if m:
        pos = m.end()
    # skip includes and blank lines
    inc_re = re.compile(r'(?:[ \t]*#include[^\n]*\n|[ \t]*\n)')
    while True:
        m2 = inc_re.match(data, pos)
        if not m2:
            break
        pos = m2.end()
    # ensure a blank line before injected forwards
    new_data = data[:pos] + ("" if data[pos-1:pos] == "\n" else "\n") + fwd + data[pos:]
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        f.write(new_data)


def _insert_block_before_namespace_close(filepath: str, ns_chain: list, content: str):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = f.read()
    except FileNotFoundError:
        # If file doesn't exist, just write block wrapped in namespaces
        with open(filepath, "w", encoding="utf-8", newline="\n") as f:
            f.write("// Auto-generated from IDA VFTABLE/RTTI scan.\n")
            f.write("// This header is a skeleton for reverse-engineering; adjust as needed.\n")
            f.write("#pragma once\n\n")
            f.write(content.rstrip() + "\n")
        return

    # Find the closing marker and insert BEFORE it, so the block stays INSIDE namespace
    if ns_chain:
        # Prefer collapsed full chain match: "} // namespace a::b"
        joined = "::".join(ns_chain)
        pat_full = re.compile(rf"\n\}}\s*//\s*namespace\s+{re.escape(joined)}\s*\n")
        last = None
        for m in pat_full.finditer(data):
            last = m
        if not last:
            # Fallback for legacy nested style: use outermost namespace marker
            outer = ns_chain[0]
            pat_outer = re.compile(rf"\n\}}\s*//\s*namespace\s+{re.escape(outer)}\s*\n")
            for m in pat_outer.finditer(data):
                last = m
        if last:
            insert_at = last.start()  # BEFORE the close marker
            before = data[:insert_at]
            after = data[insert_at:]
            # Ensure we have a separating newline before payload
            if not before.endswith("\n"):
                before += "\n"
            payload = "\n" + content.strip() + "\n"
            new_data = before + payload + after
        else:
            # no recognizable marker -> append at end
            sep = "" if data.endswith("\n") else "\n"
            new_data = data + sep + "\n" + content.strip() + "\n"
    else:
        # no namespace -> just append
        sep = "" if data.endswith("\n") else "\n"
        new_data = data + sep + "\n" + content.strip() + "\n"

    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        f.write(new_data)

def emit_cpp_headers(classes, root, qname_to_rel):
    classes_by_name = { c.get("sanitized_class",""): c for c in classes }
    # collect wrappers by owner header (insert once per owner)
    wrappers_by_owner = defaultdict(list)  # key: (hdr_abs, tuple(ns_chain)), val: [classes]
    normals = []
    for c in classes:
        if c.get("is_lua_wrapper"):
            cls_name = c.get("sanitized_class","")
            owner_raw = infer_owner_from_lua_suffix(cls_name)
            owner = refine_owner_candidate(owner_raw, set(classes_by_name.keys())) if owner_raw else None
            if not owner:
                owner = infer_owner_from_concat_prefix(cls_name, set(classes_by_name.keys()))
            # drop self-owner (case-insensitive)
            if owner and owner.lower() == cls_name.lower():
                owner = None
            owner_cls = classes_by_name.get(owner) if owner else None
            if owner_cls and owner_cls.get("hdr_abs"):
                key = (owner_cls["hdr_abs"], tuple(owner_cls.get("ns_chain", [])))
                wrappers_by_owner[key].append(c)
                continue
        normals.append(c)

    # emit normal headers (non-wrapper, and wrappers without owner)
    for c in normals:
        ns_chain = c.get("ns_chain", [])
        cls_name = c.get("sanitized_class", "Unknown")
        hdr_path = c["hdr_abs"]

        std_includes, user_qtypes = std_headers_for_class(c)

        # Force LuaPlus forwards if present in methods (for standalone headers)
        forced_lua = luaplus_qnames_in_methods(c)
        if forced_lua:
            user_qtypes |= forced_lua

        # If this class is a template specialization, also forward-declare types from template args
        q = c.get("qualified") or c.get("original_td") or ""
        base, args = _extract_template_from_qualified(q)
        if args:
            extra_types = extract_user_types([args])
            user_qtypes |= extra_types

        local_includes = []
        for b in c.get("bases", []):
            rel = qname_to_rel.get(b)
            if rel and rel != c["header_rel"]:
                local_includes.append(rel)
        local_includes = sorted(set(local_includes))

        to_fwd = {qname for qname in user_qtypes if qname not in qname_to_rel or qname_to_rel[qname] not in local_includes}
        self_q = c.get("qualified") or ("::".join(ns_chain + [cls_name]) if ns_chain else cls_name)
        to_fwd.discard(self_q)
        fwd_groups = group_by_namespace(to_fwd)

        with open(hdr_path, "w", encoding="utf-8", newline="\n") as f:
            # Header preamble and includes
            f.write("// Auto-generated from IDA VFTABLE/RTTI scan.\n")
            f.write("// This header is a skeleton for reverse-engineering; adjust as needed.\n")
            f.write("#pragma once\n\n")
            for inc in sorted(std_includes):
                f.write(f"#include {inc}\n")
            for inc in local_includes:
                f.write(f"#include \"{inc}\"\n")
            if std_includes or local_includes:
                f.write("\n")

            # Forward declarations for other user types (if any)
            if fwd_groups:
                for ns_tuple, names in sorted(fwd_groups.items(), key=lambda kv: (len(kv[0]), kv[0])):
                    if ns_tuple:
                        f.write("".join([f"namespace {n} {{ " for n in ns_tuple]))
                        for nm in sorted(names):
                            f.write(f"class {nm}; ")
                        f.write("".join(["}" for _ in ns_tuple]))
                        f.write(" // forward decl\n")
                    else:
                        for nm in sorted(names):
                            f.write(f"class {nm}; // forward decl\n")
                f.write("\n")

            # Namespace + class body (always emit, regardless of fwd_groups)
            f.write(_emit_namespace_open(ns_chain))
            indent = INDENT_UNIT * len(ns_chain)
            f.write(_emit_doc_header(c, indent=indent))
            f.write(_emit_class_decl(c, indent=indent))
            f.write(_emit_namespace_close(ns_chain))
        # Emit companion .cpp for this class/wrapper (only for standalone headers)
        cpp_path = c.get("cpp_abs")
        if cpp_path:
            ns_joined = "::".join(ns_chain) if ns_chain else ""
            with open(cpp_path, "w", encoding="utf-8", newline="\n") as cf:
                # Simple translation unit that includes the header and sets namespace
                cf.write("// Auto-generated from IDA VFTABLE/RTTI scan.\n")
                cf.write(f"#include \"{c['header_rel']}\"\n")
                if ns_joined:
                    cf.write(f"using namespace {ns_joined};\n")
                # keep a blank line at the end
                cf.write("\n")

        print(f"[+] Emitted: {hdr_path}")
        if cpp_path:
            print(f"[+] Emitted: {cpp_path}")

    # now append wrappers, batched per owner file;
    # add LuaPlus forward ONCE per file at header top (not after namespace)
    for (hdr_abs, ns_tuple), wrappers in wrappers_by_owner.items():
        try:
            with open(hdr_abs, "r", encoding="utf-8") as f:
                existing = f.read()
        except FileNotFoundError:
            existing = ""

        need_lua = set()
        for w in wrappers:
            need_lua |= luaplus_qnames_in_methods(w)
            if w.get("is_lua_wrapper"):
                need_lua |= {"LuaPlus::LuaState", "LuaPlus::LuaObject"}

        # ensure forward-decls stay at the top, once
        if need_lua:
            _ensure_luaplus_forward_at_header_top(hdr_abs, need_lua)

        # build wrapper classes block (to be inserted INSIDE namespace, right before closing)
        blocks = []
        for w in wrappers:
            blocks.append(_emit_doc_header(w, indent="") + _emit_class_decl(w, indent=""))
        # ensure one blank line between wrapper blocks, and trailing newline
        payload = ("\n\n".join(b.strip("\n") for b in blocks)).strip() + "\n"

        _insert_block_before_namespace_close(hdr_abs, list(ns_tuple), payload)
        for w in wrappers:
            print(f"[+] Appended Lua wrapper {w.get('sanitized_class','')} to {hdr_abs}")

    print(f"[+] Output root: {root}")

# ---------- Markdown ----------

def _md_escape(s: str) -> str:
    return s.replace("`", "\\`")

def _write_markdown(classes, md_path, root_for_links=None):
    total = len(classes)
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# VFTABLE & RTTI Report\n\n")
        f.write(f"- Total classes: **{total}**\n")
        f.write(f"- Imagebase: `0x{_imagebase():08X}`\n\n---\n\n")
        for c in classes:
            title = c.get("qualified") or c.get("sanitized_class") or "<unknown>"
            f.write(f"## {title}\n\n")
            if root_for_links and c.get("header_rel"):
                f.write(f"- Header: `{c['header_rel']}`\n")
            f.write(f"- VFTABLE: `0x{c['vftable_ea']:08X}`  \n")
            if c.get("col_ea"):
                f.write(f"- COL: `0x{c['col_ea']:08X}`  \n")
            if c.get("original_td"):
                f.write(f"- Original TD: `{_md_escape(c['original_td'])}`  \n")
            if c.get("bases"):
                f.write(f"- Bases: {', '.join('`'+_md_escape(b)+'`' for b in c['bases'])}\n")
            if c.get("source_hints"):
                f.write("\n**Source hints**\n")
                for s in c["source_hints"]:
                    f.write(f"- {_md_escape(s)}\n")
            if c.get("log_hints"):
                f.write("\n**Log/code strings**\n")
                for s in c["log_hints"]:
                    f.write(f"- {_md_escape(s)}\n")
            f.write("\n### Virtual functions\n\n")
            if not c["functions"]:
                f.write("_none_\n\n")
            else:
                f.write("| Slot | EA | Demangled | Inferred signature |\n|---:|---|---|---|\n")
                for fn in c["functions"]:
                    dem = _md_escape(fn.get("demangled") or fn.get("raw_name") or "")
                    ret = _clean_cpp_type(fn["ret"] or "void") or "void"
                    args = ", ".join(fn["args"]) if fn["args"] else ""
                    const_suffix = " const" if fn.get("cv", "").startswith("const") else ""
                    sig = (f"~{c['sanitized_class']}()" if fn["is_dtor"]
                           else f"{ret} {fn['name']}({args}){const_suffix}")
                    f.write(f"| {fn['slot']} | `0x{fn['ea']:08X}` | `{dem}` | `{_md_escape(sig)}` |\n")
                f.write("\n---\n\n")

def emit_markdown_reports(classes, emit_root):
    inpath = ida_nalt.get_input_file_path()
    base_no_ext = os.path.splitext(os.path.basename(inpath))[0]
    md_outer = os.path.join(os.path.dirname(inpath), f"{base_no_ext}.vftable_rtti.md")
    md_inner = os.path.join(emit_root, "REPORT.md")
    _write_markdown(classes, md_outer, root_for_links=emit_root)
    _write_markdown(classes, md_inner, root_for_links=emit_root)

# ---------- Init / Entry ----------

def _init_env():
    global INF, PTR_SIZE, TEXT_START, TEXT_END, RDATA_START, RDATA_END
    INF = None
    try:
        INF = idaapi.cvar.inf
    except Exception:
        pass
    if INF is None and hasattr(idaapi, "get_inf_structure"):
        try:
            INF = idaapi.get_inf_structure()
        except Exception:
            INF = None
    PTR_SIZE = 8 if (INF and hasattr(INF, "is_64bit") and INF.is_64bit()) else 4
    TEXT_START, TEXT_END = _get_seg_bounds_candidates([".text", "CODE"])
    RDATA_START, RDATA_END = _get_seg_bounds_candidates(
        [".rdata", ".rdata$const", ".rdata$zz", ".rdata$01", ".rdata$02", "_DATA", ".data.rel.ro"]
    )

def main():
    idaapi.auto_wait()
    _init_env()
    classes = collect_all()
    emit_root, qname_to_rel = plan_headers(classes)
    emit_cpp_headers(classes, emit_root, qname_to_rel)
    emit_markdown_reports(classes, emit_root)
    print("[*] Done.")

if __name__ == "__main__":
    main()
