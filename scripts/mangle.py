#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Single‑file MSVC x86 name mangle/demangle helper without invoking a compiler.

Supported features
------------------
- Free functions (__cdecl / __stdcall / __fastcall)
- Class methods (__thiscall by default; static methods are treated as free functions with the chosen CC)
- Trailing `const` on methods
- Primitive types, enums (as `enum T`), class/struct by value
- One level of references (&) and pointers (*)
- Constructors / destructors (including deleting destructors for demangling)
- RTTI type names that look like .?A... (class/struct/union/enum) + templates .?AV?$Name@Args@Scope@@

Limitations
-----------
- Encodes/decodes the **x86** scheme only
- Function template **demangling** of method containers is limited (best-effort TODO)
- No arrays
- No multi-level ** / *& chains
"""

import re
import sys
from typing import List, Tuple, Dict

# ---- primitive type codes ----
PRIM: Dict[str, str] = {
    "void": "X",
    "bool": "_N",
    "char": "D",
    "signed char": "C",
    "unsigned char": "E",
    "short": "F",
    "unsigned short": "G",
    "int": "H",
    "unsigned int": "I",
    "long": "J",
    "unsigned long": "K",
    "long long": "_J",
    "unsigned long long": "_K",
    "float": "M",
    "double": "N",
    "wchar_t": "_W",
}

# Common aliases that are normalized to canonical C/C++ types before encoding.
ALIASES: Dict[str, str] = {
    "uint8_t": "unsigned char",
    "int8_t": "signed char",
    "uint16_t": "unsigned short",
    "int16_t": "short",
    "uint32_t": "unsigned int",
    "int32_t": "int",
    "uint64_t": "unsigned long long",
    "int64_t": "long long",
    "size_t": "unsigned int",
    "uintptr_t": "unsigned int",
    "intptr_t": "int",
    "DWORD": "unsigned long",
    "WORD": "unsigned short",
    "BYTE": "unsigned char",
    "UINT": "unsigned int",
    "INT": "int",
    "ULONG": "unsigned long",
    "LONG": "long",
    "BOOL": "int",
}

# Aggregate kind overrides for bare (unqualified) names. This is used when
# the type does not explicitly specify `class/struct/union` and we need to
# decide which aggregate kind letter to use in the mangle.
# Values: "U" = struct, "V" = class, "T" = union.
AGG_KIND_HINT: Dict[str, str] = {
    "SessionOptions": "U",
}

# ---- calling convention encodings ----
CC_FREE_CODE  = { "__cdecl":"A", "__stdcall":"G", "__fastcall":"I" }
CC_FREE_NAME  = { v:k for k,v in CC_FREE_CODE.items() }
CC_MEMBER_CODE = { "__thiscall":"E", "__cdecl":"A", "__stdcall":"G", "__fastcall":"I" }
CC_MEMBER_NAME = { v:k for k,v in CC_MEMBER_CODE.items() }

# ---- signature parsers ----
# Allow template components in qualified names: Ns::C<T,U>::Method
_TPL_PART = r"[A-Za-z_]\w*(?:<[^<>(){}\[\]]*(?:<[^<>(){}\[\]]*>[^<>(){}\[\]]*)*>?)?"
_QUAL_NAME = rf"(?:{_TPL_PART}(?:::)*)+{_TPL_PART}"

SIG_RE = re.compile(
    r"""^\s*
        (?:(?P<virtual>virtual)\s+|(?P<static>static)\s+)?     # optional
        (?P<ret>[^()\s][^()]*?)\s+                             # return type
        (?:(?P<cc>__cdecl|__stdcall|__fastcall)\s+)?           # optional CC
        (?P<name>""" + _QUAL_NAME + r""")\s*                   # ns::Class or ns::Class<T...>::func
        \(\s*(?P<params>.*)\s*\)\s*
        (?P<cv>const(?:\s+volatile)?|volatile(?:\s+const)?)?   # trailing const
        \s*;?\s*$
    """, re.VERBOSE,
)

CTOR_RE = re.compile(
    r"""^\s*
        (?:(?P<virtual>virtual)\s+)?                           # (ignored for ctor)
        (?:(?P<cc>__cdecl|__stdcall|__fastcall)\s+)?           # optional CC
        (?P<name>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*::[A-Za-z_]\w*)\s*
        \(\s*(?P<params>.*)\s*\)\s*$
    """, re.VERBOSE,
)
DTOR_RE = re.compile(
    r"""^\s*
        (?:(?P<virtual>virtual)\s+)?                           # virtual dtor?
        (?:(?P<cc>__cdecl|__stdcall|__fastcall)\s+)?           # optional CC
        (?P<name>(?:[A-Za-z_]\w*::)*~[A-Za-z_]\w*)\s*
        \(\s*(?P<params>.*)\s*\)\s*$
    """, re.VERBOSE,
)

def split_params(s: str) -> List[str]:
    """
    Split a raw parameter list string into individual parameter type tokens.
    Supports '...' (C/C++ varargs) as a standalone token.
    - Handles nested templates and parenthesis to avoid splitting inside them.
    - Removes parameter names and default values.
    - Leaves pointer-to-function parameters as-is (unsupported for encoding).
    """
    s = s.strip()
    if s == "" or s == "void":
        return []
    out, cur, lt, par = [], [], 0, 0
    for ch in s:
        if ch == '<': lt += 1
        elif ch == '>': lt = max(0, lt-1)
        elif ch == '(': par += 1
        elif ch == ')': par = max(0, par-1)
        if ch == ',' and lt == 0 and par == 0:
            out.append("".join(cur).strip()); cur=[]
        else:
            cur.append(ch)
    if cur: out.append("".join(cur).strip())
    # strip names and default values
    cleaned=[]
    for it in out:
        it = re.sub(r"=\s*[^,]+$", "", it).strip()
        if re.search(r"\(\s*\*\s*.*\)\s*\(", it):  # ptr-to-func — not supported
            cleaned.append(it); continue
        if it == "...":  # keep ellipsis as-is; handled in arglist encoder
            cleaned.append(it); continue
        # 1) common case: "... type name"
        m = re.search(r"^(.*\S)\s+([_A-Za-z]\w*)\s*$", it)
        if m:
            cleaned.append(m.group(1).strip())
            continue
        # 2) sticky names like "Type*name" / "Type&name" / "Type*&name"
        m2 = re.search(r"^(.*[\*\&])\s*([_A-Za-z]\w*)\s*$", it)
        if m2:
            cleaned.append(m2.group(1).strip())
            continue
        cleaned.append(it)
    return cleaned

def encode_scoped(name: str) -> str:
    """Encode a C++ scoped name `A::B::C` into MSVC `C@B@A@@` form."""
    parts = [p for p in name.split("::") if p]
    return parts[-1] + ("@" + "@".join(parts[-2::-1]) if len(parts)>1 else "") + "@@"

# --- templates in scope encoding (A::B<T,U>::C) ---
def _split_tpl_args(s: str) -> List[str]:
    """Split template argument list 'T, U<V>' into ['T', 'U<V>'] (handles nesting)."""
    args, cur, depth = [], [], 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            args.append("".join(cur).strip()); cur=[]
            i += 1; continue
        cur.append(ch)
        i += 1
    if cur: args.append("".join(cur).strip())
    return args

def encode_scoped_tpl(name: str) -> str:
    """
    Encode scope with possible template components.
    Examples:
      'Moho::X'                  -> 'X@Moho@@'
      'Moho::FastVectorN<T>'     -> '?$FastVectorN@VT@@@Moho@@'
      'Ns::V<A*, const B&>::M'   -> '?$V@PAT@@ABVNs::B@@@Ns@@'
    """
    parts = [p for p in name.split("::") if p]
    enc_parts: List[str] = []
    for p in parts[::-1]:  # inner->outer in MSVC
        if '<' not in p:
            enc_parts.append(p + "@")
            continue
        # templated
        base, _, rest = p.partition("<")
        args_txt = rest.rsplit(">", 1)[0]
        args = _split_tpl_args(args_txt)
        arg_codes = ""
        for a in args:
            a = a.strip()
            # allow bare dependent names like 'T'
            arg_codes += encode_type(a)
        enc_parts.append("?$" + base + "@" + arg_codes + "@")
    return "".join(enc_parts) + "@@"

def normalize_base_type(t: str) -> str:
    """Remove top-level `const`/`volatile`, collapse whitespace, and apply aliases."""
    t = re.sub(r"\bconst\b|\bvolatile\b", "", t).strip()
    t = re.sub(r"\s+", " ", t)
    return ALIASES.get(t, t)

# ---- type encoding ----
def encode_base_or_named(t: str) -> str:
    """
    Encode a primitive or a named (enum/class/struct/union) type.
    For bare names w/o an explicit keyword, consult AGG_KIND_HINT to decide kind.
    """
    t0 = normalize_base_type(t)
    if t0 in PRIM:
        return PRIM[t0]
    m_enum = re.match(r"^enum\s+(.+)$", t.strip())
    if m_enum:
        name = m_enum.group(1).strip()
        return "W4" + encode_scoped(name)
    m_cs = re.match(r"^(class|struct|union)\s+(.+)$", t0)
    if m_cs:
        kw = m_cs.group(1)
        name = m_cs.group(2).strip()
        kind_letter = {"class":"V", "struct":"U", "union":"T"}[kw]
        return kind_letter + encode_scoped(name)
    if re.match(r"^[A-Za-z_]\w*(::[A-Za-z_]\w*)*$", t0):
        last = t0.split("::")[-1]
        kind = AGG_KIND_HINT.get(last, "V")
        return kind + encode_scoped(t0)
    raise ValueError(f"Cannot encode type: '{t}'")

def peel_ref_ptr(t: str) -> Tuple[str, str]:
    """
    Split off a trailing reference or pointer from a type string.

    Returns:
        (kind, base)
        kind = '&' | '*' | ''   ('' means neither)
        base = type string without the trailing ref/pointer
    """
    ts = t.strip()
    if ts.endswith("&"): return "&", ts[:-1].strip()
    if ts.endswith("*"): return "*", ts[:-1].strip()
    return "", ts

def pointee_cv_letter(txt: str) -> str:
    """
    Produce the MSVC CV letter for the *pointee* (A/B/C/D) given a textual type.
    A = none, B = const, C = volatile, D = const volatile
    """
    has_c = bool(re.search(r"(^|\s)const(\s|$)", txt))
    has_v = bool(re.search(r"(^|\s)volatile(\s|$)", txt))
    if has_c and has_v: return "D"
    if has_c: return "B"
    if has_v: return "C"
    return "A"

def encode_type(t: str) -> str:
    """Encode a (possibly ref/pointer) type into MSVC x86 mangled form."""
    kind, base = peel_ref_ptr(t)
    base_no_cv = re.sub(r"\bconst\b|\bvolatile\b", "", base).strip()
    base_code = encode_base_or_named(base_no_cv)
    if kind == "&":
        return "A" + pointee_cv_letter(base) + base_code
    if kind == "*":
        return "P" + pointee_cv_letter(base) + base_code
    return base_code


def encode_arglist(params: List[str]) -> str:
    """
    Encode an argument list in MSVC x86 form with backreference compression.

    Rules:
    - "X" if there are no parameters (i.e., `void`).
    - Otherwise, concatenate encoded types and terminate with '@'.
    - If the parameter list is variadic (contains '...'), terminate with 'Z'
      instead of '@'. This matches MSVC/Clang Microsoft ABI:
      empty fixed part + 'Z' encodes e.g. `f(...)`.
    - Repeated types may be encoded as digits "0".."9" that refer to the N‑th
      unique parameter type encountered in this parameter list (0 = first unique type).
    """
    # Detect and strip '...' marker
    is_variadic = any(p.strip() == "..." for p in params)
    fixed = [p for p in params if p.strip() != "..."]

    # No parameters and not variadic => 'X'
    if not fixed and not is_variadic:
        return "X"
    
    # Encode fixed part
    table: List[str] = []
    out: List[str] = []
    for p in fixed:
        enc = encode_type(p)
        try:
            idx = table.index(enc)
        except ValueError:
            idx = -1
        if 0 <= idx <= 9:
            out.append(str(idx))
        else:
            out.append(enc)
            if len(table) < 10:
                table.append(enc)
    # Terminator: '@' for non-variadic, 'Z' for variadic ('...' present)
    return "".join(out) + ("Z" if is_variadic else "@")

# ---- helpers: "is this a member function?" heuristics ----
def looks_like_class(tok: str) -> bool:
    """Heuristic: treat `Ns::Class::func` as member if the penultimate token looks like a type name."""
    return bool(tok) and (tok[0].isupper() or (tok[0]=='I' and len(tok)>1 and tok[1].isupper()))

def detect_member(full_name: str) -> Tuple[bool, str, str]:
    """
    Decide whether `full_name` is `Ns::Class::method` (member) or `Ns::free` (free function).

    Returns:
        (is_member, container, name)
        container = scope without the final identifier
        name = final identifier
    """
    parts = [p for p in full_name.split("::") if p]
    if len(parts)==1:
        return False, "", parts[0]
    if looks_like_class(parts[-2]):
        return True, "::".join(parts[:-1]), parts[-1]
    return False, "::".join(parts[:-1]), parts[-1]

# ---- demangling: types ----
TYPE_DECODE = {v:k for k,v in PRIM.items()}
CV_REF_TXT = {"A":"", "B":"const ", "C":"volatile ", "D":"const volatile "}
CV_PTR_TXT = {"A":"", "B":"const ", "C":"volatile ", "D":"const volatile "}

def decode_scoped(s: str, i: int) -> Tuple[str, int]:
    """
    Decode a scoped name starting at index `i` in the MSVC form and return (fq_name, new_index).
    Consumes leading separators like '@' or '?@' sequences used inside RTTI names.
    """
    # consume leading separators: '@' and '?@' (RTTI may use these between sections)
    while i < len(s):
        if s[i] == '@':
            i += 1
            continue
        if s[i] == '?' and i + 1 < len(s) and s[i + 1] == '@':
            i += 2
            continue
        break

    m = re.match(r"[A-Za-z_]\w*", s[i:])
    if not m:
        raise ValueError(f"bad scoped name {s[i:]}")
    inner = m.group(0)
    i += len(inner)

    outers = []
    while i < len(s) and s[i] == '@':
        if i + 1 < len(s) and s[i + 1] == '@':  # end
            i += 2
            break
        i += 1
        m = re.match(r"[A-Za-z_]\w*", s[i:])
        if not m:
            raise ValueError("bad scoped component")
        outers.append(m.group(0))
        i += len(m.group(0))
        if i >= len(s) or s[i] != '@':
            raise ValueError("bad scoped missing trailing @")
    else:
        raise ValueError("unterminated scoped name")

    fq = "::".join(list(reversed(outers)) + [inner]) if outers else inner
    return fq, i

def decode_templated_named(s: str, i: int) -> Tuple[str, int]:
    """
    Decode a templated named type inside decorated symbols, starting at i:
      ?$Name@<arg1><@><arg2><@>...<@><Scope>@@
    Returns (fully_qualified_name_with_args, new_index).
    """
    # expect '?$'
    if not s.startswith("?$", i):
        raise ValueError("decode_templated_named: not at '?$'")
    i += 2
    # template identifier up to '@'
    j = s.find("@", i)
    if j == -1:
        raise ValueError("decode_templated_named: missing '@' after template name")
    tmpl_name = s[i:j]
    i = j + 1

    # parse args: sequence of MSVC types, separated by one or more '@'
    args = []
    while True:
        t, i = decode_type(s, i)
        args.append(t)
        # consume '@' separators after each arg
        k = i
        while k < len(s) and s[k] == '@':
            k += 1
        # If a scope follows here, args are done.
        try:
            _probe, _ = decode_scoped(s, k)
            i = k
            break
        except Exception:
            i = k
            if i >= len(s):
                break

    # scope (may be empty for local/anonymous, but usually present)
    scope = ""
    if i < len(s):
        scope, i = decode_scoped(s, i)
    fq = f"{scope}::{tmpl_name}" if scope else tmpl_name
    return f"{fq}<{', '.join(args)}>", i

def decode_type(s: str, i: int) -> Tuple[str, int]:
    """
    Decode a type starting at `i` in a mangled string `s`, returning (type_text, new_index).
    Supports references, pointers, enums, classes/structs/unions, and primitives.
    """
    # reference: 'A' + cv + <type>
    if s[i] == 'A' and i+1 < len(s) and s[i+1] in "ABCD":
        cv = s[i+1]; t, j = decode_type(s, i+2)
        return (CV_REF_TXT[cv] + t + "&").replace(" &","&"), j
    # pointer: 'P' + cv + <type>
    if s[i] == 'P' and i+1 < len(s) and s[i+1] in "ABCD":
        cv = s[i+1]; t, j = decode_type(s, i+2)
        return (CV_PTR_TXT[cv] + t + "*"), j
    # enum
    if s[i] == 'W':
        # Optional enum-size byte: W[1|2|4|8]
        j = i + 1
        if j < len(s) and s[j] in "1248":
            j += 1
        name, j = decode_scoped(s, j)
        return f"enum {name}", j
    # class/struct/union by value
    if s[i] in ('V', 'U', 'T'):
        j = i + 1
        # support templated names in function signatures: V?$Name@Args@Scope@@
        if s.startswith("?$", j):
            name, j = decode_templated_named(s, j)
        else:
            name, j = decode_scoped(s, j)
        # Note: return bare qualified name (no 'class/struct' prefix)
        return name, j
    # primitives
    if s[i] == '_' and s[i:i+2] in TYPE_DECODE:
        return TYPE_DECODE[s[i:i+2]], i+2
    if s[i] in TYPE_DECODE:
        return TYPE_DECODE[s[i]], i+1
    raise ValueError(f"unsupported type code at {i}: '{s[i:i+6]}'")

# ---- RTTI (.?A...) ----
def demangle_rtti_type(deco: str) -> str:
    """
    Demangle MSVC RTTI type names that start with '.?A'.
    Examples:
      .?AVClass@Ns@@
      .?AW4Enum@Ns@@
      .?AV?$Stats@VCArmyStatItem@Moho@@@Moho@@
    """
    if not deco.startswith(".?A"):
        return deco

    i = 3  # after ".?A"
    if i >= len(deco): return deco

    kind = deco[i]; i += 1
    kind_word = {"V": "class", "U": "struct", "T": "union", "W": "enum"}.get(kind)
    if not kind_word: return deco

    if kind == "W" and i < len(deco) and deco[i] in "1248":  # enum size
        i += 1

    # ---- template? ----
    if deco.startswith("?$", i):
        i += 2
        j = deco.find("@", i)
        if j == -1: return deco
        tmpl_name = deco[i:j]
        i = j + 1  # first arg

        # parse one or more template args
        args = []
        while True:
            t, j = decode_type(deco, i)
            args.append(t)

            # swallow any '@' between args
            k = j
            while k < len(deco) and deco[k] == '@':
                k += 1

            # If a scope follows, we've reached the end of args.
            try:
                _probe, _ = decode_scoped(deco, k)
                i = k
                break
            except Exception:
                i = k
                if i >= len(deco):
                    break

        # Before scope there might be stray '@' or '?@' — swallow them.
        while i < len(deco):
            if deco[i] == '@':
                i += 1
                continue
            if i + 1 < len(deco) and deco[i] == '?' and deco[i + 1] == '@':
                i += 2
                continue
            break

        scope = ""
        if i < len(deco):
            scope, i = decode_scoped(deco, i)

        fq = f"{scope}::{tmpl_name}" if scope else tmpl_name
        return f"{kind_word} {fq}<{', '.join(args)}>"

    # ---- non-template type ----
    name, _ = decode_scoped(deco, i)
    return f"{kind_word} {name}"

# ---- demangling: decorated symbols (incl. ctor/dtor) ----
def demangle(deco: str) -> str:
    """
    Demangle a decorated MSVC symbol or RTTI type name.
    If the string does not look mangled, it is returned as-is.
    """
    if not deco.startswith("?"):
        if deco.startswith(".?A"):
            return demangle_rtti_type(deco)
        return deco
    
    # Data symbols (globals / static members), layout:
    # ?<name>@<scopes>@@<stor><type-encoding><cv-letter>
    m_data = re.match(r"^\?([^@?]+(?:@[^@?]+)*)@@([0-9])(.*)$", deco)
    if m_data:
        name_seg = m_data.group(1)      # e.g. 'g_Var@Ns2@Ns1'
        stor     = m_data.group(2)      # '3' = global (unused further here)
        rest     = m_data.group(3)

        # split 'inner@outer2@outer1' into a C++-style scope
        parts  = [p for p in name_seg.split('@') if p]
        ident  = parts[0]
        scopes = list(reversed(parts[1:]))
        scope_txt = ("::".join(scopes) + ("::" if scopes else ""))

        # parse type
        t, j = decode_type(rest, 0)
        # trailing CV for variable/pointee (A/B/C/D)
        if j < len(rest) and rest[j:j+1] in ("A","B","C","D"):
            c = rest[j]
            # For pointers/references the CV belongs to the POINTEE — decode_type already handled it.
            if rest and rest[0] not in ('P','A','M'):
                t = CV_PTR_TXT[c] + t
            j += 1

        return f"{t} {scope_txt}{ident}"

    # Constructor: ??0<Class@ns@@><3><@><args>Z
    if deco.startswith("??0"):
        cls, i = decode_scoped(deco, 3)
        prefix = deco[i:i+3]; i += 3
        if i < len(deco) and deco[i] == '@': i += 1
        # args
        args=[]; is_var=False
        if i < len(deco) and deco[i] == 'X':
            i += 1
        else:
            while i < len(deco) and deco[i] not in "@Z":
                t, i = decode_type(deco, i); args.append(t)
            if i < len(deco):
                if deco[i] == 'Z':
                    is_var = True
                i += 1
        if is_var:
            args.append("...")
        cc = CC_MEMBER_NAME.get(prefix[2], None)
        cc_str = f"{cc} " if (cc and prefix[2] != 'E') else ""
        return f"{cc_str}{cls}::{cls.split('::')[-1]}(" + (", ".join(args) if args else "") + ")"

    # Destructor: ??1<Class@ns@@><3><@>XZ
    if deco.startswith("??1"):
        cls, i = decode_scoped(deco, 3)
        prefix = deco[i:i+3]; i += 3
        if i < len(deco) and deco[i] == '@': i += 1
        virt = prefix[0] in ("U","E","I")
        cc = CC_MEMBER_NAME.get(prefix[2], None)
        cc_str = f"{cc} " if (cc and prefix[2] != 'E') else ""
        virt_str = "virtual " if virt else ""
        return f"{virt_str}{cc_str}{cls}::~{cls.split('::')[-1]}()"

    # Deleting destructors
    if deco.startswith("??_G") or deco.startswith("??_E"):
        kind = "scalar deleting destructor" if deco.startswith("??_G") else "vector deleting destructor"
        cls, i = decode_scoped(deco, 4)
        prefix = deco[i:i+3]; i += 3
        if i < len(deco) and deco[i] == '@': i += 1
        args=[]
        if i < len(deco) and deco[i] != '@':
            while i < len(deco) and deco[i] != '@':
                t, i = decode_type(deco, i); args.append(t)
            if i < len(deco) and deco[i] == '@': i += 1
        cc = CC_MEMBER_NAME.get(prefix[2], None)
        cc_str = f"{cc} " if (cc and prefix[2] != 'E') else ""
        return f"void {cc_str}{cls}::`{kind}`(" + (", ".join(args) if args else "") + ")"

    # Regular member methods
    m = re.match(r"^\?([^@?]+)@(.+?)@@([A-Z_]{3})(.+)Z$", deco)
    if m:
        meth = m.group(1)
        scope_raw = m.group(2)
        prefix = m.group(3)
        rest = m.group(4)
        cls = "::".join(reversed(scope_raw.split('@')[:-1]))
        is_const = (prefix[1] == 'B')
        i = 0
        ret, i = decode_type(rest, 0)
        args=[]; is_var=False
        if i < len(rest) and rest[i] == 'X':
            i += 1
        else:
            while i < len(rest) and rest[i] not in "@Z":
                t, i = decode_type(rest, i); args.append(t)
            if i < len(rest):
                if rest[i] == 'Z':
                    is_var = True
                i += 1
        if is_var:
            args.append("...")
        cc = CC_MEMBER_NAME.get(prefix[2], None)
        cc_str = f"{cc} " if (cc and prefix[2] != 'E') else ""
        sig = f"{ret} {cc_str}{cls}::{meth}(" + (", ".join(args) if args else "") + ")"
        if is_const: sig += " const"
        return sig

    # Free functions
    m2 = re.match(r"^\?([^@?]+)@(.+?)@@Y([A-Z_])(.+)Z$", deco)
    if m2:
        fn = m2.group(1)
        scope_raw = m2.group(2)
        call = m2.group(3)
        rest = m2.group(4)
        ns = "::".join(reversed(scope_raw.split('@')[:-1]))
        i = 0
        ret, i = decode_type(rest, 0)
        args=[]; is_var=False
        if i < len(rest) and rest[i] == 'X':
            i += 1
        else:
            while i < len(rest) and rest[i] not in "@Z":
                t, i = decode_type(rest, i); args.append(t)
            if i < len(rest):
                if rest[i] == 'Z':
                    is_var = True
                i += 1
        if is_var:
            args.append("...")
        cc_txt = CC_FREE_NAME.get(call, None)
        cc_str = (cc_txt + " ") if (cc_txt and call != 'A') else ""
        scope = (ns + "::") if ns else ""
        return f"{ret} {cc_str}{scope}{fn}(" + (", ".join(args) if args else "") + ")"

    return deco

# ---- mangling from a single textual signature (incl. ctor/dtor) ----
def mangle_variable(sig: str) -> str:
    """
    Mangle a variable declaration of the form: "<type> <scoped_name>".
    Examples:
        "int g_X"
        "MyNs::CThing* MyNs::g_Ptr"
    """
    m = re.match(r"^\s*(?P<type>.+?)\s+(?P<name>(?:[_A-Za-z]\w*(?:::)*)?[_A-Za-z]\w*)\s*$", sig)
    if not m:
        raise SystemExit("Cannot parse a variable declaration. Expected '<type> <name>'.")
    t    = m.group("type").strip()
    name = m.group("name").strip()

    scope_enc = encode_scoped(name)
    type_enc  = encode_type(t)

    # trailing CV:
    #   - for pointers/references — CV of the pointee,
    #   - otherwise — top‑level CV of the type.
    kind, base = peel_ref_ptr(t)
    cv = pointee_cv_letter(base)
    return f"?{scope_enc}3{type_enc}{cv}"

def mangle_ctor(full: str, cc: str|None, params: str) -> str:
    """
    Mangle a constructor. The input must be 'Ns::Class::Class(...)'.
    CC is optional and defaults to __thiscall.
    """
    parts = [p for p in full.split("::") if p]
    if len(parts) < 2 or parts[-1] != parts[-2]:
        raise SystemExit("Ctor: expected 'Ns::Class::Class(...)'")
    cls = "::".join(parts[:-1])
    scope = encode_scoped(cls)
    call = CC_MEMBER_CODE.get(cc or "__thiscall", "E")
    prefix = "Q" + "A" + call  # public, non-const
    args_code = encode_arglist(split_params(params))
    return f"??0{scope}{prefix}@{args_code}Z"

def mangle_dtor(full: str, cc: str|None, is_virtual: bool) -> str:
    """
    Mangle a destructor. The input must be 'Ns::Class::~Class()'.
    If `is_virtual` is True, the access is encoded as public virtual.
    """
    parts = [p for p in full.split("::") if p]
    if len(parts) < 2 or parts[-1][0] != '~' or parts[-1][1:] != parts[-2]:
        raise SystemExit("Dtor: expected 'Ns::Class::~Class()'")
    cls = "::".join(parts[:-1])
    scope = encode_scoped(cls)
    first = "U" if is_virtual else "Q"  # public virtual / public non-virtual
    call = CC_MEMBER_CODE.get(cc or "__thiscall", "E")
    prefix = first + "A" + call
    return f"??1{scope}{prefix}@XZ"

def mangle_regular(m: re.Match) -> str:
    """
    Mangle a regular function/method parsed by SIG_RE.
    Decides between a member function and a free function form.
    """
    is_virtual = bool(m.group("virtual"))
    is_static  = bool(m.group("static"))
    ret = m.group("ret").strip()
    cc  = (m.group("cc") or "").strip()
    full_name = m.group("name").strip()
    params = split_params(m.group("params"))
    trailing_cv = (m.group("cv") or "").strip()
    is_const_method = trailing_cv.startswith("const")

    ret_code = encode_type(ret)
    args_code = encode_arglist(params)

    is_member, container, meth = detect_member(full_name)

    if is_member:
        # Handle templates in the container scope
        scope = encode_scoped_tpl(container) if ('<' in container and '>' in container) else encode_scoped(container)
        if is_static:
            cv_m = "B" if is_const_method else "A"
            call = CC_FREE_CODE.get(cc or "__cdecl", "A")
            prefix = "S" + cv_m + call
        else:
            first = { (False,"public"): "Q", (False,"protected"): "M", (False,"private"): "A",
                      (True, "public"): "U", (True, "protected"): "E", (True, "private"): "I" }[ (is_virtual, "public") ]
            cv_m = "B" if is_const_method else "A"
            call = CC_MEMBER_CODE.get(cc or "__thiscall", "E")
            prefix = first + cv_m + call
        return f"?{meth}@{scope}{prefix}{ret_code}{args_code}Z"
    else:
        call = CC_FREE_CODE.get(cc or "__cdecl", "A")
        head = (f"?{meth}@{encode_scoped(container)}" if container else f"?{meth}@@")
        return f"{head}Y{call}{ret_code}{args_code}Z"

def mangle_from_signature(sig: str) -> str:
    """
    Entry point for mangling a single signature string.
    Supports:
      - Variable: '<type> <scoped_name>' (no parentheses)
      - Constructor: 'Ns::Class::Class(...)'
      - Destructor: 'Ns::Class::~Class()'
      - Regular function/method: 'ret [CC] Ns::Name(args) [const]'
    """
    if "(" not in sig and ")" not in sig:
        return mangle_variable(sig)
    
    mc = CTOR_RE.match(sig)
    if mc:
        return mangle_ctor(mc.group("name"), mc.group("cc"), mc.group("params") or "")
    md = DTOR_RE.match(sig)
    if md:
        return mangle_dtor(md.group("name"), md.group("cc"), bool(md.group("virtual")))
    m = SIG_RE.match(sig)
    if not m:
        raise SystemExit("Cannot parse signature. Example: 'uint32_t __fastcall f(void*, uint32_t*)' or 'virtual ~C::C()'")
    return mangle_regular(m)

# ---- CLI ----
def main() -> None:
    """
    CLI usage:
      mangle.py "virtual ~CArmyImpl()"
      mangle.py "CArmyImpl(int a)"
      mangle.py "uint32_t __fastcall f(void*, uint32_t*)"
      mangle.py "?Decorated@Name@@..." | ".?AVClass@Ns@@"
    """
    if len(sys.argv) != 2:
        print("Usage:\n  mangle.py \"virtual ~CArmyImpl()\"\n  mangle.py \"CArmyImpl(int a)\"\n  mangle.py \"uint32_t __fastcall f(void*, uint32_t*)\"\n  mangle.py \"?Decorated@Name@@...\" | \".?AVClass@Ns@@\"\n")
        sys.exit(2)
    s = sys.argv[1].strip()
    if s.startswith("?") or s.startswith(".?A"):
        print(demangle(s))
    else:
        print(mangle_from_signature(s))

if __name__ == "__main__":
    main()
