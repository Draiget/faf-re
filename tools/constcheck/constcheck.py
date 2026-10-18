#!/usr/bin/env python3
"""
constcheck - cross-check recovered C++ against the retail binary for
replay-determinism hazards.

Two modes, both keyed on the Doxygen `Address: 0xXXXXXXXX` block that sits
above every recovered definition in src/sdk:

  consts (default)
      For each definition, collect every float/double constant the retail
      function reads from a read-only PE section (`movss xmm0, dword ptr
      [0xdff0ac]`, `fmul qword ptr [0xe4f7e0]`, `comiss ...`, `fld ...`),
      read its bit pattern from the PE, and compare against the float
      literals the C++ body can produce (direct literals, folded
      literal-only subexpressions, named constants anywhere in src/sdk,
      Wm3::Math constants). Reports:
        NEAR       retail constant with a C++ literal a few ulps away
                   (0.01f = 0x3C23D70A written where retail loads 0x3C23D70B)
        TYPE       retail loads a double where C++ only has the float (or
                   vice versa) - a precision-of-computation difference
        MISSING    retail constant with no counterpart in the body
        INLINED?   no counterpart in the body, but an included header has
                   the bit pattern (likely an inlined helper)
        UNLOADED   C++ float literal (not 0/+-1) that retail never loads
                   nor stores as an immediate

  math
      For each definition, list the libm calls in the C++ body
      (std::sin, sinf, Wm3::Math<float>::Sin, msvc8::sin, ...) next to what
      the retail asm does (inline x87 fsin/fcos/fpatan/fsqrt/fyl2x/...,
      CRT calls by name, SSE sqrtss) and flag the combinations that are
      known to diverge.

Usage
  python tools/constcheck/constcheck.py [--mode consts|math] [options] PATH...
    PATH        .cpp/.h files or directories (recursed)
    --pe        retail PE (default C:/ProgramData/FAForever/bin/ForgedAlliance.exe)
    --asm-dir   IDA/capstone export dir (default decomp/recovery/disasm/fa_full_2026_03_26)
    --json      machine-readable output
    --all       also print functions with no findings (consts mode)
    --no-unloaded / --no-weak   suppress UNLOADED / INLINED?+MISSING-via-mov noise

Example
  python tools/constcheck/constcheck.py src/sdk/moho/sim src/sdk/moho/unit
  python tools/constcheck/constcheck.py --mode math src/sdk/moho/ai
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import struct
import sys
from fractions import Fraction

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_PE = r"C:/ProgramData/FAForever/bin/ForgedAlliance.exe"
DEFAULT_ASM = os.path.join(REPO, "decomp", "recovery", "disasm", "fa_full_2026_03_26")
SDK = os.path.join(REPO, "src", "sdk")

# --------------------------------------------------------------------------
# IEEE helpers
# --------------------------------------------------------------------------


def f32_bits(x: float) -> int:
    return struct.unpack("<I", struct.pack("<f", x))[0]


def f64_bits(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def bits_f32(b: int) -> float:
    return struct.unpack("<f", struct.pack("<I", b))[0]


def bits_f64(b: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", b))[0]


def round_f32(q: Fraction) -> float:
    """Correctly rounded (ties-to-even) Fraction -> binary32, as a Python float."""
    if q == 0:
        return 0.0
    neg = q < 0
    q = -q if neg else q
    e = q.numerator.bit_length() - q.denominator.bit_length()
    if Fraction(2) ** e > q:
        e -= 1
    while Fraction(2) ** (e + 1) <= q:
        e += 1
    e = max(e, -126)
    scale = Fraction(2) ** (e - 23)
    s = q / scale
    m = s.numerator // s.denominator
    rem = s - m
    if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and (m & 1)):
        m += 1
    v = Fraction(m) * scale
    if v >= Fraction(2) ** 128 - Fraction(2) ** 103:  # rounds to infinity
        out = math.inf
    else:
        out = float(v)  # exact: v is a binary32 value
    return -out if neg else out


def round_f64(q: Fraction) -> float:
    try:
        return float(q)  # Fraction.__float__ is correctly rounded
    except OverflowError:
        return math.inf if q > 0 else -math.inf


def ulp_distance32(a: int, b: int) -> int:
    def key(x):
        return x if x < 0x80000000 else -(x & 0x7FFFFFFF)
    return abs(key(a) - key(b))


def ulp_distance64(a: int, b: int) -> int:
    def key(x):
        return x if x < (1 << 63) else -(x & ((1 << 63) - 1))
    return abs(key(a) - key(b))


def fmt32(b: int) -> str:
    return f"0x{b:08X}({bits_f32(b)!r}f)"


def fmt64(b: int) -> str:
    return f"0x{b:016X}({bits_f64(b)!r})"


# --------------------------------------------------------------------------
# PE
# --------------------------------------------------------------------------


class PE:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        self.base = struct.unpack_from("<I", d, pe + 24 + 28)[0]
        self.sections = []
        off = pe + 24 + optsz
        for i in range(nsec):
            name = d[off:off + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", d, off + 8)
            ch = struct.unpack_from("<I", d, off + 36)[0]
            self.sections.append((name, self.base + va, max(vsize, rawsz), rawptr, rawsz, ch))
            off += 40

    def section_of(self, va: int):
        for s in self.sections:
            if s[1] <= va < s[1] + s[2]:
                return s
        return None

    def is_readonly_data(self, va: int) -> bool:
        s = self.section_of(va)
        if not s:
            return False
        ch = s[5]
        return not (ch & 0x80000000) and not (ch & 0x20000000)  # !WRITE, !EXECUTE

    def read(self, va: int, n: int):
        s = self.section_of(va)
        if not s:
            return None
        rel = va - s[1]
        if rel + n > s[4]:
            return None
        return self.data[s[3] + rel:s[3] + rel + n]


# --------------------------------------------------------------------------
# asm
# --------------------------------------------------------------------------

ASM_LINE = re.compile(r"^0x([0-9A-Fa-f]+):\s+([0-9A-F]{2}(?: [0-9A-F]{2})*)\s+(\S+)\s*(.*?)\s*$")
ABS_MEM = re.compile(r"\b(dword|qword|tbyte|xmmword) ptr \[0x([0-9a-f]+)\]")
IMM32 = re.compile(r"(?:,\s*|^)0x([0-9a-f]{6,8})\b")

SSE_F32 = {"movss", "addss", "subss", "mulss", "divss", "comiss", "ucomiss", "maxss", "minss",
           "sqrtss", "cvtss2sd", "rcpss", "rsqrtss", "cmpss", "cmpltss", "cmpless", "cmpeqss",
           "cmpnltss", "cmpnless", "cmpneqss"}
SSE_F64 = {"movsd", "addsd", "subsd", "mulsd", "divsd", "comisd", "ucomisd", "maxsd", "minsd",
           "sqrtsd", "cvtsd2ss"}
SSE_PS = {"movaps", "movups", "mulps", "addps", "subps", "divps", "maxps", "minps", "cmpps"}
X87 = {"fld", "fmul", "fadd", "fsub", "fsubr", "fdiv", "fdivr", "fcom", "fcomp"}
MOVISH = {"mov", "push"}


IDA_MEM = re.compile(r"(?:\b(byte|word|dword|qword|tbyte|xmmword) ptr )?ds:([A-Za-z_@?$][\w@?$]*)(?:\+[0-9A-Fa-f]+h?)?")
IDA_NAME_SIZE = (("flt_", "dword"), ("dword_", "dword"), ("dbl_", "qword"), ("qword_", "qword"),
                 ("xmmword_", "xmmword"), ("tbyte_", "tbyte"))


def _ida_operand_size(explicit, name, mnem, raw):
    if explicit:
        return explicit
    for prefix, size in IDA_NAME_SIZE:
        if name.startswith(prefix):
            return size
    rm = re.match(r"__real@([0-9a-f]+)$", name)
    if rm:
        return "dword" if len(rm.group(1)) == 8 else "qword"
    if mnem.endswith("ss") or mnem in ("comiss", "ucomiss", "cvtss2sd") or mnem in MOVISH:
        return "dword"
    if mnem.endswith("sd") or mnem in ("cvtsd2ss",):
        return "qword"
    if mnem.endswith("ps"):
        return "xmmword"
    if mnem.startswith("f") and raw:
        op = next((b for b in raw if b not in (0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65, 0x66, 0x67)), 0)
        return {0xD8: "dword", 0xD9: "dword", 0xDC: "qword", 0xDD: "qword", 0xDB: "tbyte"}.get(op, "dword")
    return "dword"


def normalize_ida_operands(mnem: str, ops: str, raw: bytes) -> str:
    """Rewrite IDA-style text (`ds:flt_DFEB0C`, `3F800000h`, `loc_57A678`) into
    the capstone form the rest of the tool parses. The absolute address comes
    from the instruction's disp32 bytes, not from the (arbitrary) IDA name."""
    def mem(m):
        windows = [struct.unpack_from("<I", raw, k)[0] for k in range(0, max(0, len(raw) - 3))]
        windows = [w for w in windows if 0x00400000 <= w < 0x02000000]
        if not windows:
            return m.group(0)
        name = m.group(2)
        pick = next((w for w in windows if f"{w:X}" in name.upper()), windows[-1])
        size = _ida_operand_size(m.group(1), name, mnem, raw)
        return f"{size} ptr [0x{pick:x}]"
    if "ds:" in ops:
        ops = IDA_MEM.sub(mem, ops)
    ops = re.sub(r"\b(?:short |near ptr )?(?:loc|sub|j_sub|locret|nullsub)_([0-9A-F]+)\b",
                 lambda m: f"0x{int(m.group(1), 16):x}", ops)
    ops = re.sub(r"(?<![\w$])([0-9][0-9A-F]*)h\b", lambda m: f"0x{int(m.group(1), 16):x}", ops)
    return ops


class AsmFunc:
    def __init__(self, path: str):
        self.path = path
        self.insns = []  # (addr, mnem, ops)
        self.raw = {}  # addr -> instruction bytes
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = ASM_LINE.match(line)
                if m:
                    mn, ops = m.group(3), m.group(4)
                    if "ds:" in ops or re.search(r"[0-9A-F]h\b|loc_|sub_", ops):
                        ops = normalize_ida_operands(mn, ops, bytes.fromhex(m.group(2).replace(" ", "")))
                    self.insns.append((int(m.group(1), 16), mn, ops))
                    self.raw[int(m.group(1), 16)] = bytes.fromhex(m.group(2).replace(" ", ""))
        # The capstone export sometimes runs past the function into the next
        # one; cut at a `ret`/`jmp` followed by an address with its own export.
        d = os.path.dirname(path)
        last = self.insns[-1][0] if self.insns else 0
        has_table = any(mn == "jmp" and "ptr [" in ops for _, mn, ops in self.insns)
        targets = []
        for _, mn, ops in self.insns:
            if mn.startswith("j"):
                tm = re.match(r"0x([0-9a-f]+)", ops)
                if tm:
                    targets.append(int(tm.group(1), 16))
        for k in range(1, len(self.insns)):
            prev_addr, prev_mn, _ = self.insns[k - 1]
            if prev_mn not in ("ret", "jmp"):
                continue
            here = self.insns[k][0]
            if os.path.exists(os.path.join(d, f"FUN_{here:08X}.asm")) or \
                    (prev_mn == "ret" and not has_table and not any(here <= t <= last for t in targets)):
                self.insns = self.insns[:k]
                break


_asm_cache: dict = {}


def load_asm(asm_dir: str, addr: int):
    if addr in _asm_cache:
        return _asm_cache[addr]
    p = os.path.join(asm_dir, f"FUN_{addr:08X}.asm")
    r = AsmFunc(p) if os.path.exists(p) else None
    _asm_cache[addr] = r
    return r


_meta_name_cache: dict = {}


def callee_name(asm_dir: str, addr: int) -> str:
    if addr in _meta_name_cache:
        return _meta_name_cache[addr]
    name = ""
    p = os.path.join(asm_dir, f"FUN_{addr:08X}.meta.json")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(2000)
        m = re.search(r'"name":\s*"([^"]*)"', head)
        if m:
            name = m.group(1)
    _meta_name_cache[addr] = name
    return name


def retail_constants(pe: PE, fn: AsmFunc):
    """-> list of dicts {kind: f32|f64|f80, bits, va, insn, mnem, weak}"""
    out = []
    seen = set()
    for ia, mn, ops in fn.insns:
        for m in ABS_MEM.finditer(ops):
            size, va = m.group(1), int(m.group(2), 16)
            if not pe.is_readonly_data(va):
                continue
            weak = False
            if mn in SSE_F32 or (mn in X87 and size == "dword"):
                kinds = [("f32", 4)]
            elif mn in SSE_F64 or (mn in X87 and size == "qword"):
                kinds = [("f64", 8)]
            elif mn in X87 and size == "tbyte":
                kinds = [("f80", 10)]
            elif mn in SSE_PS and size == "xmmword":
                raw = pe.read(va, 16)
                if raw is None:
                    continue
                for lane in range(4):
                    b = struct.unpack_from("<I", raw, lane * 4)[0]
                    if (b & 0x7F800000) == 0x7F800000 or b in (0x80000000,):
                        continue
                    key = (va + lane * 4, "f32")
                    if key not in seen:
                        seen.add(key)
                        out.append(dict(kind="f32", bits=b, va=va + lane * 4, insn=ia, mnem=mn, weak=False))
                continue
            elif mn in MOVISH and size == "dword":
                raw = pe.read(va, 4)
                if raw is None:
                    continue
                b = struct.unpack("<I", raw)[0]
                e = (b >> 23) & 0xFF
                if b in (0, 0x80000000) or not (127 - 40 <= e <= 127 + 40):
                    continue
                kinds = [("f32", 4)]
                weak = True
            else:
                continue
            for kind, n in kinds:
                key = (va, kind)
                if key in seen:
                    continue
                raw = pe.read(va, n)
                if raw is None:
                    continue
                seen.add(key)
                if kind == "f32":
                    b = struct.unpack("<I", raw)[0]
                elif kind == "f64":
                    b = struct.unpack("<Q", raw)[0]
                else:
                    b = int.from_bytes(raw, "little")
                out.append(dict(kind=kind, bits=b, va=va, insn=ia, mnem=mn, weak=weak))
    # FLT_MAX loaded as the target of `ucomiss d, 0; lahf; test ah, 0x44; jnp`:
    # the zero-divisor branch of an inlined Wm3 `Vector / scalar`.
    targets = {int(m.group(1), 16) for _, mn, ops in fn.insns if mn == "jnp"
               for m in [re.match(r"0x([0-9a-f]+)", ops)] if m}
    for rc in out:
        rc["divguard"] = rc["kind"] == "f32" and rc["bits"] == 0x7F7FFFFF and rc["insn"] in targets
    return out


def retail_immediates(fn: AsmFunc):
    s = set()
    for ia, mn, ops in fn.insns:
        if mn in ("mov", "push", "cmp"):
            for m in IMM32.finditer(ops):
                s.add(int(m.group(1), 16))
    return s


def f80_to_fraction(b: int):
    mant = b & ((1 << 64) - 1)
    exp = (b >> 64) & 0x7FFF
    sign = (b >> 79) & 1
    if exp == 0x7FFF:
        return None
    v = Fraction(mant) * Fraction(2) ** (exp - 16383 - 63)
    return -v if sign else v


# --------------------------------------------------------------------------
# C++ scanning
# --------------------------------------------------------------------------


def strip_cpp(text: str) -> str:
    """Blank comments, string and char literals, preserving offsets/newlines."""
    out = list(text)
    i, n = 0, len(text)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == '"':
            # raw string?
            if i > 0 and text[i - 1] == "R":
                m = re.match(r'"([^(\s]*)\(', text[i:])
                if m:
                    endtok = ")" + m.group(1) + '"'
                    j = text.find(endtok, i)
                    j = n if j < 0 else j + len(endtok)
                    blank(i, j)
                    i = j
                    continue
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            blank(i, min(j + 1, n))
            i = j + 1
        elif c == "'":
            m = re.match(r"'(\\.[^']*|[^\\'\n])'", text[i:])
            if m and not (i > 0 and text[i - 1].isalnum()):
                blank(i, i + m.end())
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


NUM_RE = re.compile(
    r"(?<![\w.])("
    r"0[xX](?:[0-9a-fA-F]+\.?[0-9a-fA-F]*|\.[0-9a-fA-F]+)[pP][+-]?\d+[fFlL]?"
    r"|0[xX][0-9a-fA-F]+[uUlL]*"
    r"|(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?[fFlL]?"
    r"|\d+[eE][+-]?\d+[fFlL]?"
    r"|\d+[uUlL]*"
    r")(?![\w.])"
)
TOKEN_RE = re.compile(
    NUM_RE.pattern + r"|(static_cast\s*<\s*(?:float|double)\s*>)|(\(\s*(?:float|double)\s*\))|([A-Za-z_]\w*)|(::|[-+*/()\[\]<>,;{}=?:!&|^%~.])"
)


class Lit:
    """A typed C++ constant value. kind: f32 | f64 | int; val: Fraction."""
    __slots__ = ("kind", "val", "text", "direct", "hexbits")

    def __init__(self, kind, val, text="", direct=False, hexbits=None):
        self.kind, self.val, self.text, self.direct, self.hexbits = kind, val, text, direct, hexbits

    def as_f32_bits(self):
        return f32_bits(round_f32(self.val))

    def as_f64_bits(self):
        return f64_bits(round_f64(self.val))


def parse_literal(tok: str):
    t = tok
    if re.match(r"0[xX][0-9a-fA-F]*\.?[0-9a-fA-F]*[pP]", t):
        suf = t[-1] if t[-1] in "fFlL" else ""
        body = t[:-1] if suf else t
        m = re.match(r"0[xX]([0-9a-fA-F]*)\.?([0-9a-fA-F]*)[pP]([+-]?\d+)", body)
        ip, fp, ex = m.group(1) or "0", m.group(2) or "", int(m.group(3))
        val = Fraction(int(ip + fp, 16)) * Fraction(2) ** (ex - 4 * len(fp))
        kind = "f32" if suf in "fF" and suf else "f64"
        v = round_f32(val) if kind == "f32" else round_f64(val)
        return Lit(kind, Fraction(v), tok, True)
    if re.match(r"0[xX][0-9a-fA-F]+[uUlL]*$", t):
        hexd = re.sub(r"[uUlL]+$", "", t)
        iv = int(hexd, 16)
        return Lit("int", Fraction(iv), tok, True, hexbits=iv if len(hexd) >= 8 else None)
    if re.match(r"\d+[uUlL]*$", t):
        return Lit("int", Fraction(int(re.sub(r"[uUlL]+$", "", t))), tok, True)
    suf = t[-1] if t[-1] in "fFlL" else ""
    body = t[:-1] if suf else t
    val = Fraction(body)  # exact decimal
    if suf in ("f", "F"):
        return Lit("f32", Fraction(round_f32(val)), tok, True)
    return Lit("f64", Fraction(round_f64(val)), tok, True)


def arith(a: Lit, op: str, b: Lit):
    if op == "/" and b.val == 0:
        return None
    x = {"+": a.val + b.val, "-": a.val - b.val, "*": a.val * b.val, "/": a.val / b.val if b.val else None}[op]
    kinds = {a.kind, b.kind}
    if "f64" in kinds:
        k = "f64"
    elif "f32" in kinds:
        k = "f32"
    else:
        if op == "/":
            if b.val == 0:
                return None
            q = abs(a.val.numerator * b.val.denominator) // abs(a.val.denominator * b.val.numerator)
            x = Fraction(q if (a.val >= 0) == (b.val > 0) else -q)
        k = "int"
    if k == "f32":
        x = Fraction(round_f32(x)) if math.isfinite(round_f32(x)) else None
    elif k == "f64":
        r = round_f64(x)
        x = Fraction(r) if math.isfinite(r) else None
    if x is None:
        return None
    return Lit(k, x)


WM3 = {}


def _init_wm3():
    pi32 = round_f32(Fraction(4.0 * math.atan(1.0)))
    P = Fraction(pi32)
    f = lambda q: Lit("f32", Fraction(round_f32(q)))
    WM3.update({
        "PI": f(P), "TWO_PI": f(2 * P), "HALF_PI": f(Fraction(1, 2) * P), "INV_PI": f(1 / P),
        "INV_TWO_PI": f(1 / Fraction(round_f32(2 * P))), "DEG_TO_RAD": f(P / 180), "RAD_TO_DEG": f(180 / P),
        "ZERO_TOLERANCE": f(Fraction("1e-06")), "EPSILON": Lit("f32", Fraction(bits_f32(0x34000000))),
        "MAX_REAL": Lit("f32", Fraction(bits_f32(0x7F7FFFFF))),
        "FLT_EPSILON": Lit("f32", Fraction(bits_f32(0x34000000))),
        "FLT_MAX": Lit("f32", Fraction(bits_f32(0x7F7FFFFF))),
        "FLT_MIN": Lit("f32", Fraction(bits_f32(0x00800000))),
        "M_PI": Lit("f64", Fraction(math.pi)),
    })


_init_wm3()


class Evaluator:
    """Recursive-descent evaluator for literal/named-constant expressions."""

    def __init__(self, toks, names):
        self.t, self.i, self.names = toks, 0, names

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expr(self):
        v = self.term()
        while v is not None and self.peek() in ("+", "-"):
            op = self.take()
            r = self.term()
            v = arith(v, op, r) if r is not None else None
        return v

    def term(self):
        v = self.unary()
        while v is not None and self.peek() in ("*", "/"):
            op = self.take()
            r = self.unary()
            v = arith(v, op, r) if r is not None else None
        return v

    def unary(self):
        tok = self.peek()
        if tok == "-":
            self.take()
            v = self.unary()
            return Lit(v.kind, -v.val) if v else None
        if tok == "+":
            self.take()
            return self.unary()
        if tok in ("(float)", "(double)") or (tok and tok.startswith("static_cast")) or tok in ("float", "double"):
            self.take()
            target = "f32" if "float" in tok else "f64"
            v = self.unary()
            if v is None:
                return None
            r = round_f32(v.val) if target == "f32" else round_f64(v.val)
            return Lit(target, Fraction(r)) if math.isfinite(r) else None
        return self.primary()

    def primary(self):
        tok = self.take()
        if tok is None:
            return None
        if tok == "(":
            v = self.expr()
            if self.take() != ")":
                return None
            return v
        if NUM_RE.fullmatch(tok):
            try:
                return parse_literal(tok)
            except Exception:
                return None
        if re.match(r"[A-Za-z_]\w*$", tok):
            # qualified name: skip A::B<...>::C ; keep last identifier
            name = tok
            while self.peek() in ("::", "<"):
                if self.peek() == "<":
                    depth = 0
                    while self.peek() is not None:
                        x = self.take()
                        depth += x == "<"
                        depth -= x == ">"
                        if depth == 0:
                            break
                else:
                    self.take()
                    nxt = self.take()
                    if nxt is None:
                        return None
                    name = nxt
            if self.peek() == "(":  # numeric_limits<float>::max() etc
                self.take()
                if self.take() != ")":
                    return None
                return {"max": WM3["FLT_MAX"], "epsilon": WM3["FLT_EPSILON"], "min": WM3["FLT_MIN"],
                        "lowest": Lit("f32", -WM3["FLT_MAX"].val)}.get(name)
            vals = self.names.get(name)
            if vals and len(vals) == 1:
                return next(iter(vals))
            return None
        return None


def tokenize(stripped: str):
    toks = []
    for m in TOKEN_RE.finditer(stripped):
        s = m.group(0)
        if s.startswith("static_cast"):
            s = "static_cast<float>" if "float" in s else "static_cast<double>"
        elif s.startswith("(") and len(s) > 1:
            s = "(float)" if "float" in s else "(double)"
        toks.append(s)
    return toks


CONST_DEF_RE = re.compile(
    r"\b(?:constexpr|const)\s+(?:static\s+|inline\s+)*(float|double|auto|long\s+double|"
    r"(?:std::)?u?int(?:8|16|32|64)?(?:_t)?|unsigned(?:\s+int)?|long|short)\s+(\w+)\s*"
    r"(\[[^\]]*\])?\s*(?:=\s*|(?=\{))([^;]+);"
)
DEFINE_RE = re.compile(r"^\s*#\s*define\s+(\w+)\s+(.+)$", re.M)


def collect_named(stripped: str, names: dict):
    """name -> set of Lit (multiple definitions keep all)."""
    for m in CONST_DEF_RE.finditer(stripped):
        typ, name, arr, rhs = m.group(1), m.group(2), m.group(3), m.group(4)
        t0 = "double" if typ.startswith("long") and "double" in typ else typ.split()[0]
        target = {"float": "f32", "double": "f64", "auto": None}.get(t0, "int")
        if arr or rhs.strip().startswith("{"):
            parts = rhs.strip().strip("{}").split(",")
        else:
            parts = [rhs]
        for part in parts:
            toks = tokenize(part)
            if not toks:
                continue
            ev = Evaluator(toks, names)
            try:
                v = ev.expr()
            except Exception:
                v = None
            if v is None or ev.i != len(toks):
                continue
            if target == "f32":
                r = round_f32(v.val)
                v = Lit("f32", Fraction(r)) if math.isfinite(r) else None
            elif target == "f64":
                v = Lit("f64", Fraction(round_f64(v.val)))
            elif target == "int" and v.kind != "int":
                continue
            if v is not None:
                names.setdefault(name, set()).add(v)
    for m in DEFINE_RE.finditer(stripped):
        name, rhs = m.group(1), m.group(2).strip()
        toks = tokenize(rhs)
        if not toks:
            continue
        ev = Evaluator(toks, names)
        try:
            v = ev.expr()
        except Exception:
            v = None
        if v is not None and ev.i == len(toks):
            names.setdefault(name, set()).add(v)


ADDR_LINE_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{6,8})")


def find_definitions(text: str, stripped: str):
    """Yield (addresses, line, region_start, region_end) for each Address block
    followed by a definition with a body."""
    blocks = []
    for m in re.finditer(r"/\*.*?\*/", text, re.S):
        body = m.group(0)
        if "Address:" not in body:
            continue
        addrs = []
        for line in body.splitlines():
            am = re.match(r"\s*\*?\s*Address:\s*0x([0-9A-Fa-f]{6,8})", line)
            if am:
                addrs.append(int(am.group(1), 16))
        if addrs:
            blocks.append((m.start(), m.end(), addrs))
    starts = [b[0] for b in blocks]
    n = len(stripped)
    for bi, (bs, be, addrs) in enumerate(blocks):
        limit = starts[bi + 1] if bi + 1 < len(blocks) else n
        i = be
        depth = 0
        body_start = None
        region_end = None
        while i < limit:
            c = stripped[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == ";" and depth == 0:
                break
            elif c == "{" and depth == 0:
                # match braces
                d, j = 0, i
                while j < n:
                    if stripped[j] == "{":
                        d += 1
                    elif stripped[j] == "}":
                        d -= 1
                        if d == 0:
                            break
                    j += 1
                k = j + 1
                while k < n and stripped[k] in " \t\r\n":
                    k += 1
                if k < n and stripped[k] in ",{" and body_start is None:
                    # brace initializer in a ctor init-list
                    i = k
                    continue
                body_start = i
                region_end = j + 1
                break
            i += 1
        if body_start is None:
            continue
        line = text.count("\n", 0, be) + 2
        yield addrs, line, be, region_end


def body_lits(stripped_region: str, names: dict):
    """-> (direct literal list, candidate Lit list)"""
    toks = tokenize(stripped_region)
    direct, cands = [], []
    for k, tok in enumerate(toks):
        if NUM_RE.fullmatch(tok):
            try:
                L = parse_literal(tok)
            except Exception:
                continue
            # skip array subscripts / template args / shifts heuristically? keep all for matching
            direct.append(L)
            cands.append(L)
        elif re.match(r"[A-Za-z_]\w*$", tok):
            if tok in names:
                cands.extend(names[tok])
            if tok in WM3:
                cands.append(WM3[tok])
    for m in re.finditer(r"numeric_limits\s*<\s*(float|double)\s*>\s*::\s*(\w+)", stripped_region):
        b32 = {"max": 0x7F7FFFFF, "min": 0x00800000, "epsilon": 0x34000000, "denorm_min": 1}
        b64 = {"max": 0x7FEFFFFFFFFFFFFF, "min": 0x0010000000000000, "epsilon": 0x3CB0000000000000, "denorm_min": 1}
        kind, what = m.group(1), m.group(2)
        neg = what == "lowest"
        what = "max" if neg else what
        if kind == "float" and what in b32:
            v = Fraction(bits_f32(b32[what]))
            cands.append(Lit("f32", -v if neg else v))
        elif kind == "double" and what in b64:
            v = Fraction(bits_f64(b64[what]))
            cands.append(Lit("f64", -v if neg else v))
    # fold literal-only subexpressions: try evaluating from every start token
    for k, tok in enumerate(toks):
        if tok in ("(", "-") or NUM_RE.fullmatch(tok) or tok in names or tok in WM3 or \
                tok.startswith("static_cast") or tok in ("(float)", "(double)"):
            ev = Evaluator(toks[k:k + 40], names)
            try:
                v = ev.term() if tok != "(" else ev.expr()
            except Exception:
                v = None
            if v is not None and ev.i > 1:
                cands.append(v)
    return direct, cands


INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.M)


def resolve_include(inc: str, cur: str):
    for base in (os.path.dirname(cur), SDK):
        p = os.path.normpath(os.path.join(base, inc))
        if os.path.exists(p):
            return p
    return None


# --------------------------------------------------------------------------
# global index
# --------------------------------------------------------------------------


class Index:
    def __init__(self):
        self.names: dict = {}
        self.file_bits: dict = {}  # path -> set of ("f32"/"f64", bits)
        self.stripped: dict = {}
        self.text: dict = {}

    def load(self, path):
        if path in self.stripped:
            return self.stripped[path]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                t = f.read()
        except OSError:
            t = ""
        s = strip_cpp(t)
        self.text[path] = t
        self.stripped[path] = s
        return s

    def build(self, roots):
        files = []
        for r in roots:
            for dp, dn, fn in os.walk(r):
                for f in fn:
                    if f.endswith((".h", ".cpp", ".inl")):
                        files.append(os.path.join(dp, f))
        for p in files:
            collect_named(self.load(p), self.names)
        # second pass resolves names defined in terms of other names
        for p in files:
            collect_named(self.stripped[p], self.names)
        for p in files:
            bits = set()
            for m in NUM_RE.finditer(self.stripped[p]):
                try:
                    L = parse_literal(m.group(1))
                except Exception:
                    continue
                if L.kind == "int":
                    continue
                bits.add(("f32", L.as_f32_bits()))
                bits.add(("f64", L.as_f64_bits()))
            self.file_bits[p] = bits
        self.func_bits: dict = {}   # short function name -> set of (kind, bits)
        self.func_calls: dict = {}  # short function name -> set of called short names
        for p in files:
            self._index_functions(self.stripped[p])

    _KEYWORDS = {"if", "while", "for", "switch", "catch", "return", "sizeof", "decltype", "alignof",
                 "static_assert", "defined", "__asm", "do", "else"}
    _DEF_RE = re.compile(r"\b(~?\w+)\s*\(([^;{}()]|\([^;{}()]*\))*\)\s*(?:const\s*)?(?:noexcept\s*)?"
                         r"(?:override\s*)?(?:final\s*)?(?:->\s*[\w:<>\s*&]+)?(?::[^;{}]*)?\{")
    _CALL_RE = re.compile(r"\b(\w+)\s*(?:<[^<>;(){}]*>)?\s*\(")

    def _index_functions(self, s: str):
        n = len(s)
        pos = 0
        while True:
            m = self._DEF_RE.search(s, pos)
            if not m:
                break
            name = m.group(1)
            j = m.end() - 1
            if name in self._KEYWORDS:
                pos = m.end()
                continue
            d, k = 0, j
            while k < n:
                ch = s[k]
                if ch == "{":
                    d += 1
                elif ch == "}":
                    d -= 1
                    if d == 0:
                        break
                k += 1
            body = s[m.start():k + 1]
            bits = self.func_bits.setdefault(name, set())
            for lm in NUM_RE.finditer(body):
                try:
                    L = parse_literal(lm.group(1))
                except Exception:
                    continue
                if L.kind == "int":
                    continue
                for v in (L.val, -L.val):
                    bits.add(("f32", f32_bits(round_f32(v))))
                    bits.add(("f64", f64_bits(round_f64(v))))
            if re.search(r"numeric_limits\s*<\s*float\s*>\s*::\s*(max|lowest)|FLT_MAX|MAX_REAL", body):
                bits.add(("f32", 0x7F7FFFFF))
                bits.add(("f32", 0xFF7FFFFF))
            for im in re.finditer(r"\b[A-Za-z_]\w*\b", body):
                wm3 = [WM3[im.group(0)]] if im.group(0) in WM3 else []
                for L in list(self.names.get(im.group(0), ()) or ()) + wm3:
                    for v in (L.val, -L.val):
                        bits.add(("f32", f32_bits(round_f32(v))))
                        bits.add(("f64", f64_bits(round_f64(v))))
            calls = self.func_calls.setdefault(name, set())
            for cm in self._CALL_RE.finditer(body, m.end() - m.start()):
                if cm.group(1) not in self._KEYWORDS:
                    calls.add(cm.group(1))
            # nested definitions (lambdas, local classes) are rare; resume after the header
            pos = m.end()

    def callee_bits(self, region: str, depth=4):
        """(kind,bits) -> callee name, for functions called from region (transitively)."""
        out = {}
        frontier = {cm.group(1) for cm in self._CALL_RE.finditer(region) if cm.group(1) not in self._KEYWORDS}
        seen = set()
        for _ in range(depth):
            nxt = set()
            for nm in frontier:
                if nm in seen:
                    continue
                seen.add(nm)
                for kb in self.func_bits.get(nm, ()):
                    out.setdefault(kb, nm)
                nxt |= self.func_calls.get(nm, set())
            frontier = nxt
        return out

    def include_closure(self, path, depth=3):
        seen, frontier = set(), [path]
        for _ in range(depth):
            nxt = []
            for p in frontier:
                txt = self.text.get(p)
                if txt is None:
                    self.load(p)
                    txt = self.text[p]
                for m in INCLUDE_RE.finditer(txt):
                    q = resolve_include(m.group(1), p)
                    if q and q not in seen and q != path:
                        seen.add(q)
                        nxt.append(q)
            frontier = nxt
        return seen


# --------------------------------------------------------------------------
# consts mode
# --------------------------------------------------------------------------

TRIVIAL = {Fraction(0), Fraction(1), Fraction(-1)}


def check_consts(path, idx: Index, pe: PE, asm_dir, opts):
    text = idx.text.get(path)
    if text is None:
        idx.load(path)
        text = idx.text[path]
    stripped = idx.stripped[path]
    results = []
    inc_bits = None
    for addrs, line, rs, re_ in find_definitions(text, stripped):
        fns = [load_asm(asm_dir, a) for a in addrs]
        fns = [f for f in fns if f]
        if not fns:
            continue
        rconsts, imms, stale_notes = [], set(), []
        for f in fns:
            rconsts += retail_constants(pe, f)
            stale = [a for a, _, _ in f.insns if pe.read(a, len(f.raw[a])) != f.raw[a]]
            if stale:
                stale_notes.append(f"export {os.path.basename(f.path)} differs from the PE at {len(stale)} "
                                   f"instruction(s), first 0x{stale[0]:08X} (patched exe; trust the PE)")
            imms |= retail_immediates(f)
        direct, cands = body_lits(stripped[rs:re_], idx.names)
        c32, c64, c32_from_f64, c64_from_f32 = set(), set(), {}, {}
        for L in cands:
            for sgn in (1, -1):
                v = L.val * sgn
                b32 = f32_bits(round_f32(v))
                b64 = f64_bits(round_f64(v))
                if L.kind == "f32":
                    c32.add(b32)
                    c64_from_f32[b64] = L  # widened float
                elif L.kind == "f64":
                    c64.add(b64)
                    c32_from_f64[b32] = L
                else:
                    c32.add(b32)
                    c64.add(b64)
            if L.hexbits is not None:
                c32.add(L.hexbits & 0xFFFFFFFF)
        all32 = c32 | set(c32_from_f64)
        findings = [("STALE", n) for n in stale_notes]
        callee_bits = None
        loaded32, loaded64 = set(), set()
        for rc in rconsts:
            kind, b = rc["kind"], rc["bits"]
            # compiler-introduced: sign mask for negation/fabs, 2^32 fix-up of
            # unsigned->float conversion (`fild; jns; fadd [2^32]`)
            if (kind, b) in (("f32", 0x80000000), ("f64", 0x8000000000000000)):
                continue
            if rc["mnem"] == "fadd" and (kind, b) in (("f32", 0x4F800000), ("f64", 0x41F0000000000000)):
                continue
            where = f"[0x{rc['va']:08X}] by {rc['mnem']}@0x{rc['insn']:08X}"
            if kind == "f80":
                fr = f80_to_fraction(b)
                if fr is None:
                    continue
                b = f64_bits(round_f64(fr))
                kind = "f64"
            if kind == "f32":
                loaded32.add(b)
                loaded64.add(f64_bits(bits_f32(b)))
                if b in c32:
                    continue
                if b in c32_from_f64:
                    findings.append(("TYPE", f"retail f32 {fmt32(b)} {where}; C++ has only double literal "
                                             f"{c32_from_f64[b].text or float(c32_from_f64[b].val)!r}"))
                    continue
                near = sorted((ulp_distance32(b, c), c) for c in all32 if c >> 31 == b >> 31)
                near = [x for x in near if 0 < x[0] <= 64]
                if near:
                    findings.append(("NEAR", f"retail f32 {fmt32(b)} {where}; C++ {fmt32(near[0][1])} "
                                             f"({near[0][0]} ulp)"))
                    continue
                tag = "MISSING-mov" if rc["weak"] else "MISSING"
            else:
                loaded64.add(b)
                d = bits_f64(b)
                if math.isfinite(d):
                    loaded32.add(f32_bits(d) if abs(d) < 3.4e38 else 0)
                if b in c64:
                    continue
                if b in c64_from_f32:
                    if f32_bits(d) in c32 and f64_bits(bits_f32(f32_bits(d))) == b:
                        continue  # retail widened a float constant
                if math.isfinite(d) and abs(d) < 3.4e38 and f32_bits(d) in c32 and \
                        f64_bits(bits_f32(f32_bits(d))) == b:
                    continue
                if math.isfinite(d) and abs(d) < 3.4e38 and f32_bits(d) in c32:
                    findings.append(("TYPE", f"retail f64 {fmt64(b)} {where}; C++ has only the float "
                                             f"{fmt32(f32_bits(d))}"))
                    continue
                near = sorted((ulp_distance64(b, c), c) for c in c64 if c >> 63 == b >> 63)
                near = [x for x in near if 0 < x[0] <= 1 << 30]
                if near:
                    findings.append(("NEAR", f"retail f64 {fmt64(b)} {where}; C++ {fmt64(near[0][1])}"))
                    continue
                tag = "MISSING"
            key = (kind, b)
            if inc_bits is None:
                inc_bits = {}
                for q in idx.include_closure(path):
                    if q not in idx.file_bits:
                        idx.file_bits[q] = set()
                    for kb in idx.file_bits[q]:
                        inc_bits.setdefault(kb, os.path.relpath(q, SDK))
            if callee_bits is None:
                callee_bits = idx.callee_bits(stripped[rs:re_])
            if rc.get("divguard"):
                tag = "INLINED?"
                extra = " (zero-divisor branch of an inlined Wm3 vector divide)"
            elif key in callee_bits:
                tag = "INLINED?"
                extra = f" (literal in callee {callee_bits[key]})"
            elif key in inc_bits:
                tag = "INLINED?"
                extra = f" (literal in {inc_bits[key]})"
            else:
                extra = ""
            val = fmt32(b) if kind == "f32" else fmt64(b)
            findings.append((tag, f"retail {kind} {val} {where}{extra}"))
        if not opts.no_unloaded:
            for L in direct:
                if L.kind == "int" or L.val in TRIVIAL or abs(L.val) in TRIVIAL:
                    continue
                b32 = L.as_f32_bits()
                b64 = L.as_f64_bits()
                nb32 = f32_bits(-round_f32(L.val))
                if b32 in loaded32 or nb32 in loaded32 or b64 in loaded64 or \
                        f64_bits(-round_f64(L.val)) in loaded64 or b32 in imms or nb32 in imms:
                    continue
                findings.append(("UNLOADED", f"C++ literal {L.text} = {fmt32(b32) if L.kind == 'f32' else fmt64(b64)}"
                                             f" never loaded by retail"))
        if opts.no_weak:
            findings = [f for f in findings if f[0] not in ("INLINED?", "MISSING-mov")]
        if findings or opts.all:
            results.append(dict(file=os.path.relpath(path, REPO), line=line,
                                addrs=[f"0x{a:08X}" for a in addrs], findings=findings))
    return results


# --------------------------------------------------------------------------
# math mode
# --------------------------------------------------------------------------

MATH_CALL_RE = re.compile(
    r"((?:std::|msvc8::|::)?(?:Wm3::Math<\s*(?:float|double|Real)\s*>::|Math<\s*(?:float|double|Real)\s*>::|Mathf::)?"
    r"\b(?:sinf?|cosf?|tanf?|atanf?|atan2f?|asinf?|acosf?|sqrtf?|fmodf?|powf?|expf?|logf?|log10f?|floorf?|ceilf?|"
    r"fabsf?|Sin|Cos|Tan|ATan|ATan2|ASin|ACos|Sqrt|InvSqrt|FMod|Pow|Exp|Log|Floor|Ceil|FastSin0|FastCos0|"
    r"SinTimes|SinTimesCos|CosTimesCos|Atan2Plus|Atan2Difference|IntrinsicExp|IntrinsicLn|IntrinsicLog10|"
    r"HalfSumX87|HalfAbsDifferenceX87|SlerpSphericalBlend|ScaleVector\w*X87|RoundToInt|BilinearHeight))\s*\("
)
X87_TRANS = {"fsin", "fcos", "fsincos", "fpatan", "fptan", "fsqrt", "fyl2x", "fyl2xp1", "f2xm1", "frndint",
             "fprem", "fprem1", "fscale"}
CRT_MATH = {"sin", "cos", "tan", "atan", "atan2", "asin", "acos", "sqrt", "fmod", "pow", "exp", "log", "log10",
            "floor", "ceil", "_CIsin", "_CIcos", "_CItan", "_CIatan", "_CIatan2", "_CIasin", "_CIacos",
            "_CIsqrt", "_CIfmod", "_CIpow", "_CIexp", "_CIlog", "_CIlog10", "__ftol2_sse", "__ftol2", "_ftol"}
CALL_RE = re.compile(r"^call\s+0x([0-9a-f]+)")


def check_math(path, idx: Index, pe: PE, asm_dir, opts):
    text = idx.text.get(path)
    if text is None:
        idx.load(path)
        text = idx.text[path]
    stripped = idx.stripped[path]
    results = []
    for addrs, line, rs, re_ in find_definitions(text, stripped):
        region = stripped[rs:re_]
        calls = []
        for m in MATH_CALL_RE.finditer(region):
            # skip member definitions / declarations: preceded by type keyword
            pre = region[max(0, m.start() - 12):m.start()]
            if re.search(r"(float|double|void|auto)\s+$", pre) or re.search(r"(\.|->)\s*$", pre):
                continue  # a declaration, or a member call on some other object
            ln = line + region.count("\n", 0, m.start()) - 1
            calls.append((ln, re.sub(r"\s+", "", m.group(1))))
        fns = [load_asm(asm_dir, a) for a in addrs]
        fns = [f for f in fns if f]
        if not fns:
            continue
        x87, crt, sse_sqrt = {}, {}, 0
        for f in fns:
            for ia, mn, ops in f.insns:
                if mn in X87_TRANS:
                    x87.setdefault(mn, []).append(ia)
                elif mn == "sqrtss" or mn == "sqrtsd":
                    sse_sqrt += 1
                elif mn in ("call", "jmp"):
                    cm = re.match(r"0x([0-9a-f]+)", ops)
                    if cm:
                        nm = callee_name(asm_dir, int(cm.group(1), 16))
                    else:  # IDA text names the target (`call _fmod`, `call __CIfmod`)
                        nm = ops.split()[0] if ops else ""
                        if nm not in CRT_MATH and nm[1:] in CRT_MATH:
                            nm = nm[1:]
                    if nm in CRT_MATH:
                        crt.setdefault(nm, []).append(ia)
                    elif cm and mn == "call":
                        # A tiny engine wrapper around one x87 transcendental
                        # (0x005734E0 `fld; fsin; ret`, 0x00452FC0 `fsqrt`)
                        # behaves like the inline instruction.
                        callee = load_asm(asm_dir, int(cm.group(1), 16))
                        if callee is not None and len(callee.insns) <= 16:
                            for _, cmn, _ in callee.insns:
                                if cmn in X87_TRANS:
                                    x87.setdefault(cmn, []).append(ia)
        if not calls and not x87 and not crt:
            continue
        flags = []
        cnames = [c[1] for c in calls]

        def has(*pats):
            return [c for c in calls if any(re.search(p, c[1]) for p in pats)]
        plain = r"^(std::|::)?"
        # x87 trig in retail but C++ uses std/CRT/Wm3 float trig
        for ins, pats in (("fsin", [plain + r"sinf?$", r"Math<\w+>::Sin$"]),
                          ("fcos", [plain + r"cosf?$", r"Math<\w+>::Cos$"]),
                          ("fptan", [plain + r"tanf?$", r"Math<\w+>::Tan$"]),
                          ("fpatan", [plain + r"atan2?f?$", r"Math<\w+>::ATan2?$"])):
            if ins in x87 or (ins in ("fsin", "fcos") and "fsincos" in x87):
                for c in has(*pats):
                    flags.append(f"L{c[0]} {c[1]}: retail inlines {ins} -> use msvc8:: x87 helper")
        for nm, pats in (("_CIsin", [r"msvc8::sinf?$"]), ("_CIcos", [r"msvc8::cosf?$"]),
                         ("sin", [r"msvc8::sinf?$"]), ("cos", [r"msvc8::cosf?$"])):
            if nm in crt and not x87:
                for c in has(*pats):
                    flags.append(f"L{c[0]} {c[1]}: retail calls CRT {nm}, not inline fsin/fcos")
        if "fsqrt" in x87 and not sse_sqrt:
            for c in has(plain + r"sqrtf?$", r"Math<\w+>::Sqrt$"):
                flags.append(("SQRT~", f"L{c[0]} {c[1]}: retail uses x87 fsqrt; same bits under 24-bit PC "
                                       f"unless its operand or consumer stays on the x87 stack"))
        if ("fyl2x" in x87 or "f2xm1" in x87):
            for c in has(plain + r"(exp|log|log10|pow)f?$", r"Math<\w+>::(Exp|Log|Pow)$"):
                flags.append(f"L{c[0]} {c[1]}: retail inlines fyl2x/f2xm1 -> msvc8::Intrinsic* helper")
        if "fprem" in x87 or "fprem1" in x87:
            for c in has(plain + r"fmodf?$"):
                flags.append(f"L{c[0]} {c[1]}: retail inlines fprem")
        if "_CIfmod" in crt or "fmod" in crt:
            for c in has(r"^(std::|::)?fmodf?$", r"Math<\w+>::FMod$"):
                flags.append(f"L{c[0]} {c[1]}: retail calls CRT fmod (0x00A8E06A) -> msvc8::fmod")
        if "acos" in crt:
            for c in has(plain + r"acosf?$", r"Math<\w+>::ACos$"):
                flags.append(f"L{c[0]} {c[1]}: retail calls CRT acos -> msvc8::acos(double)")
        # retail transcendental present but no math call in C++ at all
        trans = sorted(set(x87) - {"fsqrt", "frndint"})
        if trans and not calls:
            flags.append(f"retail has {trans} but C++ body has no math call (inlined helper?)")
        if crt and not calls and set(crt) - {"__ftol2_sse", "__ftol2", "_ftol", "floor", "ceil"}:
            flags.append(f"retail calls {sorted(set(crt) - {'__ftol2_sse', '__ftol2', '_ftol'})} "
                         f"but C++ body has no math call")
        if flags or opts.all:
            results.append(dict(file=os.path.relpath(path, REPO), line=line,
                                addrs=[f"0x{a:08X}" for a in addrs],
                                calls=cnames, x87={k: [f"0x{a:08X}" for a in v] for k, v in x87.items()},
                                crt={k: [f"0x{a:08X}" for a in v] for k, v in crt.items()},
                                sse_sqrt=sse_sqrt, findings=[f if isinstance(f, tuple) else ("MATH", f) for f in flags]))
    return results


# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--mode", choices=("consts", "math"), default="consts")
    ap.add_argument("--pe", default=DEFAULT_PE)
    ap.add_argument("--asm-dir", default=DEFAULT_ASM)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-unloaded", action="store_true")
    ap.add_argument("--no-weak", action="store_true")
    ap.add_argument("--only", default="", help="comma list of finding tags to keep (e.g. NEAR,TYPE)")
    opts = ap.parse_args()

    pe = PE(opts.pe)
    idx = Index()
    idx.build([SDK, os.path.join(REPO, "dependencies", "WildMagic3p8", "Foundation", "Math")])

    files = []
    for p in opts.paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                for f in sorted(fn):
                    if f.endswith((".cpp", ".h")):
                        files.append(os.path.join(dp, f))
        elif os.path.exists(p):
            files.append(p)
    keep = set(t for t in opts.only.split(",") if t)
    all_results = []
    for f in sorted(files):
        res = (check_math if opts.mode == "math" else check_consts)(f, idx, pe, opts.asm_dir, opts)
        for r in res:
            if keep:
                r["findings"] = [x for x in r["findings"] if x[0] in keep]
                if not r["findings"]:
                    continue
            all_results.append(r)
    if opts.json:
        json.dump(all_results, sys.stdout, indent=1)
        return
    counts = {}
    for r in all_results:
        print(f"{r['file']}:{r['line']} {' '.join(r['addrs'])}")
        if opts.mode == "math" and opts.all:
            print(f"    calls={r['calls']} x87={list(r['x87'])} crt={list(r['crt'])} sqrtss={r['sse_sqrt']}")
        for tag, msg in r["findings"]:
            counts[tag] = counts.get(tag, 0) + 1
            print(f"    {tag:9} {msg}")
    print(f"# {len(all_results)} definitions with findings; " +
          ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
