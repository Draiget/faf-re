"""Writes the two hook specs for comparing a function's calls between the
original game and our instrumented x86 build (README, "Comparing with our build").

Both specs name the same functions and hash the same words: an argument or a
result counts only when our own type says it is a plain value, because a pointer
differs per run. Types come from our build's PDB, never from Hex-Rays, which
often calls a pointer an int. Where a retail entry's arguments cannot be lined
up with ours (a different count or word size), neither side hashes arguments.

usage: spec_compare.py <inventory.tsv> <retail spec.bin from spec.py> <headless.exe> <headless.pdb>
                       <retail out.bin> <ours out.bin> <map out.tsv>
"""
import bisect
import ctypes
import os
import re
import struct
import subprocess
import sys

PDBUTIL = r"C:\Program Files\LLVM\bin\llvm-pdbutil.exe"
OBJDUMP = r"C:\Program Files\LLVM\bin\llvm-objdump.exe"

RET_NONE, RET_EAX, RET_ST0_FLOAT, RET_ST0_DOUBLE, RET_EDX_EAX, RET_AL, RET_AX, RET_XMM0_FLOAT, RET_EAX_POINTER = range(9)
STACK = 0x80
ECX, EDX = 1, 2
ENTRY_NOPS = bytes.fromhex("66 90 66 90 66 90 66 90")  # -fpatchable-function-entry=8
SIM_ENTRY = 0x00749F40  # Moho::Sim::AdvanceBeat

# Word kinds of a value.
INT, FLOAT, DOUBLE, INT64, NARROW1, NARROW2, POINTER, STRUCT, VOID = range(9)
BUILTIN = {
    "void": VOID, "float": FLOAT, "double": DOUBLE, "long double": DOUBLE,
    "bool": NARROW1, "char": NARROW1, "signed char": NARROW1, "unsigned char": NARROW1, "char8_t": NARROW1,
    "short": NARROW2, "unsigned short": NARROW2, "wchar_t": NARROW2, "char16_t": NARROW2,
    "int": INT, "unsigned": INT, "unsigned int": INT, "long": INT, "unsigned long": INT, "char32_t": INT,
    "__int64": INT64, "unsigned __int64": INT64, "long long": INT64, "unsigned long long": INT64,
    "HRESULT": INT, "__int32": INT, "unsigned __int32": INT, "int64_t": INT64,
}


def pdb_dump(pdb, what):
    return subprocess.run(
        [PDBUTIL, "dump", what, pdb], capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).stdout.splitlines()


def read_types(pdb):
    """type index -> record: kind plus the fields we use."""
    types, cur = {}, None
    head = re.compile(r"^\s*(0x[0-9A-F]+) \| (LF_\w+) \[size = \d+\]\s*(?:`(.*)`)?")
    for line in pdb_dump(pdb, "--types"):
        m = head.match(line)
        if m:
            cur = {"kind": m.group(2), "name": m.group(3) or "", "text": ""}
            types[int(m.group(1), 16)] = cur
        elif cur is not None:
            cur["text"] += " " + line.strip()
    return types


TYPE_REF = re.compile(r"(0x[0-9A-F]+)(?: \(([^)]*)\))?")


def classify(types, index, depth=0):
    """(kind, words) of the type with this index; words is None when unknown."""
    if depth > 8:
        return STRUCT, None
    if index < 0x1000:
        # A simple type: its pointer forms have the mode nibble set.
        if index & 0x0F00:
            return POINTER, 1
        name = SIMPLE.get(index & 0xFF)
        if name is None:
            return STRUCT, None
        return name, {INT64: 2, DOUBLE: 2, VOID: 0}.get(name, 1)
    rec = types.get(index)
    if rec is None:
        return STRUCT, None
    kind = rec["kind"]
    if kind == "LF_POINTER":
        return POINTER, 1
    if kind == "LF_MODIFIER":
        m = re.search(r"referent = (0x[0-9A-F]+)", rec["text"])
        return classify(types, int(m.group(1), 16), depth + 1) if m else (STRUCT, None)
    if kind == "LF_ENUM":
        return INT, 1
    if kind in ("LF_STRUCTURE", "LF_CLASS", "LF_UNION"):
        forward = re.search(r"forward ref \(-> (0x[0-9A-F]+)\)", rec["text"])
        if forward:
            return classify(types, int(forward.group(1), 16), depth + 1)
        m = re.search(r"sizeof (\d+)", rec["text"])
        return STRUCT, (int(m.group(1)) + 3) // 4 if m and int(m.group(1)) else None
    return STRUCT, None


# CodeView simple types, low byte.
SIMPLE = {
    0x03: VOID, 0x08: INT,
    0x10: NARROW1, 0x20: NARROW1, 0x68: NARROW1, 0x69: NARROW1, 0x30: NARROW1, 0x31: NARROW1, 0x7C: NARROW1,
    0x11: NARROW2, 0x21: NARROW2, 0x71: NARROW2, 0x72: NARROW2, 0x73: NARROW2, 0x7A: NARROW2, 0x32: NARROW2,
    0x12: INT, 0x22: INT, 0x74: INT, 0x75: INT, 0x7B: INT, 0x33: INT,
    0x13: INT64, 0x23: INT64, 0x76: INT64, 0x77: INT64,
    0x40: FLOAT, 0x41: DOUBLE, 0x42: DOUBLE,
}


def signature(types, index):
    """(convention, result (kind, words, sizeof known), [(kind, words)], has this) or None."""
    rec = types.get(index)
    if rec is None or rec["kind"] not in ("LF_PROCEDURE", "LF_MFUNCTION"):
        return None
    text = rec["text"]
    ret = re.search(r"return type = (0x[0-9A-F]+)", text)
    plist = re.search(r"param list = (0x[0-9A-F]+)", text)
    conv = re.search(r"calling conv = (\w+)", text)
    if not ret or not plist or not conv:
        return None
    args = []
    arglist = types.get(int(plist.group(1), 16))
    if arglist is None:
        return None
    for m in TYPE_REF.finditer(arglist["text"]):
        args.append(classify(types, int(m.group(1), 16)))
    has_this = rec["kind"] == "LF_MFUNCTION" and "this type = <no type>" not in text
    return conv.group(1), classify(types, int(ret.group(1), 16)), args, has_this


def read_procs(pdb):
    """code offset (section, offset) -> (qualified name, size, type index); one per address."""
    procs = {}
    lines = pdb_dump(pdb, "--symbols")
    head = re.compile(r"\| S_[GL]PROC32 \[size = \d+\] `(.*)`$")
    addr = re.compile(r"addr = (\d+):(\d+), code size = (\d+)")
    kind = re.compile(r"type = `(0x[0-9A-F]+)")
    for i, line in enumerate(lines):
        m = head.search(line)
        if not m or i + 2 >= len(lines):
            continue
        a, t = addr.search(lines[i + 1]), kind.search(lines[i + 2])
        if a and t:
            key = (int(a.group(1)), int(a.group(2)))
            procs.setdefault(key, (m.group(1), int(a.group(3)), int(t.group(1), 16)))
    return procs


def read_sections(exe):
    data = open(exe, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    sections = []
    at = pe + 24 + optional
    for i in range(count):
        va, size, raw = struct.unpack_from("<III", data, at + 12)
        sections.append((va, raw))
        at += 40
    return data, base, sections


def return_sizes(exe, base):
    """rva, bytes popped: every return instruction in the exe."""
    out = subprocess.run(
        [OBJDUMP, "-d", "--no-show-raw-insn", "--section=.text", exe],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).stdout
    rets = []
    pattern = re.compile(r"^\s*([0-9a-f]+):\s+ret[lw]?\b(?:\s+\$(0x[0-9a-f]+|\d+))?", re.M)
    for m in pattern.finditer(out):
        rets.append((int(m.group(1), 16) - base, int(m.group(2), 0) if m.group(2) else 0))
    rets.sort()
    return rets


def undecorate_name(mangled):
    """The qualified name of a mangled x64 symbol, as a PDB proc spells it."""
    buffer = ctypes.create_string_buffer(4096)
    dbghelp = ctypes.WinDLL("dbghelp")
    if dbghelp.UnDecorateSymbolName(mangled.encode(), buffer, 4096, 0x1000) == 0:
        return None
    return buffer.value.decode(errors="replace")


def undecorate_params(mangled, name):
    """The parameter kinds of a mangled symbol, from its undecorated text; None when unreadable."""
    buffer = ctypes.create_string_buffer(8192)
    if ctypes.WinDLL("dbghelp").UnDecorateSymbolName(mangled.encode(), buffer, 8192, 0) == 0:
        return None
    text = buffer.value.decode(errors="replace")
    at = text.find(name + "(")
    if at < 0:
        return None
    depth, cur, params = 0, "", []
    for ch in text[at + len(name) + 1 :]:
        if ch in "(<":
            depth += 1
        elif ch == ")" and depth == 0:
            break
        elif ch in ")>":
            depth -= 1
        if ch == "," and depth == 0:
            params.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        params.append(cur.strip())
    if params == ["void"]:
        return []
    return ["pointer" if ("*" in t or "&" in t) else t.replace("const ", "").strip() for t in params]


def kinds_match(text_kinds, args):
    """Whether a PDB signature's arguments fit the undecorated parameter texts."""
    args = [a for a in args if a[0] != VOID]
    if len(text_kinds) != len(args):
        return False
    for text, (kind, _) in zip(text_kinds, args):
        if text == "pointer":
            if kind != POINTER:
                return False
        elif text in BUILTIN and text not in ("__int64", "unsigned __int64"):
            if BUILTIN[text] != kind:
                return False
        elif text in ("__int64", "unsigned __int64"):
            # x64's size_t is unsigned __int64 here and a 32-bit int in our x86 build.
            if kind not in (INT, INT64):
                return False
        elif kind in (POINTER, FLOAT, DOUBLE):
            return False
    return True


def read_retail(path):
    data = open(path, "rb").read()
    assert data[:4] == b"RRS2"
    count = struct.unpack_from("<I", data, 4)[0]
    at, entries = 8, {}
    for _ in range(count):
        va, pop, prologue, ret, nargs, writes = struct.unpack_from("<IHBBBB", data, at)
        at += 10
        args = [struct.unpack_from("4B", data, at + 4 * i) for i in range(nargs)]
        at += 4 * nargs
        entries[va] = {"pop": pop, "prologue": prologue, "ret": ret, "args": args}
    return entries


def params_of(sig):
    """Our function's parameters in order, including `this` and a hidden result pointer."""
    conv, result, args, has_this = sig
    params = []
    if has_this:
        params.append((POINTER, 1))
    if result[0] == STRUCT:
        if result[1] is None or result[1] <= 2:
            return None  # returned in registers or unknown: its stack layout is not certain
        params.append((POINTER, 1))
    for a in args:
        if a[0] == VOID:
            continue
        if a[1] is None:
            return None
        params.append(a)
    return params


def our_locations(sig, params):
    conv, _, _, has_this = sig
    locations, stack = [], 0
    registers = [ECX, EDX] if conv == "fastcall" else ([ECX] if conv == "thiscall" else [])
    for kind, words in params:
        if registers and words == 1 and kind in (INT, NARROW1, NARROW2, POINTER):
            locations.append(registers.pop(0))
        else:
            locations.append(STACK | stack)
            stack += words
    return locations, stack


def pop_bytes(rets, ret_rvas, rva, size, conv, stack_words):
    """The bytes our function pops, or None when its returns do not fit its convention.

    A jump table in the code decodes as stray returns, so more than one size is
    normal: the convention says which is real, if that size is among them.
    """
    low, high = bisect.bisect_left(ret_rvas, rva), bisect.bisect_left(ret_rvas, rva + size)
    pops = {rets[i][1] for i in range(low, high)}
    expected = stack_words * 4 if conv in ("thiscall", "stdcall", "fastcall") else 0
    if pops and expected not in pops:
        if len(pops) > 1:
            return None
        return pops.pop()
    return expected


def write_spec(path, flags, entries):
    with open(path, "wb") as f:
        f.write(b"RRS3" + struct.pack("<II", len(entries), flags))
        for va, pop, prologue, ret, args, ident in entries:
            f.write(struct.pack("<IHBBBB", va, pop, prologue, ret, len(args), 1))
            f.write(struct.pack("<I", ident))
            for arg in args:
                f.write(struct.pack("<BBBB", *arg))


def plan_result(kind, retail_ret):
    """The result kinds (ours, retail), or None when it cannot be compared.

    Both sides must really return a value: where the original returns nothing or
    a pointer (a hidden result, Moho::EntityDB::DoReserveId) its register holds
    no value to compare, whatever ours returns. Integers compare at the narrower
    width, since a char return leaves the rest of eax undefined.
    """
    if retail_ret in (RET_NONE, RET_EAX_POINTER):
        return None
    retail_float = retail_ret in (RET_ST0_FLOAT, RET_ST0_DOUBLE, RET_XMM0_FLOAT)
    if kind == FLOAT:
        if retail_ret == RET_XMM0_FLOAT:
            return RET_ST0_FLOAT, RET_XMM0_FLOAT
        return (RET_ST0_FLOAT, RET_ST0_FLOAT) if retail_float else None
    if kind == DOUBLE:
        return (RET_ST0_DOUBLE, RET_ST0_DOUBLE) if retail_ret in (RET_ST0_FLOAT, RET_ST0_DOUBLE) else None
    if retail_float:
        return None
    ours = {INT: RET_EAX, NARROW1: RET_AL, NARROW2: RET_AX, INT64: RET_EDX_EAX}.get(kind)
    if ours is None:
        return None
    narrower = min((ours, retail_ret), key=[RET_AL, RET_AX, RET_EAX, RET_EDX_EAX].index)
    return narrower, narrower


HASHED_KINDS = (INT, FLOAT, DOUBLE, INT64)


def main():
    if len(sys.argv) != 8:
        raise SystemExit(__doc__)
    inventory, retail_path, exe, pdb, retail_out, ours_out, map_out = sys.argv[1:]
    retail = read_retail(retail_path)
    types = read_types(pdb)
    procs = read_procs(pdb)
    data, base, sections = read_sections(exe)
    rets = return_sizes(exe, base)
    ret_rvas = [r[0] for r in rets]
    by_name = {}
    for (section, offset), (name, size, tindex) in procs.items():
        if 1 <= section <= len(sections):
            by_name.setdefault(name, []).append((sections[section - 1][0] + offset, section, offset, size, tindex))

    stats = {}
    def count(why):
        stats[why] = stats.get(why, 0) + 1

    retail_entries, ours_entries, rows = [], [], []
    seen = set()
    for line in open(inventory, encoding="utf-8"):
        cols = line.rstrip("\n").split("\t")
        if not re.match(r"^0x[0-9A-Fa-f]{8}$", cols[0]):
            continue
        va = int(cols[0], 16)
        if va in seen:
            continue
        seen.add(va)
        entry = retail.get(va)
        if entry is None:
            count("not hookable in the original game")
            continue
        symbol = cols[4]
        mangled = symbol.split(":", 1)[1] if ":" in symbol.split("?")[0] and "?" in symbol else symbol
        name = undecorate_name(mangled) if mangled.startswith("?") else mangled
        candidates = by_name.get(name or "", [])
        if not candidates:
            count("no function of that name in our build (inlined away or unused)")
            continue
        if len(candidates) > 1 and mangled.startswith("?"):
            text_kinds = undecorate_params(mangled, name)
            if text_kinds is not None:
                fitting = []
                for candidate in candidates:
                    sig = signature(types, candidate[4])
                    if sig is not None and kinds_match(text_kinds, sig[2]):
                        fitting.append(candidate)
                candidates = fitting or candidates
        if len(candidates) > 1:
            count("several overloads of that name in our build")
            continue
        rva, section, offset, size, tindex = candidates[0]
        va_raw = sections[section - 1][1] + offset
        if data[va_raw : va_raw + 8] != ENTRY_NOPS:
            count("our function has no patchable entry (naked or asm)")
            continue
        sig = signature(types, tindex)
        if sig is None:
            count("no signature in our PDB")
            continue
        params = params_of(sig)
        if params is None:
            count("our stack layout is not certain (struct result or unknown size)")
            continue
        locations, stack_words = our_locations(sig, params)
        pop = pop_bytes(rets, ret_rvas, rva, size, sig[0], stack_words)
        if pop is None:
            count("our function's return sizes do not fit its convention")
            continue

        # Hex-Rays lists a register function's parameters in register order, not
        # the source's (Entity::SetVizToEnemies is (mode@eax, this@ecx)), so a
        # position says nothing. The plain ones pair up in order instead, as both
        # sides tell them apart from pointers, and the hash sorts its words anyway.
        ours_plain = [i for i, (kind, _) in enumerate(params) if kind != POINTER]
        retail_plain = [a for a in entry["args"] if a[2]]
        lined_up = len(entry["args"]) == len(params) and len(ours_plain) == len(retail_plain) and all(
            params[i][1] == a[1] and (params[i][0] in (FLOAT, DOUBLE)) == bool(a[3])
            for i, a in zip(ours_plain, retail_plain)
        )
        ours_args, retail_args = [], []
        if lined_up:
            for i, a in zip(ours_plain, retail_plain):
                kind, words = params[i]
                if kind in HASHED_KINDS:
                    flt = 1 if kind in (FLOAT, DOUBLE) else 0
                    ours_args.append((locations[i], words, 1, flt))
                    retail_args.append((a[0], words, 1, flt))
        result = plan_result(sig[1][0], entry["ret"])
        ours_ret, retail_ret = result if result else (RET_NONE, RET_NONE)
        hashed_words = sum(a[1] for a in ours_args if a[2])
        if not hashed_words and ours_ret == RET_NONE:
            count("nothing plain to compare (pointers and void only, or arguments do not line up)")
            continue
        count("compared")
        retail_entries.append((va, entry["pop"], entry["prologue"], retail_ret, retail_args, va))
        ours_entries.append((rva, pop, 8, ours_ret, ours_args, va))
        rows.append((va, name, cols[1], cols[2], hashed_words, ours_ret))

    # Sim::AdvanceBeat names the sim thread (RETAIL_RECORDER_SIM_ENTRY), so it is
    # hooked on both sides whether or not it has anything to hash.
    if not any(e[5] == SIM_ENTRY for e in retail_entries):
        entry = retail[SIM_ENTRY]
        retail_entries.append((SIM_ENTRY, entry["pop"], entry["prologue"], RET_NONE, [], SIM_ENTRY))
        rva, section, offset, size, tindex = by_name["moho::Sim::AdvanceBeat"][0]
        ours_entries.append((rva, pop_bytes(rets, ret_rvas, rva, size, "thiscall", 1), 8, RET_NONE, [], SIM_ENTRY))
    write_spec(retail_out, 0, retail_entries)
    write_spec(ours_out, 1, ours_entries)
    with open(map_out, "w", encoding="utf-8", newline="\n") as f:
        f.write("va\tname\tfile\tline\thashed_arg_words\tresult_kind\n")
        for va, name, source, source_line, words, ret in rows:
            f.write(f"0x{va:08X}\t{name}\t{source}\t{source_line}\t{words}\t{ret}\n")
    for why, n in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"{n:6d}  {why}")


if __name__ == "__main__":
    main()
