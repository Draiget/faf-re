"""Build the sampling profiler's lookup tables for a rebuilt engine exe, from its own PDB.

build_symbols.py does this for the original ForgedAlliance.exe from the IDA export; this
script does the same for `main.exe` (Release or Debug), which ships with a PDB instead.

Writes into <out_dir>:
  symmap.json     sorted [start, end, token, name, location] per function (preferred image base)
  symnames.json   same order: [token, name, location]
  callsites.txt   every `call` of the exe's disassembly, in build_symbols.py's format
  taken.json      start addresses of functions whose address is stored somewhere (indirect targets)
  meta.json       {"image_base", "sim_vtable"}: sampler.py rebases by the module's load address

usage: python scripts/perf/build_symbols_pdb.py <main.exe> <out_dir>
The PDB is looked up next to the exe.
"""
import ctypes
import ctypes.wintypes as wt
import glob
import json
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SYMOPT_UNDNAME = 0x2
SYMOPT_DEFERRED_LOADS = 0x4
SYMOPT_LOAD_LINES = 0x10
SYM_TAG_FUNCTION = 5
SYM_TAG_PUBLIC = 10


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wt.ULONG), ("TypeIndex", wt.ULONG), ("Reserved", ctypes.c_uint64 * 2),
                ("Index", wt.ULONG), ("Size", wt.ULONG), ("ModBase", ctypes.c_uint64), ("Flags", wt.ULONG),
                ("Value", ctypes.c_uint64), ("Address", ctypes.c_uint64), ("Register", wt.ULONG),
                ("Scope", wt.ULONG), ("Tag", wt.ULONG), ("NameLen", wt.ULONG), ("MaxNameLen", wt.ULONG),
                ("Name", wt.WCHAR * 1)]


class IMAGEHLP_LINEW64(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wt.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", wt.DWORD),
                ("FileName", ctypes.c_wchar_p), ("Address", ctypes.c_uint64)]


def pe_sections(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    image_base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    iat_rva, iat_size = struct.unpack_from("<II", data, pe + 24 + 96 + 12 * 8)
    sec = pe + 24 + opt_size
    sections = {}
    for i in range(nsec):
        name, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", data, sec + i * 40)
        sections[name.rstrip(b"\0").decode()] = (image_base + va, data[rptr:rptr + min(rsize, vsize or rsize)])
    return image_base, sections, (image_base + iat_rva, image_base + iat_rva + iat_size)


def enumerate_symbols(exe, image_base):
    dbg = ctypes.WinDLL("dbghelp", use_last_error=True)
    dbg.SymInitializeW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.BOOL]
    dbg.SymLoadModuleExW.argtypes = [wt.HANDLE, wt.HANDLE, wt.LPCWSTR, wt.LPCWSTR, ctypes.c_uint64, wt.DWORD,
                                     ctypes.c_void_p, wt.DWORD]
    dbg.SymLoadModuleExW.restype = ctypes.c_uint64
    callback_type = ctypes.WINFUNCTYPE(wt.BOOL, ctypes.POINTER(SYMBOL_INFOW), wt.ULONG, ctypes.c_void_p)
    dbg.SymEnumSymbolsW.argtypes = [wt.HANDLE, ctypes.c_uint64, wt.LPCWSTR, callback_type, ctypes.c_void_p]
    dbg.SymGetLineFromAddrW64.argtypes = [wt.HANDLE, ctypes.c_uint64, ctypes.POINTER(wt.DWORD),
                                          ctypes.POINTER(IMAGEHLP_LINEW64)]
    handle = wt.HANDLE(0x7A11)
    dbg.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES)
    if not dbg.SymInitializeW(handle, os.path.dirname(os.path.abspath(exe)), False):
        raise SystemExit("SymInitialize failed %d" % ctypes.get_last_error())
    base = dbg.SymLoadModuleExW(handle, None, os.path.abspath(exe), None, image_base, 0, None, 0)
    if not base:
        raise SystemExit("SymLoadModuleEx failed %d" % ctypes.get_last_error())

    functions, publics = {}, {}

    def on_symbol(info, size, _ctx):
        sym = info.contents
        name = ctypes.wstring_at(ctypes.addressof(sym) + SYMBOL_INFOW.Name.offset, sym.NameLen).rstrip("\0")
        if sym.Tag == SYM_TAG_FUNCTION and sym.Size:
            functions.setdefault(sym.Address, (sym.Address + sym.Size, name))
        elif sym.Tag == SYM_TAG_PUBLIC:
            publics.setdefault(sym.Address, name)
        return True

    if not dbg.SymEnumSymbolsW(handle, base, "*", callback_type(on_symbol), None):
        raise SystemExit("SymEnumSymbols failed %d" % ctypes.get_last_error())

    def location(addr):
        line = IMAGEHLP_LINEW64()
        line.SizeOfStruct = ctypes.sizeof(line)
        disp = wt.DWORD(0)
        if not dbg.SymGetLineFromAddrW64(handle, addr, ctypes.byref(disp), ctypes.byref(line)):
            return ""
        path = os.path.normpath(line.FileName)
        try:
            rel = os.path.relpath(path, REPO)
            if not rel.startswith(".."):
                path = rel
        except ValueError:
            pass
        return "%s:%d" % (path.replace("\\", "/"), line.LineNumber)

    return functions, publics, location


def main():
    exe, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    image_base, sections, (iat_lo, iat_hi) = pe_sections(exe)
    text_va, text = sections[".text"]
    text_end = text_va + len(text)

    functions, publics, location = enumerate_symbols(exe, image_base)
    rows = []
    for start, (end, name) in sorted(functions.items()):
        if text_va <= start < text_end:
            rows.append([start, end, "F_%08X" % start, name, location(start)])
    # Public symbols with no function record (asm, CRT objects) fill the gaps up to the next symbol.
    known = sorted(functions)
    import bisect
    for start, name in sorted(publics.items()):
        if start in functions or not (text_va <= start < text_end):
            continue
        i = bisect.bisect_right(known, start) - 1
        if i >= 0 and start < functions[known[i]][0]:
            continue
        nxt = known[i + 1] if i + 1 < len(known) else text_end
        rows.append([start, nxt, "F_%08X" % start, name, ""])
    rows.sort()
    for a, b in zip(rows, rows[1:]):
        if a[1] > b[0]:
            a[1] = b[0]
    json.dump(rows, open(os.path.join(out, "symmap.json"), "w"))
    json.dump([[r[2], r[3], r[4]] for r in rows], open(os.path.join(out, "symnames.json"), "w"))
    print("functions:", len(rows))

    starts = {r[0] for r in rows}
    taken = set()
    for name, (va, blob) in sections.items():
        step = 1 if name == ".text" else 4
        for off in range(0, len(blob) - 3, step):
            v = struct.unpack_from("<I", blob, off)[0]
            if v in starts:
                taken.add(v)
    json.dump(sorted(taken), open(os.path.join(out, "taken.json"), "w"))
    print("address-taken:", len(taken))

    # The engine's vtables carry no public symbol; the slot before a vtable points at its
    # RTTI Complete Object Locator, which does.
    sim_vtable = None
    col = next((a for a, n in publics.items() if n == "moho::Sim::`RTTI Complete Object Locator'"), None)
    rdata_va, rdata = sections[".rdata"]
    if col is not None:
        at = rdata.find(struct.pack("<I", col))
        while at >= 0 and at % 4:
            at = rdata.find(struct.pack("<I", col), at + 1)
        if at >= 0:
            sim_vtable = rdata_va + at + 4
    json.dump({"image_base": image_base, "sim_vtable": sim_vtable}, open(os.path.join(out, "meta.json"), "w"))
    print("Sim vtable:", hex(sim_vtable) if sim_vtable else None)

    dumpbin = sorted(glob.glob(r"C:\Program Files\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x86\dumpbin.exe"))[-1]
    proc = subprocess.Popen([dumpbin, "/disasm:nobytes", "/section:.text", exe], stdout=subprocess.PIPE,
                            text=True, encoding="latin1", bufsize=1 << 20)
    line_re = re.compile(r"^\s+([0-9A-F]{8}): (\w+)\s*(.*)$")
    pending = None
    count = 0
    with open(os.path.join(out, "callsites.txt"), "w") as fh:
        for line in proc.stdout:
            m = line_re.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            if pending is not None:
                size = addr - pending
                if 0 < size <= 8:
                    # dumpbin names call targets by their decorated symbol; decode the bytes instead.
                    off = pending - text_va
                    if text[off] == 0xE8 and size == 5:
                        target = (pending + 5 + struct.unpack_from("<i", text, off + 1)[0]) & 0xFFFFFFFF
                        operand = "0x%08X" % target
                    elif text[off] == 0xFF and text[off + 1] == 0x15 and size == 6:
                        operand = "dword ptr [0x%08X]" % struct.unpack_from("<I", text, off + 2)[0]
                    else:
                        operand = "indirect"
                    fh.write("0x%08X: %s call %s\n" % (pending, "00 " * size, operand))
                    count += 1
                pending = None
            if m.group(2) == "call":
                pending = addr
    proc.wait()
    print("call sites:", count)


if __name__ == "__main__":
    main()
