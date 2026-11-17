#!/usr/bin/env python3
"""Engine addition (dedicated-server plan WPL.13): the faf_sim objects call no host libm
transcendental outside the reviewed list.

A transcendental from the C library (sin, cos, tan, atan2, exp, log, pow, ...) can round
differently on Windows (UCRT) and Linux (glibc), so the simulation's arithmetic goes through
the engine's own implementations (legacy/math/X87Math). This gate lists every function in the
faf_sim objects that calls one (nm -u, then objdump relocations) and fails on any pair
(symbol, function) that tests/linux/libm_allowlist.txt does not name. Static initialisers
calling sin/cos are allowed as a class: they are the Wm3 axis-angle constants of
QuaternionMath.h, whose float results are millions of ulps from any rounding boundary (WPR.57).

Usage: LibmGate.py <allowlist> <object>...
"""
import re
import subprocess
import sys

TRANSCENDENTALS = {
    "sin", "cos", "tan", "asin", "acos", "atan", "atan2", "exp", "exp2", "expm1", "log", "log2",
    "log10", "log1p", "logb", "pow", "sinh", "cosh", "tanh", "asinh", "acosh", "atanh", "cbrt",
    "erf", "erfc", "hypot", "lgamma", "tgamma",
}
TRANSCENDENTALS |= {name + suffix for name in list(TRANSCENDENTALS) for suffix in ("f", "l")}
# sin and cos of one argument, which LLVM merges into one call when math functions don't set errno.
TRANSCENDENTALS |= {"sincos", "sincosf", "sincosl", "__sincos", "__sincosf", "__sincos_stret", "__sincosf_stret"}


def normalized(function):
    """A demangled name with the demanglers' spacing differences removed ("> >" and ">>")."""
    return re.sub(r"\s+(?=>)", "", function)


def load_allowlist(path):
    allowed = set()
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            symbol, function = line.split(" ", 1)
            allowed.add((symbol, normalized(function.strip())))
    return allowed


def is_mach_o(obj):
    """True for a Mach-O object (macOS), whose C symbols carry a leading '_'."""
    with open(obj, "rb") as f:
        return f.read(4) in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")


def mach_o_names(obj):
    """{address: demangled name} of an object's defined symbols, without the assembler's ltmp labels."""
    names = {}
    listing = subprocess.run(["nm", "-n", "--defined-only", "-C", obj], capture_output=True, text=True).stdout
    for line in listing.splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and not parts[2].startswith("ltmp"):
            names.setdefault(int(parts[0], 16), parts[2][1:] if parts[2].startswith("_") and parts[2][1:2] != "_" else parts[2])
    return names


def calls(obj):
    """(symbol, demangled caller) for every transcendental this object calls."""
    mach_o = is_mach_o(obj)
    undefined = subprocess.run(["nm", "-u", obj], capture_output=True, text=True).stdout.split()
    if mach_o:
        undefined = [name[1:] if name.startswith("_") else name for name in undefined]
    if not TRANSCENDENTALS.intersection(undefined):
        return set()
    listing = subprocess.run(["objdump", "-dr", "--no-show-raw-insn", "-C", obj], capture_output=True, text=True).stdout
    names = mach_o_names(obj) if mach_o else {}
    found, function, section = set(), "?", ""
    for line in listing.splitlines():
        if line.startswith("Disassembly of section "):
            section = line[len("Disassembly of section "):].rstrip(":")
            continue
        head = re.match(r"^([0-9a-f]+) <(.*)>:$", line)
        if head:
            function = head.group(2)
            if mach_o:
                # Apple's assembler labels each section's start ltmpN; the function there is the
                # symbol at that address, and the static initialisers in __StaticInit have none.
                if function.startswith("ltmp"):
                    function = names.get(int(head.group(1), 16), function)
                if function.startswith("ltmp") and section.endswith("__StaticInit"):
                    function = "_GLOBAL__sub_I_"
                if function.startswith("__GLOBAL__"):
                    function = function[1:]
            continue
        if mach_o:
            # ARM64: a call is BRANCH26; an address taken goes through the GOT.
            reloc = re.search(r"ARM64_RELOC_(?:BRANCH26|GOT_LOAD_PAGE21|GOT_LOAD_PAGEOFF12)\s+_(\w+)", line)
        else:
            reloc = re.search(r"R_X86_64_(?:PLT32|PC32|GOTPCREL\w*)\s+(\w+)(?:-0x[0-9a-f]+)?$", line)
        if reloc and reloc.group(1) in TRANSCENDENTALS:
            found.add((reloc.group(1), normalized(function)))
    return found


def main():
    allowed = load_allowlist(sys.argv[1])
    unexpected = []
    for obj in sys.argv[2:]:
        for symbol, function in sorted(calls(obj)):
            if function.startswith("_GLOBAL__sub_I_") and symbol in ("sin", "cos", "sincos", "__sincos_stret"):
                continue
            if (symbol, function) not in allowed:
                unexpected.append(f"{symbol} {function}    ({obj})")
    if unexpected:
        print("libm gate: transcendental calls not in tests/linux/libm_allowlist.txt:")
        for line in unexpected:
            print("  " + line)
        return 1
    print(f"libm gate: {len(sys.argv) - 2} objects, no unreviewed transcendental call")
    return 0


if __name__ == "__main__":
    sys.exit(main())
