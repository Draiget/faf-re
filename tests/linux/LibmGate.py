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


def load_allowlist(path):
    allowed = set()
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            symbol, function = line.split(" ", 1)
            allowed.add((symbol, function.strip()))
    return allowed


def calls(obj):
    """(symbol, demangled caller) for every transcendental this object calls."""
    undefined = subprocess.run(["nm", "-u", obj], capture_output=True, text=True).stdout.split()
    if not TRANSCENDENTALS.intersection(undefined):
        return set()
    listing = subprocess.run(["objdump", "-dr", "--no-show-raw-insn", "-C", obj], capture_output=True, text=True).stdout
    found, function = set(), "?"
    for line in listing.splitlines():
        head = re.match(r"^[0-9a-f]+ <(.*)>:$", line)
        if head:
            function = head.group(1)
            continue
        reloc = re.search(r"R_X86_64_(?:PLT32|PC32|GOTPCREL\w*)\s+(\w+)(?:-0x[0-9a-f]+)?$", line)
        if reloc and reloc.group(1) in TRANSCENDENTALS:
            found.add((reloc.group(1), function))
    return found


def main():
    allowed = load_allowlist(sys.argv[1])
    unexpected = []
    for obj in sys.argv[2:]:
        for symbol, function in sorted(calls(obj)):
            if function.startswith("_GLOBAL__sub_I_") and symbol in ("sin", "cos"):
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
