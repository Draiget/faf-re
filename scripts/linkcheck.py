"""Fail the build when a *new* unresolved external symbol appears.

Why this exists
---------------
`main.vcxproj` links with `/FORCE`, so unresolved externals are warnings, not
errors. The linker still has to put an address in the call site, and it uses
RVA 0 - which the loader relocates to the module base. Calling such a symbol
therefore jumps to `imagebase + 0` and dies with an access violation whose
faulting address looks like a wild pointer, nowhere near the missing function.

That is not hypothetical. `FafProbeFrameSeq` / `FafProbeFrameDiag` were called
from six committed diagnostics while their only definitions sat in an
uncommitted edit to `D3D9Interfaces.cpp`. A clean build of HEAD crashed on the
first frame that had a world view, and every build that reached gameplay did so
only because its checkout happened to carry the missing lines. Diagnosing it
took a bisect, a byte-level decode of the call site, and two wrong theories.
The link log had said so all along, in a warning nobody reads.

So: the link log is the oracle. Everything already known to be absent is listed
in `scripts/forced_unresolved.md`; anything else is a crash waiting for its
code path to run.

Usage
-----
    msbuild src/sdk/main.vcxproj ... | python scripts/linkcheck.py
    python scripts/linkcheck.py --log build.log
    python scripts/linkcheck.py --log build.log --update   # re-baseline

`--update` rewrites the allowlist from the current log. Use it when a symbol is
*recovered* (it disappears) - not to silence a new one. A new entry is a bug
report, not a chore.
"""

import argparse
import io
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWLIST = os.path.join(REPO, "scripts", "forced_unresolved.md")

QUOTED = re.compile(r'unresolved external symbol "([^"]+)"')
BARE = re.compile(r"unresolved external symbol (\S+)")


def symbols_in(lines):
    """Every unresolved external the linker reported, deduplicated."""
    found = set()
    for line in lines:
        if "LNK2019" not in line and "LNK2001" not in line:
            continue
        match = QUOTED.search(line) or BARE.search(line)
        if match:
            found.add(match.group(1).strip())
    return found


def read_allowlist():
    """The symbols inside the document's fenced block; the prose explains them."""
    if not os.path.exists(ALLOWLIST):
        return set(), ""
    with io.open(ALLOWLIST, "r", encoding="utf-8") as handle:
        text = handle.read()
    fence = "```" + "\n"
    before, marker, rest = text.partition(fence)
    if not marker:
        return set(), text
    listing, _, _ = rest.partition("```")
    return {line.strip() for line in listing.splitlines() if line.strip()}, before + marker


def write_allowlist(symbols, preamble):
    """Rewrite only the fenced list, leaving every word of the prose alone."""
    with io.open(ALLOWLIST, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(preamble)
        for symbol in sorted(symbols):
            handle.write(symbol + "\n")
        handle.write("```" + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", help="build log to read instead of stdin")
    parser.add_argument("--update", action="store_true", help="re-baseline the allowlist")
    args = parser.parse_args()

    if args.log:
        with io.open(args.log, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    else:
        lines = sys.stdin.readlines()

    found = symbols_in(lines)
    known, preamble = read_allowlist()

    # LNK4088 ("image being generated due to /FORCE") is emitted once per
    # completed link of this project, so it is what distinguishes a whole build
    # log from a filtered excerpt. Absent, every symbol the excerpt happens not
    # to mention would look recovered.
    complete = any("LNK4088" in line for line in lines)

    if args.update:
        if not complete:
            print("refusing to re-baseline from a log with no LNK4088 line --")
            print("that is an excerpt, not a finished link.")
            return 2
        write_allowlist(found, preamble)
        print("allowlist rewritten: %d symbols" % len(found))
        return 0

    if complete:
        for symbol in sorted(known - found):
            print("recovered (drop from the allowlist): %s" % symbol)

    added = found - known
    if not added:
        print("unresolved externals: %d, all known" % len(found))
        return 0

    print("")
    print("NEW unresolved external symbol(s) -- each is a jump to the image base")
    print("the first time its code path runs:")
    for symbol in sorted(added):
        print("  %s" % symbol)
    print("")
    print("Define it, or recover it. If it is genuinely out of reach, add it to")
    print("%s with a comment saying why." % os.path.relpath(ALLOWLIST, REPO).replace("\\", "/"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
