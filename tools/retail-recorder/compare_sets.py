"""Compares the original game's per-function call sets with our build's.

Each call is one hash of its plain arguments and result. Every hash the original
game produced must also appear in ours; ours may have more, because the original
inlined some calls our uninlined build still makes. A hash only the original has
means the same inputs gave a different result, or our build never saw those inputs.

usage: compare_sets.py <retail.sets> <ours.sets> <map.tsv> <out.tsv> [--self]

--self compares two runs of the same program: both directions must be empty.
"""
import csv
import os
import struct
import sys

RETAIL_BUGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "replay_sets", "retail_bugs.tsv")


def read_sets(path):
    data = open(path, "rb").read()
    assert data[:4] == b"RSET", path
    at, out = 4, {}
    while at < len(data):
        ident, level, count = struct.unpack_from("<III", data, at)
        at += 12
        calls, recorded = struct.unpack_from("<qq", data, at)
        at += 16
        hashes = set(struct.unpack_from(f"<{count}Q", data, at))
        at += 8 * count
        out[ident] = {"level": level, "calls": calls, "recorded": recorded, "hashes": hashes}
    return out


def read_retail_sets(path):
    """The original game's sets without its known bugs: we don't copy those, so ours must not need them."""
    sets = read_sets(path)
    for bug in csv.DictReader(open(RETAIL_BUGS, encoding="utf-8"), delimiter="\t", quoting=csv.QUOTE_NONE):
        found = sets.get(int(bug["va"], 16))
        if found:
            found["hashes"].discard(int(bug["hash"], 16))
    return sets


def sample(hashes, level):
    if level == 0:
        return hashes
    return {h for h in hashes if h >> (64 - level) == 0}


def main():
    args = [a for a in sys.argv[1:] if a != "--self"]
    both_ways = "--self" in sys.argv
    if len(args) != 4:
        raise SystemExit(__doc__)
    first, second = read_sets(args[0]) if both_ways else read_retail_sets(args[0]), read_sets(args[1])
    names = {}
    for line in open(args[2], encoding="utf-8"):
        cols = line.rstrip("\n").split("\t")
        if cols[0].startswith("0x"):
            names[int(cols[0], 16)] = cols
    counts = {}
    rows = []
    for ident, cols in sorted(names.items()):
        a, b = first.get(ident), second.get(ident)
        if a is None or a["recorded"] == 0:
            verdict, missing, extra, kept = "not called in the original", 0, 0, 0
        elif b is None or b["recorded"] == 0:
            verdict, missing, extra, kept = "not called in ours", 0, 0, len(a["hashes"])
        else:
            level = max(a["level"], b["level"])
            left, right = sample(a["hashes"], level), sample(b["hashes"], level)
            missing, extra, kept = len(left - right), len(right - left), len(left)
            if kept == 0:
                verdict = "no sample in common"
            elif missing == 0 and (not both_ways or extra == 0):
                verdict = "same"
            else:
                verdict = "DIFFERS"
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append((verdict, missing, kept, extra, ident, a, b, cols))
    rows.sort(key=lambda r: (r[0] != "DIFFERS", -(r[1] / max(r[2], 1)), r[4]))
    with open(args[3], "w", encoding="utf-8", newline="\n") as f:
        f.write("verdict\tmissing\tretail_kept\tours_only\tva\tretail_calls\tours_calls\tlevel\tname\tfile\tline\n")
        for verdict, missing, kept, extra, ident, a, b, cols in rows:
            level = max(a["level"] if a else 0, b["level"] if b else 0)
            f.write(
                f"{verdict}\t{missing}\t{kept}\t{extra}\t0x{ident:08X}\t{a['recorded'] if a else 0}\t"
                f"{b['recorded'] if b else 0}\t{level}\t{cols[1]}\t{cols[2]}\t{cols[3]}\n"
            )
    for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"{n:6d}  {verdict}")


if __name__ == "__main__":
    main()
