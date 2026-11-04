"""The stored call hashes of tests/replay_sets: a replay test that needs no original game.

The original game's per-function call hashes (compare_sets.py's "same" functions)
live in the repo, each with the words they cover. To check a build, its PDB gives
the hook spec for those same words, the replay plays under the recorder DLL, and
every stored hash must appear. A function whose signature changed is reported, not
skipped, since its stored hashes no longer cover the same words.

  replay_sets.py make  <retail.sets> <cmp.tsv> <self.tsv> <ours spec.bin> <headless.exe> <headless.pdb> <out dir> <replay id>
  replay_sets.py spec  <golden dir> <replay id> <headless.exe> <headless.pdb> <spec out.bin>
  replay_sets.py check <golden dir> <replay id> <ours.sets> <spec out.bin>

make needs the original game's run; spec and check do not. check exits 1 on any
difference, so a CI step or a person can use its exit code.
"""
import csv
import os
import re
import struct
import sys

import compare_sets
import spec_compare as sc

kMaxStored = 4096  # hashes per function; hotter functions keep a sample by a higher level
KIND_LETTER = {
    sc.INT: "I", sc.FLOAT: "F", sc.DOUBLE: "D", sc.INT64: "Q", sc.NARROW1: "B", sc.NARROW2: "W", sc.POINTER: "P", sc.VOID: "V",
}


def kinds_text(described):
    """A function's parameter and result kinds: what its stored hashes assume."""
    sig, params, _, _ = described
    letter = lambda kind, words: f"S{words}" if kind == sc.STRUCT else KIND_LETTER[kind]
    return " ".join(letter(*p) for p in params) + " -> " + letter(*sig[1])


def without_struct_sizes(text):
    """Kinds as a check compares them. Struct sizes follow the container layout a build picks, and
    no hash covers a struct: the words around one are found from the current build's sizes."""
    return re.sub(r"S\d+", "S", text)


class Build:
    def __init__(self, exe, pdb):
        self.types = sc.read_types(pdb)
        self.data, self.base, self.sections = sc.read_sections(exe)
        self.rets = sc.return_sizes(exe, self.base)
        self.ret_rvas = [r[0] for r in self.rets]
        self.by_name, self.by_rva = {}, {}
        for (section, offset), (name, size, tindex) in sc.read_procs(pdb).items():
            if 1 <= section <= len(self.sections):
                rva = self.sections[section - 1][0] + offset
                raw = self.sections[section - 1][1] + offset
                entry = (rva, raw, size, tindex, name)
                self.by_name.setdefault(name, []).append(entry)
                self.by_rva[rva] = entry

    def describe(self, entry):
        """(signature, params, locations, pop) of a function, or None when it cannot be hooked."""
        rva, raw, size, tindex, _ = entry
        if self.data[raw : raw + 8] != sc.ENTRY_NOPS:
            return None
        sig = sc.signature(self.types, tindex)
        params = sc.params_of(sig) if sig else None
        if params is None:
            return None
        locations, stack_words = sc.our_locations(sig, params)
        pop = sc.pop_bytes(self.rets, self.ret_rvas, rva, size, sig[0], stack_words)
        return None if pop is None else (sig, params, locations, pop)


def read_spec(path):
    data = open(path, "rb").read()
    count, flags = struct.unpack_from("<II", data, 4)
    at, out = 12, {}
    for _ in range(count):
        va, pop, prologue, ret, nargs, writes, ident = struct.unpack_from("<IHBBBBI", data, at)
        at += 14
        args = [struct.unpack_from("4B", data, at + 4 * i) for i in range(nargs)]
        at += 4 * nargs
        out[ident] = (va, ret, args)
    return out


def make(retail_sets, cmp_tsv, self_tsv, ours_spec, exe, pdb, out_dir, replay):
    build = Build(exe, pdb)
    sets = compare_sets.read_retail_sets(retail_sets)
    spec = read_spec(ours_spec)
    noise = {r["va"] for r in csv.DictReader(open(self_tsv), delimiter="\t") if r["verdict"] == "DIFFERS"}
    os.makedirs(out_dir, exist_ok=True)
    kept, dropped, not_unique = 0, 0, 0
    with open(f"{out_dir}/{replay}.tsv", "w", encoding="utf-8", newline="\n") as tsv, open(f"{out_dir}/{replay}.sets", "wb") as out:
        tsv.write("va\tname\tparams\thashed\tresult\tcalls\tfile\tline\n")
        out.write(b"RSET")
        for row in csv.DictReader(open(cmp_tsv), delimiter="\t"):
            if row["verdict"] != "same" or row["va"] in noise:
                continue
            ident = int(row["va"], 16)
            rva, ret, args = spec[ident]
            info = build.by_rva.get(rva)
            described = build.describe(info) if info else None
            if described is None:
                dropped += 1
                continue
            _, params, locations, _ = described
            text = kinds_text(described)
            twins = [c for c in build.by_name[info[4]] if (d := build.describe(c)) and kinds_text(d) == text]
            if len(twins) != 1:
                not_unique += 1  # a later check could not tell which one the hashes belong to
                continue
            hashed = [i for i, loc in enumerate(locations) if any(a[0] == loc and a[2] for a in args)]
            source = sets[ident]
            level, hashes = source["level"], source["hashes"]
            while len(hashes) > kMaxStored:
                level += 1
                hashes = compare_sets.sample(hashes, level)
            tsv.write(
                f"0x{ident:08X}\t{row['name']}\t{text}\t{' '.join(map(str, hashed))}\t{ret}\t"
                f"{source['recorded']}\t{row['file']}\t{row['line']}\n"
            )
            out.write(struct.pack("<III", ident, level, len(hashes)))
            out.write(struct.pack("<qq", source["calls"], source["recorded"]))
            out.write(struct.pack(f"<{len(hashes)}Q", *sorted(hashes)))
            kept += 1
    print(f"{kept} functions stored, {dropped} no longer describable, {not_unique} not unique by name and kinds")


def read_golden(golden_dir, replay):
    return list(csv.DictReader(open(f"{golden_dir}/{replay}.tsv", encoding="utf-8"), delimiter="\t", quoting=csv.QUOTE_NONE))


def spec(golden_dir, replay, exe, pdb, out_path):
    build = Build(exe, pdb)
    entries, changed = [], []
    for row in read_golden(golden_dir, replay):
        ident = int(row["va"], 16)
        matches = []
        for candidate in build.by_name.get(row["name"], []):
            described = build.describe(candidate)
            if described and without_struct_sizes(kinds_text(described)) == without_struct_sizes(row["params"]):
                matches.append((candidate, described))
        if len(matches) != 1:
            changed.append(row["name"])
            continue
        (rva, _, _, _, _), (_, params, locations, pop) = matches[0]
        args = []
        for index in map(int, row["hashed"].split()):
            kind, words = params[index]
            args.append((locations[index], words, 1, 1 if kind in (sc.FLOAT, sc.DOUBLE) else 0))
        entries.append((rva, pop, 8, int(row["result"]), args, ident))
    if not any(e[5] == sc.SIM_ENTRY for e in entries):
        candidate = build.by_name["moho::Sim::AdvanceBeat"][0]
        described = build.describe(candidate)
        entries.append((candidate[0], described[3], 8, sc.RET_NONE, [], sc.SIM_ENTRY))
    sc.write_spec(out_path, 1, entries)
    with open(out_path + ".changed", "w", encoding="utf-8", newline="\n") as f:
        f.writelines(name + "\n" for name in changed)
    print(f"{len(entries)} functions hooked, {len(changed)} changed signature or are gone")


def check(golden_dir, replay, ours_sets, spec_path):
    stored = compare_sets.read_sets(f"{golden_dir}/{replay}.sets")
    ours = compare_sets.read_sets(ours_sets)
    changed = open(spec_path + ".changed", encoding="utf-8").read().split("\n")
    changed = [c for c in changed if c]
    passed, failed, unrun = 0, [], []
    rows = {int(r["va"], 16): r for r in read_golden(golden_dir, replay)}
    for ident, row in rows.items():
        if row["name"] in changed:
            continue
        mine = ours.get(ident)
        if mine is None or mine["recorded"] == 0:
            unrun.append(row)
            continue
        level = max(stored[ident]["level"], mine["level"])
        missing = compare_sets.sample(stored[ident]["hashes"], level) - compare_sets.sample(mine["hashes"], level)
        if missing:
            failed.append((len(missing), stored[ident]["level"], row))
        else:
            passed += 1
    print(f"replay {replay}: {passed} functions pass, {len(failed)} differ, {len(unrun)} not called, {len(changed)} changed signature")
    # One bug spreads through the game, so the function at fault is often not the
    # one with the most missing hashes: the whole list goes to a file.
    lines = [
        f"DIFFERS {row['va']} {count} stored hashes missing: {row['name']} ({row['file']}:{row['line']})"
        for count, _, row in sorted(failed, key=lambda f: -f[0])
    ]
    lines += [f"NOT CALLED {row['va']} {row['name']} ({row['file']}:{row['line']})" for row in unrun]
    lines += [f"CHANGED {name}" for name in changed]
    with open(spec_path + ".report", "w", encoding="utf-8", newline="\n") as f:
        f.writelines(line + "\n" for line in lines)
    for line in lines[:40]:
        print("  " + line)
    if lines:
        print(f"  all {len(lines)} lines: {spec_path}.report")
    return 1 if lines else 0


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "make" and len(sys.argv) == 10:
        make(*sys.argv[2:])
    elif command == "spec" and len(sys.argv) == 7:
        spec(*sys.argv[2:])
    elif command == "check" and len(sys.argv) == 6:
        sys.exit(check(*sys.argv[2:]))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
