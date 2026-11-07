#!/usr/bin/env python3
"""Compares the Lua `Sync` a player gets from the server's routing with what a lockstep client of
that army builds, per beat and per key (plan §8, WP6.9, WPR.39).

    headless ... --focus 2 --sync-dump focus2.bin            a lockstep client of army 2 (0-based)
    headless ... --view-bench b.csv --lua-routing --lua-routing-dump routed   writes routed_2.bin ...
    compare.py focus2.bin routed_2.bin

Both files hold one record per beat: beat and size as little-endian 32-bit numbers, then the table as
`LuaObject::ToByteStream` encodes it. Prints each key with beats in which it matches, beats it's
missing from the routed table, beats it's extra, and beats it differs, with an example of each.
Exit code 1 if any key differs in any way.

A lockstep client gets every unit's death in `UnitData` and `ReleaseIds`, and the server keeps those
with the unit's owner. `--army` (0-based, the view's army) leaves other armies' out of the reference.

A lockstep client also gets every reclaim label, and the server sends a later one only once the player
sees the spot. So `Reclaim` is checked apart: each label the player gets must be one the lockstep client
got by then; the map's first ones must arrive on their beat; the rest is printed as held back.
"""
import argparse
import collections
import struct
import sys

TAG_NUMBER, TAG_STRING, TAG_NIL, TAG_BOOL, TAG_BEGIN, TAG_END = 0, 1, 2, 3, 4, 5


def decode(data, pos=0):
    tag = data[pos]
    pos += 1
    if tag == TAG_NUMBER:
        return struct.unpack_from("<f", data, pos)[0], pos + 4
    if tag == TAG_STRING:
        end = data.index(0, pos)
        return data[pos:end].decode("latin1"), end + 1
    if tag == TAG_NIL:
        return None, pos
    if tag == TAG_BOOL:
        return data[pos] != 0, pos + 1
    if tag == TAG_BEGIN:
        table = {}
        while data[pos] != TAG_END:
            key, pos = decode(data, pos)
            value, pos = decode(data, pos)
            table[key] = value
        return table, pos + 1
    raise ValueError("bad tag %d at %d" % (tag, pos - 1))


def records(path):
    with open(path, "rb") as f:
        data = f.read()
    pos = 0
    while pos + 8 <= len(data):
        beat, size = struct.unpack_from("<II", data, pos)
        pos += 8
        yield beat, data[pos:pos + size]
        pos += size


def normal(value):
    """A list's order is what its writers made it, which routing changes; everything else must match."""
    if isinstance(value, dict):
        if value and all(isinstance(k, float) and k == int(k) for k in value):
            return tuple(sorted((repr(normal(v)) for v in value.values())))
        return tuple(sorted((repr(k), repr(normal(v))) for k, v in value.items()))
    return value


def empty(value):
    return isinstance(value, dict) and not value


def drop_foreign_deaths(table, army):
    for key in ("UnitData", "ReleaseIds"):
        entries = table.get(key)
        if isinstance(entries, dict):
            for entity in [k for k, v in entries.items() if isinstance(v, bool) and isinstance(k, str) and k.isdigit()]:
                if (int(entity) >> 20) & 0xFF != army:
                    del entries[entity]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reference", help="--sync-dump of a run focused on the army")
    ap.add_argument("routed", help="that army's --lua-routing-dump file")
    ap.add_argument("--examples", type=int, default=1)
    ap.add_argument("--army", type=int, help="the view's army, for the deaths the server keeps with their owner")
    ap.add_argument("--from-beat", type=int, default=0, help="compare from this beat on")
    args = ap.parse_args()

    reference = {beat: bytes(body) for beat, body in records(args.reference)}
    routed = {beat: bytes(body) for beat, body in records(args.routed)}
    beats = sorted(beat for beat in set(reference) & set(routed) if beat >= args.from_beat)
    counts = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(list)
    labels = {}
    reclaim = collections.Counter()
    reclaim_bad = []
    for beat in sorted(b for b in reference if b < args.from_beat and reference[b]):
        for entity, value in (decode(reference[beat])[0].get("Reclaim") or {}).items():
            labels.setdefault(entity, set()).add(repr(normal(value)))
    for beat in beats:
        want = decode(reference[beat])[0] if reference[beat] else {}
        got = decode(routed[beat])[0] if routed[beat] else {}
        if args.army is not None:
            drop_foreign_deaths(want, args.army)
        for entity, value in (want.get("Reclaim") or {}).items():
            labels.setdefault(entity, set()).add(repr(normal(value)))
            reclaim["told"] += 1
        for entity, value in (got.get("Reclaim") or {}).items():
            reclaim["got"] += 1
            if repr(normal(value)) not in labels.get(entity, ()):
                reclaim_bad.append((beat, entity, value))
        if beat <= 1 and normal(want.get("Reclaim")) != normal(got.get("Reclaim")):
            reclaim_bad.append((beat, "first labels", None))
        want.pop("Reclaim", None)
        got.pop("Reclaim", None)
        for key in sorted(set(want) | set(got), key=str):
            a = want.get(key)
            b = got.get(key)
            if a is None or empty(a):
                kind = "same" if b is None or empty(b) else "extra"
            elif b is None or empty(b):
                kind = "missing"
            else:
                kind = "same" if normal(a) == normal(b) else "differs"
            counts[key][kind] += 1
            if kind != "same" and len(examples[(key, kind)]) < args.examples:
                examples[(key, kind)].append((beat, a, b))

    print("beats compared %d (reference %d, routed %d)" % (len(beats), len(reference), len(routed)))
    bad = bool(reclaim_bad)
    print("Reclaim: lockstep told %d, player got %d, not as lockstep %d" % (reclaim["told"], reclaim["got"], len(reclaim_bad)))
    for example in reclaim_bad[:args.examples]:
        print("    %s" % repr(example)[:150])
    for key in sorted(counts, key=str):
        c = counts[key]
        if c["missing"] or c["extra"] or c["differs"]:
            bad = True
        print("%-28s same %6d  missing %5d  extra %5d  differs %5d" % (key, c["same"], c["missing"], c["extra"], c["differs"]))
        for kind in ("missing", "extra", "differs"):
            for beat, a, b in examples[(key, kind)]:
                print("    %s beat %d: focused %s" % (kind, beat, repr(a)[:150]))
                print("    %s beat %d: routed  %s" % (kind, beat, repr(b)[:150]))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
