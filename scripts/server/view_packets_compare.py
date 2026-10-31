"""Sync equivalence (plan WPR.3): the server routes every army its own packet, rebuilt from one
unfocused sim (remote/ViewPackets.h); each army's packet there must equal the packet the sim builds
itself when it is focused on that army, beat by beat.

Input: headless `--view-packets <army> <file>` files, one from an unfocused run (`--focus -1`, the
routed packet) and one focused on the army (the reference), named `vp_<replay>_a<army>_f-1.vp` and
`vp_<replay>_a<army>_f<army>.vp` in one folder. Each line is "beat", six lane sizes, six lane
digests and, from WP5.4 on, the army lane's digest. With `--view-packets-entries` each run also
wrote `<same name>.vpe`, one line per record ("beat lane id digest"); for every beat whose lines
differ, the records are listed: MISSING from the routed packet, EXTRA in it, or CHANGED. Ids are
compared as the sim assigns them (no per-view id mapping yet).

A pair that matches on every beat both played but played a different number of trailing beats
counts as matching ("tail-only"), as in focus_gate.py: after a replay's recorded commands end, the
number of extra beats depends on thread timing.

usage:
  view_packets_compare.py <folder>

Prints one line per pair, the differing records under it, and a summary line; exit code 0 when no
pair differs.
"""

import glob
import os
import re
import sys

LANES = ["creates", "unit-creates", "entity-updates", "unit-updates", "deletes", "erases"]
ENTRY_LANES = {"c": "create", "u": "unit-create", "e": "entity-update", "n": "unit-update", "d": "delete", "x": "erase"}
MAX_ENTRY_LINES = 40


def read_lines(path):
    rows = {}
    with open(path, errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) in (13, 14):
                rows[int(parts[0])] = parts
    return rows


def read_entries(path, beats):
    entries = {}
    with open(path, errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 4 and int(parts[0]) in beats:
                entries[(int(parts[0]), parts[1], parts[2])] = parts[3]
    return entries


def print_entries(routed_path, reference_path, beats):
    if not (os.path.exists(routed_path) and os.path.exists(reference_path)):
        print("  ENTRIES not written (run both with --view-packets-entries)")
        return
    routed, reference = read_entries(routed_path, beats), read_entries(reference_path, beats)
    rows = []
    for key in sorted(set(routed) | set(reference)):
        if key not in routed:
            rows.append(("MISSING", key))
        elif key not in reference:
            rows.append(("EXTRA", key))
        elif routed[key] != reference[key]:
            rows.append(("CHANGED", key))
    counts = {}
    for kind, _ in rows:
        counts[kind] = counts.get(kind, 0) + 1
    print("  ENTRIES %s" % (" ".join("%s=%d" % item for item in sorted(counts.items())) or "none differ"))
    for kind, (beat, lane, entity_id) in rows[:MAX_ENTRY_LINES]:
        print("  %-7s beat %d %s %s" % (kind, beat, ENTRY_LANES.get(lane, lane), entity_id))
    if len(rows) > MAX_ENTRY_LINES:
        print("  ... %d more" % (len(rows) - MAX_ENTRY_LINES))


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    folder = argv[1]
    pairs = differing = 0
    for routed_path in sorted(glob.glob(os.path.join(folder, "vp_*_f-1.vp"))):
        match = re.match(r"vp_(\d+)_a(\d+)_f-1\.vp", os.path.basename(routed_path))
        if match is None:
            continue
        replay, army = match.group(1), int(match.group(2))
        reference_path = os.path.join(folder, "vp_%s_a%d_f%d.vp" % (replay, army, army))
        pairs += 1
        if not os.path.exists(reference_path):
            print("VIEWPACKETS %s army=%d MISSING focused run" % (replay, army))
            differing += 1
            continue
        routed, reference = read_lines(routed_path), read_lines(reference_path)
        common = sorted(set(routed) & set(reference))
        bad = [beat for beat in common if routed[beat] != reference[beat]]
        lanes = {}
        for beat in bad:
            for i, name in enumerate(LANES):
                if routed[beat][1 + i] != reference[beat][1 + i] or routed[beat][7 + i] != reference[beat][7 + i]:
                    lanes[name] = lanes.get(name, 0) + 1
            if len(routed[beat]) == 14 and routed[beat][13] != reference[beat][13]:
                lanes["armies"] = lanes.get("armies", 0) + 1
        if bad:
            verdict = "differ first=%d lanes=%s" % (bad[0], lanes)
            differing += 1
        elif len(routed) != len(reference):
            verdict = "tail-only"
        else:
            verdict = "identical"
        print("VIEWPACKETS %s army=%d beats=%d/%d common=%d %s" % (replay, army, len(routed), len(reference), len(common), verdict))
        if bad:
            print_entries(routed_path + "e", reference_path + "e", set(bad))
    print("VIEWPACKETS SUMMARY pairs=%d differ=%d" % (pairs, differing))
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
