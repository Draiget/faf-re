"""Oracle digest compare (plan WP4.1): the server asks the visibility oracle about every army from
one unfocused sim, so each army's answers there must equal its answers in a sim focused on it.

Input: headless `--oracle-digests` files. Each line is "beat army entities visible digest". The
unfocused run (`--focus -1`) has a line for every army each beat; a focused run has lines for its
focus army only. For every focused file, each of its lines is compared with the unfocused run's
line for the same beat and army.

A focused run that matches on every beat both played but played a different number of trailing
beats counts as matching ("tail-only"), as in focus_gate.py: after a replay's recorded commands
end, the number of extra beats depends on thread timing.

usage:
  oracle_digest_compare.py <unfocused.digests> <focused.digests> [<focused.digests> ...]

Prints one line per focused file and a summary line; exit code 0 when no file differs.
"""

import sys


def read_digests(path):
    lines = {}
    with open(path, errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) != 5:
                continue
            beat, army = int(parts[0]), int(parts[1])
            lines[(beat, army)] = (int(parts[2]), int(parts[3]), parts[4])
    return lines


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    base = read_digests(argv[1])
    base_beats = {}
    for beat, army in base:
        base_beats[army] = max(base_beats.get(army, -1), beat)

    failed = 0
    for path in argv[2:]:
        focused = read_digests(path)
        armies = sorted({army for _, army in focused})
        if len(armies) != 1:
            print("ORACLEDIGEST %s armies=%s FAILED (a focused run has lines for one army)" % (path, armies))
            failed += 1
            continue
        army = armies[0]
        compared = 0
        first_diff = None
        missing = 0
        for (beat, _), value in sorted(focused.items()):
            other = base.get((beat, army))
            if other is None:
                missing += 1
                continue
            compared += 1
            if other != value and first_diff is None:
                first_diff = (beat, value, other)
        last_focused = max(beat for beat, _ in focused)
        tail = missing > 0 and all(beat > base_beats.get(army, -1) for (beat, _) in focused if (beat, army) not in base)
        if first_diff is not None:
            beat, value, other = first_diff
            verdict = "differ first-beat=%d focused=%s unfocused=%s" % (beat, value, other)
            failed += 1
        elif missing and not tail:
            verdict = "differ (%d beats missing from the unfocused run)" % missing
            failed += 1
        else:
            verdict = "identical" if not missing else "tail-only"
        print("ORACLEDIGEST %s army=%d beats=%d last=%d %s" % (path, army, compared, last_focused, verdict))
    print("ORACLEDIGEST SUMMARY files=%d differ=%d" % (len(argv) - 2, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
