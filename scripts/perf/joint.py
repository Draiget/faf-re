"""How the sim and main threads overlap in sampler64.py windows.

usage: python scripts/perf/joint.py <win.json...>     (env NJ=<rows> for longer lists)

Prints the share of sampling rounds in which the main thread and the sim thread were each busy
or waiting ("main+sim" both busy, "-+-" both waiting), then, for each state of one thread, the
inclusive profile of the other: for example what the main thread was doing while the sim waited.
A large "-+-" share or long one-sided waits point at pacing between the threads, not CPU cost.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prof64 import thread_of  # noqa: E402


def main():
    states = collections.Counter()
    during = collections.Counter()
    for path in sys.argv[1:]:
        w = json.load(open(path))
        names = w["names"]
        main_tid, sim_tid = thread_of(w, "main"), thread_of(w, "sim")
        for busy_tids, count in w.get("joint", []):
            busy = set(map(str, busy_tids))
            states[("main" if main_tid in busy else "-", "sim" if sim_tid in busy else "-")] += count
        for x, x_busy, y, f, count in w.get("cond", []):
            x, y = str(x), str(y)
            if x == sim_tid and y == main_tid:
                during[("sim busy" if x_busy else "sim WAIT", names[f])] += count
            elif x == main_tid and y == sim_tid:
                during[("main busy" if x_busy else "main WAIT", names[f])] += count

    total = sum(states.values())
    print("joint states (%d rounds):" % total)
    for key, count in states.most_common():
        print("  %-12s %5.1f%%" % ("+".join(key), 100.0 * count / max(total, 1)))

    rows = int(os.environ.get("NJ", 25))
    for state in ("sim WAIT", "sim busy", "main WAIT", "main busy"):
        entries = [(count, f) for (s, f), count in during.items() if s == state]
        if not entries:
            continue
        base = max(count for count, _ in entries)
        print()
        print("while %s, %s is in:" % (state, "main" if state.startswith("sim") else "sim"))
        for count, f in sorted(entries, reverse=True)[:rows]:
            print("  %5.1f%% %s" % (100.0 * count / base, f[:120]))


if __name__ == "__main__":
    main()
