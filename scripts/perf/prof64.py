"""Analysis of sampler64.py windows.

usage:
  python scripts/perf/prof64.py curve <prof_dir> [<prof_dir2>]
      sim and main thread CPU ms per sim tick for each window; with two directories, windows are
      matched by tick and the ratio is printed (B/A)
  python scripts/perf/prof64.py frames <win.json...>
      rendered frames per second, wall ms per frame and main-thread CPU ms per frame per window
      (windows recorded by a sampler64.py that found MeshInstance::sFrameCounter)
  python scripts/perf/prof64.py top <thread> <win.json...> [-n N]
      flat (leaf) and inclusive profile of one thread
  python scripts/perf/prof64.py under <thread> <func> <win.json...> [-n N]
      inclusive time of <func> split by its direct callees ("<self>" = in the function itself)
  python scripts/perf/prof64.py callers <thread> <func> <win.json...> [-n N]
      who calls <func>

<thread> is main (the thread running WinMain), sim (the thread running Sim::AdvanceBeat) or a
thread id. <func> is the full symbol name as printed by `top`. Percentages are of all samples of
that thread; samples are wall-clock, so waits count ("busy" excludes samples whose leaf frame is
a wait in ntdll/win32u/kernelbase).
"""
import collections
import glob
import json
import os
import sys

WAITS = ("NtWaitFor", "ZwWaitFor", "NtDelayExecution", "ZwDelayExecution", "NtUserMsgWaitForMultipleObjectsEx",
         "NtUserWaitMessage", "NtRemoveIoCompletion", "NtWaitForAlertByThreadId", "ZwWaitForAlertByThreadId",
         "NtUserGetMessage", "NtUserPeekMessage")


def load(paths):
    wins = []
    for p in paths:
        w = json.load(open(p))
        wins.append(w)
    return wins


def thread_of(w, which):
    names = w["names"]
    want = {"main": ("WinMain", "moho::WIN_AppExecute"), "sim": ("moho::Sim::AdvanceBeat",)}.get(which)
    if want is None:
        return which
    best = (0, None)
    for t, k, v in w["incl"]:
        if names[k] in want and v > best[0]:
            best = (v, str(t))
    return best[1]


def is_wait(name):
    return any(x in name for x in WAITS)


def curve(d):
    rows = []
    for f in sorted(glob.glob(os.path.join(d, "win_*.json"))):
        w = json.load(open(f))
        s, e = w.get("sim_start"), w.get("sim_end")
        if not s or not e or e["tick"] <= s["tick"]:
            continue
        ticks = e["tick"] - s["tick"]
        main, sim = thread_of(w, "main"), thread_of(w, "sim")
        cpu = w["cpu_100ns"]
        rows.append({"t0": s["tick"], "t1": e["tick"], "units": (e.get("families") or {}).get("unit"),
                     "sim": cpu.get(sim, 0) / 1e4 / ticks, "main": cpu.get(main, 0) / 1e4 / ticks,
                     "rate": ticks / float(w.get("window_s", 60.0))})
    return rows


def at(rows, tick):
    pts = [((r["t0"] + r["t1"]) / 2, r) for r in rows]
    for (x0, r0), (x1, r1) in zip(pts, pts[1:]):
        if x0 <= tick <= x1:
            f = (tick - x0) / (x1 - x0)
            return {k: r0[k] + (r1[k] - r0[k]) * f for k in ("sim", "main")}
    return None


def main():
    cmd = sys.argv[1]
    if cmd == "curve":
        a = curve(sys.argv[2])
        if len(sys.argv) == 3:
            print("ticks            units  ticks/s  sim ms/tick  main ms/tick")
            for r in a:
                print("%6d-%-6d  %6s  %6.1f  %10.2f  %11.2f" % (r["t0"], r["t1"], r["units"], r["rate"], r["sim"], r["main"]))
            return
        b = curve(sys.argv[3])
        tot = [0, 0, 0, 0]
        print("tick    units   A sim   B sim   B/A    A main  B main  B/A")
        for r in a:
            mid = (r["t0"] + r["t1"]) / 2
            o = at(b, mid)
            if not o:
                continue
            tot[0] += r["sim"]; tot[1] += o["sim"]; tot[2] += r["main"]; tot[3] += o["main"]
            print("%6d  %6s  %6.2f  %6.2f  %5.3f  %6.2f  %6.2f  %5.3f" % (
                mid, r["units"], r["sim"], o["sim"], o["sim"] / max(r["sim"], 1e-9), r["main"], o["main"],
                o["main"] / max(r["main"], 1e-9)))
        if tot[0]:
            print("overall sim B/A %.3f, main B/A %.3f" % (tot[1] / tot[0], tot[3] / max(tot[2], 1e-9)))
        return

    if cmd == "frames":
        print("window  frames    fps  ms/frame  main cpu ms/frame")
        for w in load(sys.argv[2:]):
            frames, secs = w.get("frames"), float(w.get("window_s", 60.0))
            if not frames:
                print("%6s  (no frame count)" % w.get("window"))
                continue
            cpu = w["cpu_100ns"].get(thread_of(w, "main"), 0) / 1e4
            print("%6s  %6d  %5.1f  %8.1f  %17.1f" % (w.get("window"), frames, frames / secs, 1000.0 * secs / frames,
                                                       cpu / frames))
        return

    which = sys.argv[2]
    n = 40
    args = sys.argv[3:]
    if "-n" in args:
        i = args.index("-n")
        n = int(args[i + 1])
        del args[i:i + 2]
    func = None
    if cmd in ("under", "callers"):
        func, args = args[0], args[1:]
    wins = load(args)
    flat, incl, tot, busy = collections.Counter(), collections.Counter(), 0, 0
    split = collections.Counter()
    fsamples = 0
    for w in wins:
        names = w["names"]
        tid = thread_of(w, which)
        if tid is None:
            continue
        tot += w["samples"].get(tid, 0)
        for t, c, v in w["chains"]:
            if str(t) != tid:
                continue
            ch = [names[k] for k in c]
            if not is_wait(ch[0]):
                busy += v
            if cmd == "top":
                flat[ch[0]] += v
                for f in set(ch):
                    incl[f] += v
            else:
                idx = [i for i, f in enumerate(ch) if f == func]
                if not idx:
                    continue
                i = max(idx)  # outermost occurrence
                fsamples += v
                if cmd == "under":
                    split[ch[i - 1] if i > 0 else "<self>"] += v
                else:
                    split[ch[i + 1] if i + 1 < len(ch) else "<root>"] += v
    print("samples %d, busy %d (%.1f%%)" % (tot, busy, 100.0 * busy / max(tot, 1)))
    if cmd == "top":
        print("-- flat")
        for k, v in flat.most_common(n):
            print("%6.2f%% %s" % (100.0 * v / tot, k[:150]))
        print("-- inclusive")
        for k, v in incl.most_common(n):
            print("%6.2f%% %s" % (100.0 * v / tot, k[:150]))
    else:
        print("%s: %.2f%% of thread" % (func, 100.0 * fsamples / max(tot, 1)))
        for k, v in split.most_common(n):
            print("%6.2f%% (%5.1f%% of it) %s" % (100.0 * v / tot, 100.0 * v / max(fsamples, 1), k[:150]))


if __name__ == "__main__":
    main()
