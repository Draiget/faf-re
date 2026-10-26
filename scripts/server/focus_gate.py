"""Focus gate (plan WPR.2): a replay's sim must not depend on the army whose view it builds.

Plays each replay with faf-replay at focus -1 (an observer) and at chosen armies, every run with
`--checksum-period 1` (the sim's checksum on every beat), and compares the per-beat digests of
each focus run with the -1 run's. Prints one verdict line per replay and a summary line; the exit
code is 0 when no run differs.

Only the sim checksum is compared. `--state-digests` is not: what a sim publishes to its client
is filtered by the focus army on purpose, so it differs between foci by design.

A run that matches the -1 run on every beat both played, but played a different number of
trailing beats, counts as matching ("tail-only"): after the end of a replay's recorded commands
the number of extra beats depends on thread timing (plan §12).

usage:
  focus_gate.py --exe <faf-replay.exe> --init <init.lua> --replay-dir <dir> [options] [replay id ...]

  replay ids          default: the core set of docs/PR_REPLAY_CHECK.md; or --ids-file <file>
  --replay-dir        holds <id>.scfareplay or vault_<id>.scfareplay
  --armies all|ends|N[,M...]
                      all (default): every army; ends: the first and the last army;
                      a list: those armies (skipped where a replay has fewer)
  --jobs N            faf-replay processes at a time (default 2)
  --jobs-file F       re-read on every scheduling step: when it holds a number, that is the limit
                      (lets other work borrow a slot without restarting the gate)
  --out DIR           digests, logs and outputs (default ./focus_gate_out)
  --before-start CMD  a command run (through the shell) before each faf-replay start; it may block,
                      e.g. a machine-wide game-instance limit ("bash game_slots.sh wait 1")
  --simworkers N      passed through (default 8)
  --timeout MIN       per run (default 180)
  --label TAG         prefix of every run's label and file (default fg)
  M28AI replays (the vault's mods/M28AI must hold the version the replay was recorded with):
  --m28-versions F    lines "<id> <version>" (0: the replay does not use M28AI)
  --vault DIR         the vault the init file mounts; its mods/M28AI is swapped per replay
  --modcache DIR      holds m28ai.vNNNN/M28AI for every version
  --markers DIR       a folder of "version in use" files that other runners share; runs of
                      different versions never overlap; repeatable, this gate's own files go
                      to the first (default: none)
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time

CORE_SET = ["26902315", "26930624", "26943656", "26883423", "26881085", "26928211", "26989770", "26897073"]


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("ids", nargs="*")
    p.add_argument("--exe", required=True)
    p.add_argument("--init", required=True)
    p.add_argument("--replay-dir", required=True)
    p.add_argument("--ids-file")
    p.add_argument("--armies", default="all")
    p.add_argument("--jobs", type=int, default=2)
    p.add_argument("--jobs-file")
    p.add_argument("--out", default="focus_gate_out")
    p.add_argument("--simworkers", type=int, default=8)
    p.add_argument("--before-start")
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--label", default="fg")
    p.add_argument("--m28-versions")
    p.add_argument("--vault")
    p.add_argument("--modcache")
    p.add_argument("--markers", action="append", default=[])
    return p.parse_args()


def read_ids(args):
    if args.ids_file:
        with open(args.ids_file) as f:
            return [line.split()[0] for line in f if line.strip() and not line.startswith("#")]
    return args.ids or list(CORE_SET)


def read_versions(path):
    versions = {}
    if path:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    versions[parts[0]] = int(parts[1])
    return versions


def replay_path(replay_dir, rid):
    for name in ("%s.scfareplay" % rid, "vault_%s.scfareplay" % rid):
        path = os.path.join(replay_dir, name)
        if os.path.isfile(path):
            return os.path.abspath(path)
    return None


def load_digests(path):
    out = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    out.append((int(parts[0]), parts[1]))
    except OSError:
        return None
    return out


def compare(base, other):
    """'same', 'tail-only' or ('differ', first differing beat)."""
    n = min(len(base), len(other))
    for i in range(n):
        if base[i] != other[i]:
            return ("differ", base[i][0] if base[i][0] == other[i][0] else min(base[i][0], other[i][0]))
    return ("same", None) if len(base) == len(other) else ("tail-only", None)


class VaultGuard:
    """Runs of M28AI version v run only while no run of another nonzero version does."""

    def __init__(self, args):
        self.vault = args.vault
        self.modcache = args.modcache
        self.markers = args.markers
        self.lock = threading.Lock()
        self.running = {}  # label -> version

    def _others_busy(self, version):
        if any(v != 0 and v != version for v in self.running.values()):
            return True
        for folder in self.markers:
            if not os.path.isdir(folder):
                continue
            for name in os.listdir(folder):
                if name.startswith("fg_self_"):
                    continue
                try:
                    with open(os.path.join(folder, name)) as f:
                        v = int(f.read().strip() or "0")
                except (OSError, ValueError):
                    continue
                if v != 0 and v != version:
                    return True
        return False

    def try_acquire(self, label, version):
        with self.lock:
            if version != 0:
                if self._others_busy(version):
                    return False
                if self.vault and self.modcache:
                    target = os.path.join(self.vault, "mods", "M28AI")
                    stamp = os.path.join(target, ".faf_version")
                    current = None
                    try:
                        with open(stamp) as f:
                            current = int(f.read().strip())
                    except (OSError, ValueError):
                        pass
                    if current != version:
                        if any(v != 0 for v in self.running.values()):
                            return False  # someone uses the vault's current version
                        shutil.rmtree(target, ignore_errors=True)
                        shutil.copytree(os.path.join(self.modcache, "m28ai.v%04d" % version, "M28AI"), target)
                        with open(stamp, "w") as f:
                            f.write("%d\n" % version)
            self.running[label] = version
            if self.markers:
                os.makedirs(self.markers[0], exist_ok=True)
                with open(os.path.join(self.markers[0], "fg_self_" + label), "w") as f:
                    f.write("%d\n" % version)
            return True

    def release(self, label):
        with self.lock:
            self.running.pop(label, None)
            if self.markers:
                try:
                    os.remove(os.path.join(self.markers[0], "fg_self_" + label))
                except OSError:
                    pass


def run_one(args, rid, focus, path):
    label = "%s_%s_f%d" % (args.label, rid, focus)
    out_dir = os.path.abspath(args.out)
    digests = os.path.join(out_dir, label + ".digests")
    cmd = [args.exe, "--label", label, "--replay", path, "/init", args.init, "/nobugreport", "/nosound",
           "/log", os.path.join(out_dir, label + ".log"), "/simworkers", str(args.simworkers),
           "--focus", str(focus), "--checksum-period", "1", "--digests", digests,
           "--timeout", str(args.timeout)]
    start = time.time()
    with open(os.path.join(out_dir, label + ".out"), "w") as out:
        rc = subprocess.call(cmd, cwd=os.path.dirname(os.path.abspath(args.exe)), stdout=out, stderr=subprocess.STDOUT)
    text = open(os.path.join(out_dir, label + ".out"), errors="replace").read()
    m = re.search(r"loaded in [0-9.]+s: (\d+) armies", text)
    armies = int(m.group(1)) if m else None
    verdict = re.findall(r"VERDICT [^\r\n]*", text)
    return {"rc": rc, "armies": armies, "digests": digests, "wall": time.time() - start,
            "verdict": verdict[-1] if verdict else "VERDICT missing"}


def current_jobs(args):
    if args.jobs_file:
        try:
            with open(args.jobs_file) as f:
                return max(0, int(f.read().strip()))
        except (OSError, ValueError):
            pass
    return args.jobs


def pick_armies(spec, count):
    if spec == "all":
        return list(range(count))
    if spec == "ends":
        return sorted({0, count - 1}) if count > 0 else []
    return [a for a in (int(x) for x in spec.split(",")) if 0 <= a < count]


def main():
    args = parse_args()
    os.makedirs(args.out, exist_ok=True)
    ids = read_ids(args)
    versions = read_versions(args.m28_versions)
    guard = VaultGuard(args)
    lock = threading.Lock()
    results = {}  # rid -> {"base": run, "foci": {focus: run}}
    pending = [(rid, -1) for rid in ids]  # base runs first, focus runs added when a base ends
    active = []
    summary = {"replays": 0, "runs": 0, "same": 0, "tail": 0, "differ": 0, "failed": 0}
    printed = set()

    def finish_replay(rid):
        entry = results[rid]
        base = load_digests(entry["base"]["digests"])
        parts, differ = [], []
        same = tail = 0
        for focus in sorted(entry["foci"]):
            run = entry["foci"][focus]
            other = load_digests(run["digests"])
            summary["runs"] += 1
            if base is None or other is None or not other:
                differ.append("%d: no digests (%s)" % (focus, run["verdict"]))
                summary["failed"] += 1
                continue
            kind, beat = compare(base, other)
            if kind == "same":
                same += 1
            elif kind == "tail-only":
                tail += 1
                parts.append("%d tail (%d vs %d beats)" % (focus, len(other), len(base)))
            else:
                differ.append("%d: first differing beat %d" % (focus, beat))
        summary["same"] += same
        summary["tail"] += tail
        summary["differ"] += len(differ)
        summary["replays"] += 1
        line = "FOCUSGATE %s armies=%s beats=%d foci=%s identical=%d tail-only=%d differ=%d | base %s%s%s" % (
            rid, entry["base"]["armies"], len(base or []), ",".join(str(f) for f in sorted(entry["foci"])),
            same, tail, len(differ), entry["base"]["verdict"],
            (" | " + "; ".join(parts)) if parts else "", (" | DIFFER " + "; ".join(differ)) if differ else "")
        print(line, flush=True)
        printed.add(rid)

    def worker(rid, focus, path, version):
        label = "%s_%s_f%d" % (args.label, rid, focus)
        try:
            run = run_one(args, rid, focus, path)
        finally:
            guard.release(label)
        with lock:
            entry = results.setdefault(rid, {"base": None, "foci": {}, "expected": None})
            if focus == -1:
                entry["base"] = run
                if run["armies"] is None:
                    print("FOCUSGATE %s base run did not load | %s" % (rid, run["verdict"]), flush=True)
                    summary["failed"] += 1
                    printed.add(rid)
                    return
                foci = pick_armies(args.armies, run["armies"])
                entry["expected"] = len(foci)
                for f in foci:
                    pending.append((rid, f))
                if not foci:
                    finish_replay(rid)
            else:
                entry["foci"][focus] = run
                if len(entry["foci"]) == entry["expected"]:
                    finish_replay(rid)

    print("FOCUSGATE START %s exe=%s armies=%s ids=%s" % (time.strftime("%Y-%m-%d %H:%M:%S"), args.exe, args.armies,
                                                          " ".join(ids)), flush=True)
    while True:
        with lock:
            active[:] = [t for t in active if t.is_alive()]
            done = not pending and not active
            if not done and len(active) < current_jobs(args):
                # Focus runs of a replay whose base has ended go first, then the next base.
                pending.sort(key=lambda item: (item[1] == -1,))
                for index, (rid, focus) in enumerate(pending):
                    path = replay_path(args.replay_dir, rid)
                    if path is None:
                        pending.pop(index)
                        print("FOCUSGATE %s replay file missing" % rid, flush=True)
                        summary["failed"] += 1
                        printed.add(rid)
                        break
                    version = versions.get(rid, 0)
                    label = "%s_%s_f%d" % (args.label, rid, focus)
                    if guard.try_acquire(label, version):
                        if args.before_start:
                            subprocess.call(args.before_start, shell=True)
                        pending.pop(index)
                        thread = threading.Thread(target=worker, args=(rid, focus, path, version), daemon=True)
                        thread.start()
                        active.append(thread)
                        break
        if done:
            break
        time.sleep(2)
    for rid in ids:
        if rid not in printed:
            print("FOCUSGATE %s incomplete (a run failed to start or report)" % rid, flush=True)
            summary["failed"] += 1
    print("FOCUSGATE SUMMARY %s replays=%d focus-runs=%d identical=%d tail-only=%d differ=%d failed=%d" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), summary["replays"], summary["runs"], summary["same"], summary["tail"],
        summary["differ"], summary["failed"]), flush=True)
    return 0 if summary["differ"] == 0 and summary["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
