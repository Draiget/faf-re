"""Plays one shard of a parity plan on headless and writes a result per replay.

usage: shard.py --plan plan.json --shard N --headless EXE --pack DIR --replays DIR --maps DIR
                --m28 DIR --work DIR --out DIR [--minutes M] [--slots N] [--simworkers N]

Runs --slots replays at once (default: one per CPU). Whenever a slot is free it starts the
longest replay left whose estimated time still fits before --minutes are up; what no longer fits
is reported as not run, so the job ends inside its time limit. A replay, map or M28AI version
missing from the caches is downloaded from FAF (one request at a time).

Verdicts are the parity runner's (tools/replay-parity/parity.py, HeadlessGame): pass, desync
(first mismatched beat; the replay is stopped), incomplete, crash, timeout; plus unsupported
(the replay needs a sim mod or another game version), error (the replay, its map or M28AI could
not be got ready) and not-run (no time left in the job, or stopped at its time limit; a later run
with --after picks those up). What fits is judged by the plan's estimates times the ratio of
measured to estimated time of the replays the job has finished. A mismatch is the live game's,
not ours, when more of the recorded clients agree with the sim at that beat than with the one
that differs; that client is not counted again for the rest of the game (live_desyncs).

Writes DIR/results.jsonl (one line per replay) and DIR/logs/<id>.out/.log for every replay that
did not pass. Every 30 seconds the job log gets a progress block: the shard's replays done, game
time played of all, speedup over all slots and time left, then each running replay's beat, share
done, game and wall time, speedup and time left.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

from common import (MOD_URL, REPLAY_URL, check_replay, clock, extract_map, fetch, find_mod_info, map_url, speed)
from replayfile import (HL_ENDED_RE, HL_LOADED_RE, HL_PROGRESS_RE, HL_SUMMARY_RE, HL_TROUBLE_RE, HL_VERDICT_RE,
                        MISMATCH_RE, live_client_desync, replay_checksums)

VAULT_LINE_RE = re.compile(r"^custom_vault_path = .*$", re.M)
PROGRESS_S = 30  # seconds between progress blocks in the job log


def find_folder(parent, name):
    """parent/<name>, matched without regard to case as the engine does."""
    try:
        for entry in os.listdir(parent):
            if entry.lower() == name.lower():
                return os.path.join(parent, entry)
    except OSError:
        pass
    return None


def link_tree(src, dst):
    """A copy of src made of hard links: instant, and no extra disk."""
    shutil.copytree(src, dst, copy_function=os.link)


class Shard:
    def __init__(self, args, replays):
        self.args = args
        self.queue = list(replays)  # longest first (plan.py)
        self.running = []
        self.results = []
        self.start = time.time()
        self.shown = self.start
        self.total = len(self.queue)
        self.deadline = self.start + args.minutes * 60
        with open(os.path.join(args.pack, "bin", "init_ci.lua"), encoding="utf-8") as f:
            self.init_text = f.read()
        self.retail_maps = os.path.join(args.pack, "fa", "maps")
        for sub in ("run", "dl", "maps", "m28"):
            os.makedirs(os.path.join(args.work, sub), exist_ok=True)
        os.makedirs(os.path.join(args.out, "logs"), exist_ok=True)

    def record(self, entry, game=None):
        entry = {k: v for k, v in entry.items() if v is not None}
        self.results.append(entry)
        with open(os.path.join(self.args.out, "results.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        if game and entry["verdict"] != "pass":
            for src, ext in ((game["out"], "out"), (game["log"], "log")):
                if os.path.isfile(src):
                    shutil.copyfile(src, os.path.join(self.args.out, "logs", "%d.%s" % (entry["id"], ext)))
        if "first_beat" in entry:
            detail = "beat %s" % entry["first_beat"]
        else:
            detail = speed(entry) or entry.get("why", "")
        print("%-8d %-11s %s" % (entry["id"], entry["verdict"], detail), flush=True)

    # ------------------------------------------------------------------------ preparing
    def replay_bytes(self, replay_id):
        cached = os.path.join(self.args.replays, "%d.fafreplay" % replay_id)
        if os.path.isfile(cached):
            return open(cached, "rb").read(), False
        path = os.path.join(self.args.work, "dl", "%d.fafreplay" % replay_id)
        if not os.path.isfile(path):
            fetch(REPLAY_URL % replay_id, path, self.args.delay)
        return open(path, "rb").read(), True

    def map_folder(self, folder):
        """None when the pack has the map in fa/maps (mounted at /maps; a local pack from make_pack.py
        build), else the map's folder: from the maps cache, or downloaded."""
        if find_folder(self.retail_maps, folder):
            return None
        found = find_folder(self.args.maps, folder) or find_folder(os.path.join(self.args.work, "maps"), folder)
        if found:
            return found
        zpath = os.path.join(self.args.work, "dl", folder + ".zip")
        fetch(map_url(folder), zpath, self.args.delay)
        return extract_map(zpath, os.path.join(self.args.work, "maps"), folder)

    def m28_folder(self, version):
        tag = "m28ai.v%04d" % version
        found = find_mod_info(os.path.join(self.args.m28, tag)) or find_mod_info(os.path.join(self.args.work, "m28", tag))
        if found:
            return found
        zpath = os.path.join(self.args.work, "dl", tag + ".zip")
        fetch(MOD_URL % tag, zpath, self.args.delay)
        shutil.unpack_archive(zpath, os.path.join(self.args.work, "m28", tag), "zip")
        return find_mod_info(os.path.join(self.args.work, "m28", tag))

    def prepare(self, item):
        """The replay's own folder: .scfareplay, a vault with its map and M28AI, an init file."""
        replay_id = item["id"]
        raw, downloaded = self.replay_bytes(replay_id)
        info, reason, data = check_replay(raw, self.args.game_version)
        if reason:
            return None, {"id": replay_id, "verdict": "unsupported", "why": reason}
        run = os.path.join(self.args.work, "run", str(replay_id))
        shutil.rmtree(run, ignore_errors=True)
        os.makedirs(os.path.join(run, "vault", "maps"))
        os.makedirs(os.path.join(run, "vault", "mods"))
        scfa = os.path.join(run, "replay.scfareplay")
        with open(scfa, "wb") as f:
            f.write(data)
        folder = self.map_folder(info["map"])
        if folder:
            link_tree(folder, os.path.join(run, "vault", "maps", info["map"]))
        if info["m28"]:
            mod = self.m28_folder(info["m28"])
            if not mod:
                return None, {"id": replay_id, "verdict": "unsupported", "why": "M28AI v%d not found" % info["m28"]}
            link_tree(mod, os.path.join(run, "vault", "mods", "m28ai"))
        init = os.path.join(self.args.pack, "bin", "init_%d.lua" % replay_id)
        vault = os.path.join(run, "vault").replace("\\", "/")
        with open(init, "w", encoding="utf-8", newline="\n") as f:
            f.write(VAULT_LINE_RE.sub(lambda m: "custom_vault_path = '%s'" % vault, self.init_text, count=1))
        return {"item": item, "info": info, "run": run, "scfa": scfa, "init": init,
                "downloaded": downloaded}, None

    # -------------------------------------------------------------------------- playing
    def launch(self, prepared):
        replay_id = prepared["item"]["id"]
        run = prepared["run"]
        game = dict(prepared)
        game.update({"out": os.path.join(run, "headless.out"), "log": os.path.join(run, "engine.log"),
                     "t0": time.time(), "pos": 0, "tick": -1, "ended": False, "over": False, "final": None,
                     "first_beat": None, "mismatches": 0, "live": [], "outvoted": set(), "recorded": None,
                     "notes": []})
        minutes_left = max(1, int((self.deadline - time.time()) / 60) + 1)
        cmd = [self.args.headless, "--replay", prepared["scfa"], "/init", prepared["init"], "/nobugreport",
               "/nosound", "/log", game["log"], "--label", "r%d" % replay_id, "--timeout", str(minutes_left),
               "/simworkers", str(self.args.simworkers)]
        with open(game["out"], "wb") as out:
            game["proc"] = subprocess.Popen(cmd, cwd=run, stdout=out, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL)
        self.running.append(game)

    def read_output(self, game):
        try:
            with open(game["out"], encoding="latin1", errors="replace") as f:
                f.seek(game["pos"])
                chunk = f.read()
        except OSError:
            return
        if game["proc"].poll() is None:
            chunk = chunk[:chunk.rfind("\n") + 1]  # whole lines only while it writes
        game["pos"] += len(chunk.encode("latin1", errors="replace"))
        for line in chunk.splitlines():
            m = MISMATCH_RE.search(line)
            if m:
                self.note_mismatch(game, m)
                continue
            m = HL_PROGRESS_RE.search(line) or HL_ENDED_RE.search(line)
            if m:
                game["tick"] = max(game["tick"], int(m.group(1)))
                game["ended"] = game["ended"] or "GAME-ENDED" in line
            elif HL_LOADED_RE.search(line):
                game["tick"] = max(game["tick"], 0)
            elif (m := HL_SUMMARY_RE.search(line)):
                game["tick"] = max(game["tick"], int(m.group(1)))
                game["over"] = m.group(2) == "True"
            elif (m := HL_VERDICT_RE.search(line)):
                game["final"] = (m.group(1) == "True", m.group(2) == "True")
            elif HL_TROUBLE_RE.search(line):
                game["notes"].append(line.strip()[:200])

    def note_mismatch(self, game, m):
        beat, sim, theirs, client = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        if client in game["outvoted"]:
            return  # desynced in the live game earlier; stays wrong for the rest of it
        if game["recorded"] is None:
            try:
                with open(game["scfa"], "rb") as f:
                    game["recorded"] = replay_checksums(f.read())
            except (OSError, ValueError, IndexError):
                game["recorded"] = {}
        if live_client_desync(game["recorded"], beat, sim, theirs):
            game["outvoted"].add(client)
            game["live"].append({"client": client, "beat": beat})
            return
        game["mismatches"] += 1
        if game["first_beat"] is None:
            game["first_beat"] = beat

    def verdict(self, game, timed_out):
        """parity.py HeadlessGame.poll, for a process that exited (or was stopped)."""
        if game["first_beat"] is not None:
            return "desync"
        if timed_out:  # the job's time ran out, not the replay's fault: a later run plays it
            game["notes"].append("stopped at the job's time limit at beat %d" % max(0, game["tick"]))
            return "not-run"
        if game["final"] is None or game["final"][1]:
            game["notes"].append("exit code %s%s" % (game["proc"].returncode, "" if game["final"] else ", no verdict"))
            return "crash"
        beats = game["info"].get("beats")
        if game["ended"] or game["over"] or (beats and game["tick"] >= beats - 2):
            return "pass"
        game["notes"].append("stopped at beat %d of %s" % (game["tick"], beats or "?"))
        return "incomplete"

    def finish(self, game, timed_out=False):
        if game["proc"].poll() is None:
            game["proc"].kill()
            game["proc"].wait()
        self.read_output(game)
        item = game["item"]
        verdict = self.verdict(game, timed_out)
        self.record({
            "id": item["id"], "verdict": verdict, "first_beat": game["first_beat"],
            "mismatches": game["mismatches"] or None, "live_desyncs": game["live"] or None,
            "last_beat": game["tick"], "length": game["info"].get("beats"), "ended": game["ended"],
            "game_s": game["tick"] / 10.0 if game["tick"] > 0 else None,  # 10 beats a game second
            "game_over": game["over"], "players": item["players"], "map": game["info"]["map"],
            "m28": game["info"]["m28"], "wall_s": round(time.time() - game["t0"], 1), "est_s": item["est"],
            "downloaded": game["downloaded"] or None, "notes": game["notes"] or None,
        }, game)
        self.running.remove(game)
        os.remove(game["init"])
        shutil.rmtree(game["run"], ignore_errors=True)

    def progress(self):
        """The shard (replays done, game time played of all, the speedup all slots give together,
        time left) and each running replay (beat, share done, game and wall time, speedup, time
        left). Game time is beats / 10; speedup is game time over wall time."""
        now = self.shown = time.time()
        played = sum(r.get("game_s") or 0 for r in self.results)
        left = sum(item["ticks"] for item in self.queue) / 10.0
        planned = sum(item["est"] for item in self.queue)  # the plan's wall seconds, for before any beat
        rows = []
        slowest = 0.0  # the job lasts at least as long as its slowest running replay
        for game in self.running:
            beats = game["info"].get("beats") or game["item"]["ticks"]
            game_s, total_s, wall = max(0, game["tick"]) / 10.0, beats / 10.0, now - game["t0"]
            played += game_s
            left += max(0.0, total_s - game_s)
            rate = game_s / wall if wall > 0 else 0.0
            if rate > 0:  # measured once the replay has played beats
                eta, how = (total_s - game_s) / rate, ""
            else:  # still loading: what the plan estimated, less the time it has had
                eta, how = max(0.0, game["item"]["est"] - wall), " (planned)"
            planned += eta
            slowest = max(slowest, eta)
            rows.append("  %-8d beat %d/%d (%d%%), game %s of %s, wall %s, x%.1f, about %s left%s"
                        % (game["item"]["id"], game_s * 10, beats, 100 * game_s / total_s if total_s else 0,
                           clock(game_s), clock(total_s), clock(wall), rate, clock(eta), how))
        wall = now - self.start
        rate = played / wall if wall > 0 else 0.0
        if rate > 0:
            eta, how = max(left / rate, slowest), ""
        else:
            eta, how = max(planned / max(1, self.args.slots), slowest), " (planned)"
        print("[%s] %d/%d replays done, %d playing, %d waiting; game %s of %s played (%d%%), x%.1f over all slots, "
              "about %s left%s" % (clock(wall), len(self.results), self.total, len(self.running), len(self.queue),
                                   clock(played), clock(played + left), 100 * played / (played + left) if played + left else 0,
                                   rate, clock(eta), how), flush=True)
        for row in rows:
            print(row, flush=True)

    def factor(self):
        """Measured wall time over the plan's estimate, from the replays this job finished (1.25
        until three have: run 41025691648's shard 3 measured 1.17 to 1.34)."""
        done = [r for r in self.results if r["verdict"] == "pass" and r.get("est_s") and r.get("wall_s")]
        if len(done) < 3:
            return 1.25
        return sum(r["wall_s"] for r in done) / sum(r["est_s"] for r in done)

    def next_fitting(self):
        """The longest replay whose estimate, corrected by what this job measured, still ends
        before the deadline."""
        left = self.deadline - time.time()
        factor = self.factor()
        for n, item in enumerate(self.queue):
            if item["est"] * factor <= left * 0.95:
                return self.queue.pop(n)
        return None

    def run(self):
        while self.queue or self.running:
            while len(self.running) < self.args.slots and self.queue:
                item = self.next_fitting()
                if item is None:
                    for rest in self.queue:
                        self.record({"id": rest["id"], "verdict": "not-run", "why": "no time left in the job",
                                     "est_s": rest["est"]})
                    self.queue = []
                    break
                try:
                    prepared, result = self.prepare(item)
                except Exception as exc:
                    self.record({"id": item["id"], "verdict": "error", "why": "prepare: %s" % str(exc)[:120]})
                    continue
                if result:
                    self.record(result)
                    continue
                self.launch(prepared)
            for game in list(self.running):
                self.read_output(game)
                if game["first_beat"] is not None or game["proc"].poll() is not None:
                    self.finish(game)
                elif time.time() > self.deadline:
                    self.finish(game, timed_out=True)
            if self.running and time.time() - self.shown >= PROGRESS_S:
                self.progress()
            time.sleep(1.0)
        counts = {}
        for r in self.results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print("shard done in %.0f min: %s" % ((time.time() - self.start) / 60, counts), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--headless", required=True)
    parser.add_argument("--pack", required=True, help="the base pack (bin/init_ci.lua, gamedata, fa/)")
    parser.add_argument("--replays", required=True, help="the bucket's replay cache")
    parser.add_argument("--maps", required=True, help="the cached maps")
    parser.add_argument("--m28", required=True, help="the cached M28AI versions")
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--minutes", type=float, default=300, help="time to play in; nothing starts that would not end by then")
    parser.add_argument("--slots", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--simworkers", type=int, default=1)
    parser.add_argument("--game-version", type=int, default=3835)
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between requests to FAF")
    args = parser.parse_args()
    args.pack = os.path.abspath(args.pack)
    args.work = os.path.abspath(args.work)
    args.headless = os.path.abspath(args.headless)
    with open(args.plan, encoding="utf-8") as f:
        plan = json.load(f)
    shard = next(s for s in plan["shards"] if s["shard"] == args.shard)
    print("shard %d: %d replays, %d slots, %.0f min" % (args.shard, len(shard["replays"]), args.slots, args.minutes),
          flush=True)
    Shard(args, shard["replays"]).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
