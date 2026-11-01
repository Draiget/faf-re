"""Gathers what a plan's replays need into one folder, for jobs that cannot restore the caches.

usage: stage.py --plan plan.json --maps DIR --m28 DIR --out DIR [--game-version N] [--delay S]

The Replay check workflow plays a small set (the core set) on Linux and Windows runners, and a
cache saved on a Linux runner does not restore on a Windows one. One Linux job restores the caches,
runs this, and uploads DIR as an artifact every play job downloads: DIR/replays/<id>.fafreplay,
DIR/maps/<folder> and DIR/m28/m28ai.vNNNN, the layout shard.py reads with --replays, --maps and
--m28. The replays are downloaded from FAF once per run (one request at a time), and a map or
M28AI version the caches lack once too, instead of by every job.
"""
import argparse
import json
import os
import shutil
import sys

from common import MOD_URL, REPLAY_URL, check_replay, extract_map, fetch, find_mod_info, has_scenario, map_url
from shard import find_folder


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--maps", required=True, help="the cached maps")
    parser.add_argument("--m28", required=True, help="the cached M28AI versions")
    parser.add_argument("--out", required=True)
    parser.add_argument("--game-version", type=int, default=3835)
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between requests to FAF")
    args = parser.parse_args()
    with open(args.plan, encoding="utf-8") as f:
        plan = json.load(f)
    for sub in ("replays", "maps", "m28", "dl"):
        os.makedirs(os.path.join(args.out, sub), exist_ok=True)

    failed = 0
    for replay_id in sorted({r["id"] for s in plan["shards"] for r in s["replays"]}):
        path = os.path.join(args.out, "replays", "%d.fafreplay" % replay_id)
        try:
            fetch(REPLAY_URL % replay_id, path, args.delay)
            with open(path, "rb") as f:
                info, reason, _ = check_replay(f.read(), args.game_version)
            if reason:
                # shard.py reports it as unsupported; nothing more to gather for it
                print("%d %s" % (replay_id, reason), flush=True)
                continue
            folder = info["map"]
            if not find_folder(os.path.join(args.out, "maps"), folder):
                cached = find_folder(args.maps, folder)
                if cached and has_scenario(cached):
                    shutil.copytree(cached, os.path.join(args.out, "maps", folder))
                else:
                    zpath = os.path.join(args.out, "dl", folder + ".zip")
                    fetch(map_url(folder), zpath, args.delay)
                    extract_map(zpath, os.path.join(args.out, "maps"), folder)
            if info["m28"]:
                tag = "m28ai.v%04d" % info["m28"]
                dest = os.path.join(args.out, "m28", tag)
                if not os.path.isdir(dest):
                    if find_mod_info(os.path.join(args.m28, tag)):
                        shutil.copytree(os.path.join(args.m28, tag), dest)
                    else:
                        zpath = os.path.join(args.out, "dl", tag + ".zip")
                        fetch(MOD_URL % tag, zpath, args.delay)
                        shutil.unpack_archive(zpath, dest, "zip")
            print("%d map %s%s" % (replay_id, folder, ", M28AI v%d" % info["m28"] if info["m28"] else ""), flush=True)
        except Exception as exc:
            # The play job tries again and reports `error` if it fails there too.
            failed += 1
            print("%d not staged: %s" % (replay_id, str(exc)[:160]), flush=True)
    shutil.rmtree(os.path.join(args.out, "dl"), ignore_errors=True)
    print("staged %d replays, %d failed" % (len(os.listdir(os.path.join(args.out, "replays"))), failed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
