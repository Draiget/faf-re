#!/usr/bin/env python3
"""Gets the replays of tests/replay_sets ready for tools/retail-recorder/check_replay_sets.ps1 in CI.

CI's game folder has no init_parity*.lua, the local files replays.tsv names. For each replay this does what shard.py
does for a play job: it writes the .scfareplay, a vault with the replay's map and M28AI version, and bin/init_<id>.lua
in the pack. Run the check with -InitPattern 'init_{0}.lua' and -Pool set to --pool here.

The replays, maps and M28AI versions come from the folders the data job staged. Anything missing there is downloaded,
as in shard.py.
"""
import argparse
import csv
import os
import shutil
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shard import Shard  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sets", required=True, help="tests/replay_sets")
    parser.add_argument("--pack", required=True, help="the base pack (bin/init_ci.lua, gamedata, fa/)")
    parser.add_argument("--replays", required=True)
    parser.add_argument("--maps", required=True)
    parser.add_argument("--m28", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--pool", required=True, help="where the .scfareplay files go")
    parser.add_argument("--game-version", type=int, default=3835)
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()
    # The init file names these folders, and the engine doesn't start in this one.
    for name in ("pack", "replays", "maps", "m28", "work", "pool"):
        setattr(args, name, os.path.abspath(getattr(args, name)))

    shard_args = types.SimpleNamespace(
        pack=args.pack, replays=args.replays, maps=args.maps, m28=args.m28, work=args.work,
        out=os.path.join(args.work, "out"), minutes=1, game_version=args.game_version, delay=args.delay)
    shard = Shard(shard_args, [])
    os.makedirs(args.pool, exist_ok=True)

    failed = 0
    with open(os.path.join(args.sets, "replays.tsv"), encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            replay_id = int(row["replay"])
            prepared, refused = shard.prepare({"id": replay_id})
            if refused:
                print("%d: %s" % (replay_id, refused.get("why")))
                failed += 1
                continue
            shutil.copyfile(prepared["scfa"], os.path.join(args.pool, "%d.scfareplay" % replay_id))
            print("%d: ready, map %s" % (replay_id, prepared["info"]["map"]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
