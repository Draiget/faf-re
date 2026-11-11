#!/usr/bin/env python3
"""Picks games for a bot dataset batch and writes a plan tools/parity-data/shard.py plays.

    python tools/neural-bot/plan.py --games games.jsonl --out plan.json [--count N] [--seed S]
                                    [--players 2] [--min-minutes 8] [--exclude done.txt]

--games is a corpus export (tools/parity-data/corpus.py export: one JSON object per game with id,
ticks, validity, players). Keeps VALID games with --players players and at least --min-minutes of
game time, leaves out the ids listed in --exclude (one per line), shuffles them with --seed and
keeps --count (all when 0). The plan has one shard; shard.py --engine-args takes "{id}" for the
replay id, so each replay can write its own --bot-obs file:

    shard.py --plan plan.json --shard 0 ... --engine-args "--focus 0 --bot-obs /out/{id}_0.jsonl"
"""

import argparse
import json
import random
import sys

BEATS_PER_SECOND = 10
ESTIMATED_BEATS_PER_SECOND = 200  # a 1v1 on one sim worker; shard.py rescales by what it measures


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--games", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--players", type=int, default=2)
    parser.add_argument("--min-minutes", type=float, default=8.0)
    parser.add_argument("--exclude")
    args = parser.parse_args()

    excluded = set()
    if args.exclude:
        with open(args.exclude, encoding="utf-8") as f:
            excluded = {int(line) for line in f if line.strip()}

    games = []
    with open(args.games, encoding="utf-8") as f:
        for line in f:
            game = json.loads(line)
            if (game.get("validity") == "VALID" and game.get("players") == args.players
                    and game.get("ticks", 0) >= args.min_minutes * 60 * BEATS_PER_SECOND
                    and game["id"] not in excluded):
                games.append(game)
    random.Random(args.seed).shuffle(games)
    if args.count:
        games = games[:args.count]

    replays = [{"id": g["id"], "players": g["players"], "ticks": g["ticks"],
                "est": max(10, g["ticks"] // ESTIMATED_BEATS_PER_SECOND)} for g in games]
    replays.sort(key=lambda r: -r["est"])
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"shards": [{"shard": 0, "replays": replays}]}, f, indent=1)
    hours = sum(r["ticks"] for r in replays) / BEATS_PER_SECOND / 3600
    print("%d games, %.0f hours of game time -> %s" % (len(replays), hours, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
