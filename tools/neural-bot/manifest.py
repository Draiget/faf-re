#!/usr/bin/env python3
"""Per-game facts for a bot dataset, read from the replays themselves.

    python tools/neural-bot/manifest.py --replays DIR --out manifest.jsonl [--obs DIR]

Reads every <id>.fafreplay (or .scfareplay) in --replays and writes one JSON line per game:
{"id", "map", "beats", "armies": [{"army", "team", "faction", "start", "mean", "dev", "rating",
"games", "human"}]}. The ratings are the ones the lobby put in each player's options when the
game launched (MEAN and DEV; "rating" is PL, the displayed MEAN - 3 DEV), so a game needs nothing
from the FAF API. Player names and ids are left out. With --obs, only games that have at least
one <id>_<army>.jsonl(.gz) there are written.

Needs Python 3.14 (compression.zstd) or the zstandard package for zstd-compressed replays.
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "replay-parity"))
import replayfile  # noqa: E402  (tools/replay-parity/replayfile.py)


def armies(data):
    """Each army's player options from a .scfareplay body (the header VCR_SetupReplaySession reads)."""
    def cstring(pos):
        return data.index(0, pos) + 1

    pos = cstring(cstring(0)) + 13                # engine version, "Replay v1.9"
    map_path = data[pos:data.index(0, pos)].decode("latin1")
    pos = cstring(cstring(pos))                   # map path, "\r\n\x1a"
    for _ in range(2):                            # sim mods, scenario info
        pos += 4 + struct.unpack_from("<i", data, pos)[0]
    sources = data[pos]
    pos += 1
    for _ in range(sources):
        pos = cstring(pos) + 4                    # name, timeouts
    count = data[pos + 1]                         # after the cheats flag
    pos += 2
    result = []
    for army in range(count):
        size = struct.unpack_from("<i", data, pos)[0]
        options, _ = replayfile.lua_value(data[pos + 4:pos + 4 + size], 0)
        pos += 4 + size
        pos = data.index(0xFF, pos) + 1           # unit sources, 0xFF-terminated
        if options.get("Civilian"):
            continue

        def number(key):
            value = options.get(key)
            return round(value, 2) if isinstance(value, (int, float)) else None

        result.append({"army": army, "team": number("Team"), "faction": number("Faction"),
                       "start": number("StartSpot"), "mean": number("MEAN"), "dev": number("DEV"),
                       "rating": number("PL"), "games": number("NG"), "human": bool(options.get("Human"))})
    return map_path, result


def read_replay(path):
    raw = open(path, "rb").read()
    if path.endswith(".fafreplay"):
        _header, raw = replayfile.decode_fafreplay(raw)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--replays", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--obs")
    args = parser.parse_args()

    observed = None
    if args.obs:
        observed = {int(name.split("_")[0]) for name in os.listdir(args.obs) if name.split("_")[0].isdigit()}

    written = failed = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for name in sorted(os.listdir(args.replays)):
            stem, ext = os.path.splitext(name)
            if ext not in (".fafreplay", ".scfareplay") or not stem.isdigit():
                continue
            game_id = int(stem)
            if observed is not None and game_id not in observed:
                continue
            try:
                data = read_replay(os.path.join(args.replays, name))
                map_path, players = armies(data)
                beats = replayfile.replay_beats(data)
            except Exception as error:  # a replay that doesn't parse is reported, not fatal
                print("%s: %s" % (name, error), file=sys.stderr)
                failed += 1
                continue
            out.write(json.dumps({"id": game_id, "map": map_path, "beats": beats, "armies": players}) + "\n")
            written += 1
    print("%d games written, %d failed -> %s" % (written, failed, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
