#!/usr/bin/env python3
"""Turns --bot-obs files into training recordings in faf-neural-ai's format (github.com/Juliansgith/faf-neural-ai,
ai/python/fa_env/record.py), so its encoder and trainers read human games.

    python tools/neural-bot/convert.py --obs DIR --manifest manifest.jsonl --maps DIR [--maps DIR ...] --out DIR
                                       [--every 20] [--blueprints blueprints.json.gz] [--only ID_ARMY,...]

One input file <id>_<army>.jsonl(.gz) (src/headless/BotObservation.cpp, format 3) gives one output file
<id>_a<army+1>.jsonl.gz: a "hello" line (map, armies, the player's rating in "meta"), a "step" line every --every
beats with the army's view, and an "end" line. A step's "sent" holds the orders the player gave after that view and
up to the next step: a command tagged beat b ran in beat b, so the view of beat s < b doesn't show it yet.

What the player didn't see doesn't go in:
  - contact ids are replaced by anonymous numbers in order of first sight. A blip's own id carries its source army
    in bits 20+ (src/moho/sim/ReconBlip.cpp:136-140); the owner is given only where the file gives it (the UI shows
    the strategic icon in the owner's colour);
  - player names (the "info" rows' CustomName) and chat callbacks are dropped.

Not converted yet (counted in the summary): enhancement orders (the file doesn't name the enhancement), FAF's
attack-move (a sim callback; the file drops callback arguments), queue count changes, dequeues, and retargets.

Armies are 0-based here and in the input; faf-neural-ai counts from 1 (ARMY_1), so "index" and "army" add 1.
Pure Python (runs in the batch container, which has no numpy).
"""

import argparse
import collections
import gzip
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scenarios", "water-levels"))
from scmap import ScMap  # noqa: E402  (tools/scenarios/water-levels/scmap.py)

FORMAT_VERSION = 3
HEIGHTMAP_N = 64          # faf-neural-ai's hello sends a 64x64 terrain and water surface
LOS_NOW, LOS_EVER, KNOWN_FAKE, MAP_WIDE = 0x08, 0x10, 0x20, 0x100
# contact row: [id, bp|null, icon|null, generic, x, y, z, flags, health|null, maxHealth|null, army|null]
C_ID, C_BP, C_ICON, C_GENERIC, C_X, C_Y, C_Z, C_FLAGS, C_HEALTH, C_MAXHEALTH, C_ARMY = range(11)

# EUnitCommandType name (src/moho/command/SSTICommandIssueData.h) -> (order type, argument kind), as
# faf-neural-ai's fa_train/replay_orders.py maps the same commands from the replay stream.
ORDERS = {
    "Stop": ("stop", None), "Move": ("move", "pos"), "FormMove": ("move", "pos"), "Dive": ("dive", None),
    "BuildSiloTactical": ("silo_build", None), "BuildSiloNuke": ("silo_build_nuke", None),
    "BuildFactory": ("factory_build", "bp"), "BuildMobile": ("build", "pos+bp"),
    "BuildAssist": ("guard", "target"), "Guard": ("guard", "target"), "AssistCommander": ("guard", "target"),
    "Attack": ("attack", "target"), "FormAttack": ("attack", "target"), "Nuke": ("nuke", "pos"),
    "Tactical": ("tactical", "target"), "Patrol": ("patrol", "pos"), "FormPatrol": ("patrol", "pos"),
    "Reclaim": ("reclaim", "target"), "Repair": ("repair", "target"), "Capture": ("capture", "target"),
    "TransportLoadUnits": ("transport_load", "target"), "TransportUnloadUnits": ("transport_unload", "pos"),
    "TransportUnloadSpecificUnits": ("transport_unload", "pos"), "Upgrade": ("upgrade", "bp"),
    "OverCharge": ("overcharge", "target"), "AggressiveMove": ("attack_move", "pos"),
    "FormAggressiveMove": ("attack_move", "pos"),
}
FACTORY_RALLY = {"Move", "FormMove", "AggressiveMove", "FormAggressiveMove", "Patrol"}


def open_text(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, encoding="utf-8")


# ---------------------------------------------------------------------------------------------- map
def find_map_folder(roots, scmap_path):
    """The folder of '/maps/<folder>/<name>.scmap' under any of the roots (names compared lowercased)."""
    parts = [p for p in scmap_path.replace("\\", "/").split("/") if p]
    folder = parts[1].lower() if len(parts) >= 3 else None
    for root in roots:
        if folder and os.path.isdir(root):
            for name in os.listdir(root):
                if name.lower() == folder:
                    return os.path.join(root, name)
    return None


def lua_markers(save_text):
    """{marker name: (type, x, z)} from a _save.lua's markers."""
    out = {}
    for m in re.finditer(r"\['([^']+)'\]\s*=\s*\{(.*?)\n\s*\},", save_text, re.S):
        body = m.group(2)
        kind = re.search(r"\['type'\]\s*=\s*STRING\(\s*'([^']*)'", body)
        pos = re.search(r"\['position'\]\s*=\s*VECTOR3\(\s*([-\d.eE]+)\s*,\s*([-\d.eE]+)\s*,\s*([-\d.eE]+)", body)
        if kind and pos:
            out[m.group(1)] = (kind.group(1), float(pos.group(1)), float(pos.group(3)))
    return out


def map_info(folder):
    """faf-neural-ai's hello "map": size, playable rect, a 64x64 terrain and water surface, deposits; plus the
    start markers {ARMY_n: (x, z)}."""
    files = {n.lower(): os.path.join(folder, n) for n in os.listdir(folder)}
    scenario = open(next(p for n, p in files.items() if n.endswith("_scenario.lua")), encoding="latin1").read()
    size = re.search(r"size\s*=\s*\{\s*(\d+)\s*,\s*(\d+)", scenario)
    width, height = (int(size.group(1)), int(size.group(2))) if size else (None, None)
    name = re.search(r"name\s*=\s*['\"]([^'\"]*)", scenario)
    save = open(next(p for n, p in files.items() if n.endswith("_save.lua")), encoding="latin1").read()
    markers = lua_markers(save)
    deposits = [{"type": "mass" if kind == "Mass" else "hydrocarbon", "x": x, "z": z}
                for kind, x, z in markers.values() if kind in ("Mass", "Hydrocarbon")]
    starts = {name_: (x, z) for name_, (kind, x, z) in markers.items() if re.fullmatch(r"ARMY_\d+", name_)}
    playable = None
    area = re.search(r"\['playable_area'\]\s*=\s*RECTANGLE\(\s*([-\d.]+)\s*,\s*([-\d.]+)\s*,\s*([-\d.]+)\s*,\s*([-\d.]+)",
                     save, re.I)
    if area:
        playable = [int(float(v)) for v in area.groups()]
    heightmap = None
    scmap_file = next((p for n, p in files.items() if n.endswith(".scmap")), None)
    if scmap_file:
        m = ScMap(bytearray(open(scmap_file, "rb").read()))
        w1, h1 = m.width + 1, m.height + 1
        words = m.heights()
        enabled, levels = m.water()
        level = levels[0]                                # surface elevation (then deep, abyss)
        terrain, surface = [], []
        for gz in range(HEIGHTMAP_N):
            z = min(h1 - 1, int((gz + 0.5) * h1 / HEIGHTMAP_N))
            for gx in range(HEIGHTMAP_N):
                x = min(w1 - 1, int((gx + 0.5) * w1 / HEIGHTMAP_N))
                t = round(words[z * w1 + x] * m.height_scale, 2)
                terrain.append(t)
                surface.append(max(t, round(level, 2)) if enabled else t)
        heightmap = {"n": HEIGHTMAP_N, "terrain": terrain, "surface": surface}
        width, height = width or m.width, height or m.height
    return {"name": name.group(1) if name else os.path.basename(folder), "width": width, "height": height,
            "playable": playable or [0, 0, width, height], "deposits": deposits, "heightmap": heightmap}, starts


# ---------------------------------------------------------------------------------------------- one game
class Converter:
    def __init__(self, header, game, hello_map, starts, every):
        self.army = header["army"]                       # 0-based
        self.me = self.army + 1
        self.every = every
        self.counts = collections.Counter()
        self.anon = {}                                   # contact id -> anonymous number
        players = {a["army"]: a for a in game["armies"]}
        mine = players.get(self.army, {})
        armies = []
        for a in game["armies"]:
            if a["army"] == self.army:
                relation = "self"
            elif mine.get("team") not in (None, 1) and a.get("team") == mine.get("team"):
                relation = "ally"                        # FAF's team 1 is "no team"
            else:
                relation = "enemy"
            start = starts.get("ARMY_%d" % int(a["start"])) if a.get("start") else None
            armies.append({"index": a["army"] + 1, "relation": relation, "civilian": False,
                           "name": "ARMY_%d" % (a["army"] + 1), "faction": a.get("faction"),
                           "start": list(start) if start else None, "brainType": "Human"})
        self.relation = {a["index"]: a["relation"] for a in armies}
        self.hello = {"map": hello_map, "armies": armies, "config": {"omniscient": False, "armies": [self.me]}}
        self.meta = {"source": "faf-replay", "replay": game["id"], "me": self.me, "decision_ticks": every,
                     # no "label_source": to faf-neural-ai's encoder (tools_bc.encode_game) that key means a teacher
                     # labelled the steps; without it the labels come from the player's own orders in "sent"
                     "map": hello_map.get("name"),
                     "rating": mine.get("rating"), "mean": mine.get("mean"), "dev": mine.get("dev"),
                     "games": mine.get("games"), "faction": mine.get("faction"),
                     "ratings": {str(a["army"] + 1): a.get("rating") for a in game["armies"]}}

    def anon_id(self, raw):
        if raw not in self.anon:
            self.anon[raw] = 0x7000000 + len(self.anon)   # never an own unit's id (own ids carry the army bits)
        return str(self.anon[raw])

    def unit_ref(self, raw):
        """An entity a command names: an own unit by its id, anything else by its anonymous contact id."""
        return str(raw) if ((raw >> 20) & 0xFF) == self.army and (raw >> 28) != 3 else self.anon_id(raw)

    def observation(self, sample):
        units = []
        for r in sample.get("own", []):
            uid, bp, x, y, z, hp, maxhp, frac, busy, work = r[:10]
            units.append({"id": uid, "army": self.me, "bp": bp, "x": x, "y": y, "z": z, "hp": hp,
                          "maxhp": maxhp, "frac": frac, "idle": not busy, "work": work})
        for r in sample.get("contacts", []):
            flags = r[C_FLAGS]
            army = r[C_ARMY] + 1 if r[C_ARMY] is not None else None
            d = {"id": int(self.anon_id(r[C_ID])), "army": army, "x": r[C_X], "y": r[C_Y], "z": r[C_Z]}
            if r[C_BP] is None:
                d["radar"] = True                        # type unknown: a radar, sonar or omni contact
            else:
                d["bp"] = r[C_BP]
                if r[C_HEALTH] is not None:
                    d["hp"], d["maxhp"] = r[C_HEALTH], r[C_MAXHEALTH]
                elif not (flags & (LOS_NOW | MAP_WIDE)):
                    d["ghost"] = True                    # remembered from an earlier sighting
            units.append(d)
        eco = sample.get("eco") or {}

        def resource(i):
            pick = lambda key: (eco.get(key) or [0.0, 0.0])[i]  # noqa: E731
            return {"stored": pick("stored"), "max": pick("max") or None, "income": pick("income") * 10.0,
                    "requested": pick("requested") * 10.0, "usage": pick("spent") * 10.0}

        armies = [{"index": i, "relation": rel} for i, rel in self.relation.items()]
        for a in armies:
            if a["index"] == self.me:
                a["eco"] = {"mass": resource(0), "energy": resource(1)}
        return {"tick": sample["beat"], "time": sample["beat"] / 10.0, "me": self.me, "armies": armies,
                "units": units}

    def orders(self, commands):
        out = []
        for c in commands:
            op = c["op"]
            if op not in ("issue", "factory"):
                self.counts["skipped " + op + (":" + c["name"] if "name" in c else "")] += 1
                continue
            units = [str(u) for u in c.get("units") or []]
            if not units:
                continue
            ctype = c.get("type")
            if c.get("clear"):
                out.append({"type": "clear", "units": units, "tick": c["b"]})
            if op == "factory" and ctype in FACTORY_RALLY:
                kind, arg = "rally", "pos"
            elif ctype in ORDERS:
                kind, arg = ORDERS[ctype]
            else:
                self.counts["skipped type " + str(ctype)] += 1
                continue
            order = {"type": kind, "units": units, "tick": c["b"]}
            if kind == "silo_build_nuke":
                order.update(type="silo_build", nuke=True)
            target = c.get("target") or {}
            pos = [target["ground"][0], target["ground"][2]] if "ground" in target else None
            ent = self.unit_ref(target["entity"]) if "entity" in target else None
            if arg in ("pos", "pos+bp"):
                if pos is None:
                    self.counts["skipped no position: " + ctype] += 1
                    continue
                order["pos"] = pos
            if arg in ("bp", "pos+bp"):
                if not c.get("bp"):
                    self.counts["skipped no blueprint: " + ctype] += 1
                    continue
                order["bp"] = c["bp"].lower()
            if arg == "target":
                if ent is not None:
                    order["target"] = ent
                elif pos is not None and kind == "attack":
                    order.update(type="attack_ground", pos=pos)
                elif pos is not None and kind in ("reclaim", "tactical"):
                    order["pos"] = pos
                else:
                    self.counts["skipped no target: " + ctype] += 1
                    continue
            if kind == "factory_build":
                order["count"] = 1
                last = out[-1] if out else None
                if (last and last["type"] == "factory_build" and last["tick"] == order["tick"]
                        and last["units"] == units and last["bp"] == order["bp"]):
                    last["count"] += 1                   # the copies of one queued factory order
                    continue
            out.append(order)
            self.counts["order " + order["type"]] += 1
        return out


def convert(obs_path, game, map_roots, out_dir, every):
    with open_text(obs_path) as f:
        header = json.loads(f.readline())
        if header.get("format") != "faf-bot-obs" or header.get("version") != FORMAT_VERSION:
            raise ValueError("not a --bot-obs file of format %d" % FORMAT_VERSION)
        folder = find_map_folder(map_roots, game["map"])
        if folder is None:
            raise ValueError("map %s not found" % game["map"])
        hello_map, starts = map_info(folder)
        conv = Converter(header, game, hello_map, starts, every)
        name = "%d_a%d.jsonl.gz" % (game["id"], conv.me)
        tmp = os.path.join(out_dir, name + ".tmp")
        steps = 0
        with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=5) as out:
            out.write(json.dumps({"hello": conv.hello, "meta": conv.meta}, separators=(",", ":")) + "\n")
            pending, pending_cmds = None, []
            for line in f:
                record = json.loads(line)
                if record.get("end"):
                    pending_cmds += record.get("cmds", [])
                    break
                pending_cmds += record.get("cmds", [])
                if record["beat"] % every:
                    continue
                if pending is not None:
                    # the view of the last step, with the orders that ran after it, up to and including this beat
                    sent = conv.orders([c for c in pending_cmds if pending["tick"] < c["b"] <= record["beat"]])
                    pending_cmds = [c for c in pending_cmds if c["b"] > record["beat"]]
                    out.write(json.dumps({"step": {"tick": pending["tick"], "sent": sent},
                                          "msg": {"type": "obs", "tick": pending["tick"], "obs": pending}},
                                         separators=(",", ":")) + "\n")
                    steps += 1
                else:
                    pending_cmds = [c for c in pending_cmds if c["b"] > record["beat"]]
                pending = conv.observation(record)
            if pending is not None:
                sent = conv.orders([c for c in pending_cmds if c["b"] > pending["tick"]])
                out.write(json.dumps({"step": {"tick": pending["tick"], "sent": sent},
                                      "msg": {"type": "obs", "tick": pending["tick"], "obs": pending}},
                                     separators=(",", ":")) + "\n")
                steps += 1
            out.write(json.dumps({"end": {"source": "faf-replay", "steps": steps}}) + "\n")
        os.replace(tmp, os.path.join(out_dir, name))
    return name, steps, conv.counts


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--obs", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--maps", action="append", required=True, help="a folder of map folders (repeatable)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--every", type=int, default=20, help="beats between steps (faf-neural-ai decides every 20)")
    parser.add_argument("--only", help="comma-separated <id>_<army> names to convert")
    args = parser.parse_args()

    games = {}
    with open(args.manifest, encoding="utf-8") as f:
        for line in f:
            g = json.loads(line)
            games[g["id"]] = g
    os.makedirs(args.out, exist_ok=True)
    only = set(args.only.split(",")) if args.only else None
    totals = collections.Counter()
    written = failed = 0
    for name in sorted(os.listdir(args.obs)):
        m = re.fullmatch(r"(\d+)_(\d+)\.jsonl(\.gz)?", name)
        if not m or (only and "%s_%s" % (m.group(1), m.group(2)) not in only):
            continue
        game = games.get(int(m.group(1)))
        if game is None:
            print("%s: not in the manifest" % name, file=sys.stderr)
            failed += 1
            continue
        try:
            out_name, steps, counts = convert(os.path.join(args.obs, name), game, args.maps, args.out, args.every)
        except Exception as error:  # one bad file is reported, not fatal
            print("%s: %s" % (name, error), file=sys.stderr)
            failed += 1
            continue
        totals.update(counts)
        written += 1
        print("%s -> %s: %d steps" % (name, out_name, steps))
    print("%d files written, %d failed -> %s" % (written, failed, args.out))
    for key, n in sorted(totals.items()):
        print("  %s: %d" % (key, n))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
