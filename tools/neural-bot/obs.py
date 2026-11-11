#!/usr/bin/env python3
"""Reads the observation files headless writes with --bot-obs (src/headless/BotObservation.h).

    python tools/neural-bot/obs.py <file.jsonl> [--check] [--blueprints <dir>]

Prints what the file holds: samples, own units, contacts, commands per minute by type.
--check exits 1 when a sample breaks the view's rules (what the player's UI shows):
  - a contact with its blueprint while the UI wouldn't draw its mesh. With --blueprints the
    rule is exact (mobile, as UserUnit::IsMobile: in sight now, 0x08; otherwise seen once,
    0x10); without it, a contact with a blueprint must at least have one of the two flags;
  - a contact with its strategic icon or owner but never seen (no 0x10) and no blueprint;
  - a contact with its health while not in sight now (no 0x08);
  - a known fake (0x20) without a blueprint;
  - a command out of beat order;
  - an own unit whose id doesn't carry the focus army.

Pairing views with decisions: a command's "b" is the beat it ran in, and a line holds the commands up to its
own beat, so its view already shows them running. The view a command was decided on is an earlier line's.

Row layouts (format version 2):
  own:      [id, bp, x, y, z, health, maxHealth, fraction, busy, workProgress]
  contacts: [id, bp|null, icon|null, generic, x, y, z, reconFlags, health|null, maxHealth|null, army|null]
            generic is the generic icon's class: structure, land, naval, air or other.
"""

import argparse
import collections
import json
import os
import re
import sys

RECON_LOS_NOW = 0x08
RECON_LOS_EVER = 0x10
RECON_KNOWN_FAKE = 0x20
BLIP_KIND = 3

# Contact row columns.
C_ID, C_BP, C_ICON, C_GENERIC, C_X, C_Y, C_Z, C_FLAGS, C_HEALTH, C_MAXHEALTH, C_ARMY = range(11)


def read(path):
    """Returns (header, samples, end) from one file."""
    header = None
    samples = []
    end = None
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(f"{path}:{number}: not JSON: {error}")
            if record.get("format") == "faf-bot-obs":
                header = record
            elif record.get("end"):
                end = record
            else:
                samples.append(record)
    if header is None:
        raise SystemExit(f"{path}: no header line")
    if header.get("version") != 2:
        raise SystemExit(f"{path}: format version {header.get('version')}, this reader reads 2")
    return header, samples, end


MOBILE_MOTION_TYPES = {
    "RULEUMT_Land", "RULEUMT_Air", "RULEUMT_Water", "RULEUMT_Biped", "RULEUMT_SurfacingSub",
    "RULEUMT_Amphibious", "RULEUMT_Hover", "RULEUMT_AmphibiousFloating",
}


def mobile_blueprints(directory):
    """Blueprint id -> mobile, from *_unit.bp files, as the client decides it (UserUnit::IsMobile 0x008C04E0):
    motion types Land through AmphibiousFloating move; None, Special or no MotionType don't."""
    result = {}
    for root, _dirs, files in os.walk(directory):
        for name in files:
            if not name.lower().endswith("_unit.bp"):
                continue
            unit_id = name[: -len("_unit.bp")].lower()
            try:
                text = open(os.path.join(root, name), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            motion = re.search(r"MotionType\s*=\s*['\"](RULEUMT_\w+)['\"]", text)
            result[unit_id] = motion is not None and motion.group(1) in MOBILE_MOTION_TYPES
    return result


def check(header, samples, end, mobile):
    army = header["army"]
    problems = []
    last_beat = -1
    for sample in samples:
        beat = sample["beat"]
        for row in sample.get("own", []):
            if (row[0] >> 20) & 0xFF != army or row[0] >> 28 == BLIP_KIND:
                problems.append(f"beat {beat}: own unit {row[0]} is not army {army}'s unit")
        for row in sample.get("contacts", []):
            bp, flags = row[C_BP], row[C_FLAGS]
            if row[C_HEALTH] is not None and not flags & RECON_LOS_NOW:
                problems.append(f"beat {beat}: contact {row[C_ID]} has its health without being in sight (flags {flags:#x})")
            if bp is None:
                if (row[C_ICON] is not None or row[C_ARMY] is not None) and not flags & RECON_LOS_EVER:
                    problems.append(f"beat {beat}: contact {row[C_ID]} has its icon or owner, never seen (flags {flags:#x})")
                if flags & RECON_KNOWN_FAKE:
                    problems.append(f"beat {beat}: contact {row[C_ID]} is a known fake (flags {flags:#x})")
                continue
            if mobile is not None and bp.lower() in mobile:
                needed = RECON_LOS_NOW if mobile[bp.lower()] else RECON_LOS_EVER
                if not flags & needed:
                    problems.append(f"beat {beat}: contact {row[C_ID]} ({bp}) has its blueprint with flags {flags:#x}")
            elif not flags & (RECON_LOS_NOW | RECON_LOS_EVER):
                problems.append(f"beat {beat}: contact {row[C_ID]} ({bp}) has its blueprint with flags {flags:#x}")
        for command in sample.get("cmds", []):
            if command["b"] < last_beat:
                problems.append(f"beat {beat}: command from beat {command['b']} out of order")
            last_beat = max(last_beat, command["b"])
    return problems


def summary(header, samples, end):
    commands = [c for s in samples for c in s.get("cmds", [])] + (end or {}).get("cmds", [])
    beats = samples[-1]["beat"] if samples else 0
    minutes = max(beats / 600.0, 1e-9)  # 10 beats a second
    own = [len(s.get("own", [])) for s in samples]
    contacts = [r for s in samples for r in s.get("contacts", [])]
    per_sample = [len(s.get("contacts", [])) for s in samples]
    with_bp = sum(1 for r in contacts if r[C_BP] is not None)
    with_icon = sum(1 for r in contacts if r[C_ICON] is not None)
    generic = collections.Counter(r[C_GENERIC] for r in contacts)
    by_type = collections.Counter(
        c.get("type", c["op"]) if c["op"] in ("issue", "factory") else c["op"] + (":" + c["name"] if "name" in c else "")
        for c in commands
    )
    lines = [
        f"replay {header['replay']}, army {header['army']}, sources {header['sources']}, every {header['every']} beats",
        f"{len(samples)} samples to beat {beats} ({beats / 600.0:.1f} min)",
        f"own units: max {max(own, default=0)}, mean {sum(own) / max(len(own), 1):.1f}",
        f"contacts: max {max(per_sample, default=0)}, mean {sum(per_sample) / max(len(per_sample), 1):.1f}, "
        f"{len(contacts)} rows: {with_bp} with blueprint, {with_icon} with icon, generic {dict(generic)}",
        f"commands: {len(commands)}, {len(commands) / minutes:.1f} per minute",
    ]
    for name, count in by_type.most_common(15):
        lines.append(f"  {name}: {count}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("file")
    parser.add_argument("--check", action="store_true", help="exit 1 when a sample breaks the view's rules")
    parser.add_argument("--blueprints", help="a units folder (*_unit.bp) for the exact mobile/structure rule")
    args = parser.parse_args()

    header, samples, end = read(args.file)
    print(summary(header, samples, end))
    if args.check:
        mobile = mobile_blueprints(args.blueprints) if args.blueprints else None
        problems = check(header, samples, end, mobile)
        for problem in problems[:20]:
            print("CHECK " + problem)
        print(f"CHECK {'FAIL' if problems else 'PASS'}: {len(problems)} problems")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
