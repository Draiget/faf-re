"""Compares desync dumps from one game (desync_*.zip, written by the engine's desync recorder,
issue #216) and prints the first value that differs.

usage: desync_diff.py [compare] A.zip B.zip [C.zip ...] [-C LINES] [--states N] [--force]
       desync_diff.py rebuild A.zip --exe HEADLESS.exe --replay FILE --init FILE [--out DIR]
                      [--no-compare] [-- ENGINE ARGS...]

compare (the default) runs four steps, each dump against the first:
  1. header: build, architecture, game version, sim fixes, map, game mods, switches, /sse2 and
     the floating-point registers
  2. hashes: the last beat every player's hash matched, the first where any differs, and who
     shares which hash there
  3. beat logs: from the last agreed beat on, the first line that differs, with the beat, the
     entity (id, blueprint, army) or army and the field it is about
  4. state.txt: entities that differ, entities on one side only, the first differences

rebuild plays a replay in headless with the recorder on and /desyncdumpbeat set to A's dump
beat, so the side of a desync that sent no dump can be rebuilt on that player's build; then it
compares the new dump with A. This only shows differences that come from the build, the
architecture or a switch (each build replays its own way every time), not memory corruption or
hardware faults.

Exit code: 0 nothing differs, 1 a difference was found, 2 invalid input. Standard library only.
"""
import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import time
import zipfile
import zlib

# The recorder's own switches differ between a live dump and a rebuilt one by design.
RECORDER_SWITCHES = {"sim_DesyncRecorder", "sim_DesyncRecorderMB", "sim_DesyncDumpBeat"}
# Pacing switches headless sets for every replay run (ReplayRunner.cpp); they don't reach the sim.
REPLAY_RUNNER_SWITCHES = {"sim_LeadOnSchedule"}

HEADER_FIELDS = [
    ("build", "commit"), ("build", "arch"), ("build", "dirty"),
    ("game", "faf_game_version"), ("game", "sim_fixes"), ("game", "map"), ("game", "game_mods_md5"),
    ("settings", "sim_ChecksumPeriod"), ("settings", "sim_workers_in_use"), ("settings", "sse2"),
    ("settings", "x87_control"), ("settings", "mxcsr"),
    ("settings", "x87_control_at_start"), ("settings", "mxcsr_at_start"),
]

HASH_LINE = re.compile(r"^\s+[0-9a-f]{32}$")
DIRTY_ENTITY = re.compile(r"^  0x([0-9a-f]{8})$")
ENTITY_REF = re.compile(r"(?:Entity|Unit|Projectile|Weapon)\[0x([0-9a-f]{8})\]|^\s*0x([0-9a-f]{8})(?:'s |->)|\bfor 0x([0-9a-f]{8})\b")
ARMY_BLOCK = re.compile(r'^  "(.*)" \[(.*)\]$')
SECTION = re.compile(r"^(Armies|Dirty Entities|\*{10} beat .*)$")
FIELD = re.compile(r"^\s*([A-Za-z_][\w\[\]]*)\s*[:=]")
CALL = re.compile(r"->(\w+)\(|^\s*(\w+)\(")
TICK = re.compile(r"'s (\w+) tick")
STATE_ENTITY = re.compile(r"^0x([0-9a-f]{8}) bp=(\S*) army=(-?\d+)")
STATE_ARMY = re.compile(r'^  (\d+) "')


class BadInput(Exception):
    pass


class Dump:
    def __init__(self, path):
        self.path = path
        self.label = os.path.basename(path)
        try:
            self.zip = zipfile.ZipFile(path)
            self.header = json.loads(self.zip.read("header.json"))
        except (OSError, zipfile.BadZipFile, KeyError, ValueError) as error:
            raise BadInput("%s: not a desync dump (%s)" % (path, error))
        if self.header.get("format") != 1:
            raise BadInput("%s: unknown dump format %r" % (path, self.header.get("format")))
        names = self.zip.namelist()
        self.beats = sorted(int(n[len("beats/beat"):-len(".log")]) for n in names
                            if n.startswith("beats/beat") and n.endswith(".log"))
        self.armies = {a["index"]: a for a in self.header.get("armies", [])}
        self.sources = {s["index"]: s["name"] for s in self.header.get("command_sources", [])}
        self._state = None

    def get(self, section, key):
        return self.header.get(section, {}).get(key)

    def switches(self):
        text = self.get("settings", "switches") or ""
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    def text(self, name):
        try:
            return self.zip.read(name).decode("utf-8", errors="replace").splitlines()
        except KeyError:
            return None

    def beat_log(self, beat):
        return self.text("beats/beat%05d.log" % beat)

    def hash_rows(self):
        raw = self.text("hashes.csv") or []
        return list(csv.DictReader(io.StringIO("\n".join(raw))))

    def state(self):
        """state.txt as (header lines, {key: block lines}, [keys in order])."""
        if self._state is None:
            lines = self.text("state.txt") or []
            head, blocks, order, key, part = [], {}, [], None, "head"
            for line in lines:
                if line in ("Armies", "Entities"):
                    part, key = line, None
                    continue
                army = STATE_ARMY.match(line) if part == "Armies" else None
                entity = STATE_ENTITY.match(line) if part == "Entities" else None
                if army:
                    key = "army " + army.group(1)
                elif entity:
                    key = "0x" + entity.group(1)
                elif key is None:
                    head.append(line)
                    continue
                if key not in blocks:
                    blocks[key] = []
                    order.append(key)
                blocks[key].append(line)
            self._state = (head, blocks, order)
        return self._state

    def entity_info(self, entity_id):
        """(blueprint, army index) from state.txt, or None if the entity isn't there."""
        _, blocks, _ = self.state()
        block = blocks.get("0x" + entity_id)
        if block:
            match = STATE_ENTITY.match(block[0])
            return match.group(2), int(match.group(3))
        return None

    def army_name(self, index):
        army = self.armies.get(index)
        return "%d %s [%s]" % (index, army["player"], army["army"]) if army else str(index)

    def describe(self):
        desync = self.header.get("desync", {})
        local = self.header.get("local_army", -1)
        who = self.army_name(local) if local >= 0 else "observer"
        kind = "replay run" if self.get("game", "replay") else "live game"
        return "%s: %s, %s, %s, dump at beat %s, first mismatch %s" % (
            self.label, self.get("build", "identity"), who, kind, desync.get("dump_beat"),
            desync.get("first_mismatched_beat"))


def section(title):
    print()
    print("== " + title)


def same_game(dumps, force):
    ids = {d.get("game", "faf_game_id") for d in dumps if d.get("game", "faf_game_id")}
    if len(ids) > 1:
        message = "the dumps come from different FAF games: " + ", ".join(sorted(ids))
        if not force:
            raise BadInput(message + " (--force compares them anyway)")
        print("warning: " + message)
    maps = {(d.get("game", "map") or "").lower() for d in dumps} - {""}  # older dumps of a replay run had none
    players = {tuple(sorted(d.sources.values())) for d in dumps}
    if len(maps) > 1 or len(players) > 1:
        message = "the dumps differ in map or players: %s / %s" % (sorted(maps), sorted(players))
        if not force:
            raise BadInput(message + " (--force compares them anyway)")
        print("warning: " + message)


def compare_headers(base, other):
    found = False
    for group, key in HEADER_FIELDS:
        a, b = base.get(group, key), other.get(group, key)
        if a != b and (a is None or b is None):
            # A field one dump's format doesn't have yet (written by an older recorder).
            print("  %s.%s: %s | %s (missing in one dump, not counted)" % (group, key, json.dumps(a), json.dumps(b)))
        elif a != b:
            print("  %s.%s: %s | %s" % (group, key, json.dumps(a), json.dumps(b)))
            found = True
    sa, sb = base.switches(), other.switches()
    one_replay = bool(base.get("game", "replay")) != bool(other.get("game", "replay"))
    for name in sorted(set(sa) | set(sb)):
        if name in RECORDER_SWITCHES:
            continue
        a, b = sa.get(name, "(absent)"), sb.get(name, "(absent)")
        if a != b:
            if one_replay and name in REPLAY_RUNNER_SWITCHES:
                print("  switch %s: %s | %s (set by the replay runner, not counted)" % (name, a, b))
                continue
            print("  switch %s: %s | %s" % (name, a, b))
            found = True
    if not found:
        print("  no difference")
    return found


def compare_hashes(dumps):
    """Prints who agrees with whom; returns (last agreed beat, first differing beat)."""
    table = {}
    for dump in dumps:
        for row in dump.hash_rows():
            beat = int(row["beat"])
            name = row["name"] or "source %s" % row["source"]
            table.setdefault(beat, {})[name] = row["reported"]
            if dump.get("game", "replay"):
                # A replay run is nobody's command source: its own hash is the "ours" column.
                table[beat]["%s (this run)" % dump.label] = row["ours"]
    last_agreed, first_diff = None, None
    for beat in sorted(table):
        hashes = set(table[beat].values())
        if len(hashes) == 1 and len(table[beat]) > 1:
            if first_diff is None:
                last_agreed = beat
        elif len(hashes) > 1 and first_diff is None:
            first_diff = beat
    print("  last beat every hash matched: %s" % (last_agreed if last_agreed is not None else "none in the dumps"))
    if first_diff is None:
        print("  no beat with differing hashes")
        return last_agreed, None
    groups = {}
    for name, digest in sorted(table[first_diff].items()):
        groups.setdefault(digest, []).append(name)
    sizes = sorted(len(g) for g in groups.values())
    if len(groups) == 2 and sizes == [1, 1]:
        shape = "the two differ"
    elif len(groups) == 2 and sizes[0] == 1:
        shape = "one off, the rest agree"
    else:
        shape = "a split into %d groups" % len(groups)
    print("  first beat with differing hashes: %d (%s)" % (first_diff, shape))
    for digest, names in sorted(groups.items(), key=lambda item: -len(item[1])):
        print("    %s: %s" % (digest, ", ".join(names)))
    return last_agreed, first_diff


def line_field(lines, index):
    """What the line at `index` is about: a field name, a call, or the hash after a line."""
    line = lines[index]
    if HASH_LINE.match(line):
        for back in range(index - 1, max(-1, index - 20), -1):
            if not HASH_LINE.match(lines[back]):
                return "the running hash after %r: a value hashed but not printed in full" % lines[back].strip()
        return "running hash"
    match = TICK.search(line)
    if match:
        return "%s tick" % match.group(1)
    match = FIELD.match(line)
    if match:
        return match.group(1)
    match = CALL.search(line)
    if match:
        return match.group(1) or match.group(2)
    return line.strip()


def line_subject(dump, other, lines, index):
    """The entity or army the line at `index` belongs to, as text."""
    for back in range(index, -1, -1):
        line = lines[back]
        match = ENTITY_REF.search(line) or DIRTY_ENTITY.match(line)
        if match:
            entity = next(g for g in match.groups() if g)
            blueprint, army = None, None
            if DIRTY_ENTITY.match(line):
                for ahead in range(back + 1, min(len(lines), back + 12)):
                    if DIRTY_ENTITY.match(lines[ahead]) or SECTION.match(lines[ahead]):
                        break
                    if lines[ahead].strip().startswith("bp:"):
                        blueprint = lines[ahead].strip()[3:]
            info = dump.entity_info(entity) or other.entity_info(entity)
            if info:
                blueprint = blueprint or info[0]
                army = info[1]
            text = "entity 0x%s" % entity
            if blueprint:
                text += " bp=%s" % blueprint
            if army is not None:
                text += " army %s" % dump.army_name(army)
            else:
                # EntityId: family in the top 4 bits, the army (source) in the next 8, 0xFF for none.
                source = (int(entity, 16) >> 20) & 0xFF
                text += " army %s" % ("none" if source == 0xFF else "%d (from its id)" % source)
            return text
        match = ARMY_BLOCK.match(line)
        if match:
            return "army %s [%s] (economy)" % (match.group(1), match.group(2))
        if SECTION.match(line) and back != index:
            break
    return "no entity or army (sim-wide line)"


def compare_logs(base, other, start, context):
    beats = sorted(set(base.beats) & set(other.beats))
    missing = sorted(set(base.beats) ^ set(other.beats))
    if start is None:
        start = 0
    beats = [b for b in beats if b == 0 and start == 0 or b >= start]
    if not beats:
        print("  no beat log in both dumps from beat %d on" % start)
        return False
    if missing:
        only = [b for b in missing if b >= start]
        if only:
            print("  beats in one dump only (not compared): %s" % compact(only))
    print("  comparing beats %d..%d" % (beats[0], beats[-1]))
    for beat in beats:
        la, lb = base.beat_log(beat), other.beat_log(beat)
        if la == lb:
            continue
        for index in range(max(len(la), len(lb))):
            a = la[index] if index < len(la) else "(end of log)"
            b = lb[index] if index < len(lb) else "(end of log)"
            if a != b:
                break
        lines = la if index < len(la) else lb
        print("  first difference: beat %d, line %d" % (beat, index + 1))
        print("  about: %s" % line_subject(base, other, lines, min(index, len(lines) - 1)))
        print("  field: %s" % line_field(lines, min(index, len(lines) - 1)))
        print()
        for line in la[max(0, index - context):index]:
            print("    " + line)
        print("  A " + a)
        print("  B " + b)
        for side, side_lines in (("A", la), ("B", lb)):
            following = side_lines[index + 1:index + 1 + context]
            if following:
                print("    -- then on %s:" % side)
                for line in following:
                    print("    " + line)
        return True
    print("  no difference in %d beats" % len(beats))
    return False


def compare_states(base, other, limit):
    head_a, blocks_a, order_a = base.state()
    head_b, blocks_b, order_b = other.state()
    if not order_a and not order_b:
        print("  no state.txt in the dumps")
        return False
    if head_a[:1] != head_b[:1]:
        print("  snapshots taken at different beats: %s | %s" % (head_a[:1], head_b[:1]))
    only_a = [k for k in order_a if k not in blocks_b]
    only_b = [k for k in order_b if k not in blocks_a]
    differing = [k for k in order_a if k in blocks_b and blocks_a[k] != blocks_b[k]]
    entities = [k for k in differing if k.startswith("0x")]
    print("  entities: %d in A, %d in B; %d differ, %d in A only, %d in B only" % (
        sum(k.startswith("0x") for k in order_a), sum(k.startswith("0x") for k in order_b),
        len(entities), sum(k.startswith("0x") for k in only_a), sum(k.startswith("0x") for k in only_b)))
    armies = [k for k in differing if k.startswith("army ")]
    if armies:
        print("  armies that differ: %s" % ", ".join(armies))
    for label, keys, blocks in (("A", only_a, blocks_a), ("B", only_b, blocks_b)):
        if keys:
            print("  in %s only: %s" % (label, "; ".join(blocks[k][0].strip() for k in keys[:limit])))
    for key in differing[:limit]:
        a, b = blocks_a[key], blocks_b[key]
        for index in range(max(len(a), len(b))):
            la = a[index] if index < len(a) else "(none)"
            lb = b[index] if index < len(b) else "(none)"
            if la != lb:
                print("  %s %s" % (key, a[0][len(key):].strip() if key.startswith("0x") else ""))
                print("    A " + la.strip())
                print("    B " + lb.strip())
                break
    if len(differing) > limit:
        print("  ... %d more" % (len(differing) - limit))
    return bool(only_a or only_b or differing or head_a[:1] != head_b[:1])


def compact(beats):
    runs, start, prev = [], None, None
    for beat in beats:
        if start is None:
            start = prev = beat
        elif beat == prev + 1:
            prev = beat
        else:
            runs.append((start, prev))
            start = prev = beat
    if start is not None:
        runs.append((start, prev))
    return ", ".join("%d" % a if a == b else "%d-%d" % (a, b) for a, b in runs)


def compare(paths, context, states, force):
    dumps = [Dump(p) for p in paths]
    same_game(dumps, force)
    print("Dumps (A is the first; every other is B against it):")
    for dump in dumps:
        print("  " + dump.describe())
    found = False

    section("1. Header")
    for other in dumps[1:]:
        if len(dumps) > 2:
            print(" %s:" % other.label)
        found |= compare_headers(dumps[0], other)

    section("2. Hashes")
    # What the game's players reported, merged from every dump: it tells where to look, but it is
    # the same in two copies of one dump, so it doesn't count as a difference between the dumps.
    last_agreed, _ = compare_hashes(dumps)

    section("3. Beat logs")
    for other in dumps[1:]:
        if len(dumps) > 2:
            print(" %s:" % other.label)
        found |= compare_logs(dumps[0], other, last_agreed, context)

    section("4. State snapshot")
    for other in dumps[1:]:
        if len(dumps) > 2:
            print(" %s:" % other.label)
        found |= compare_states(dumps[0], other, states)

    print()
    print("Result: %s" % ("the dumps differ" if found else "no difference between the dumps"))
    return 1 if found else 0


def rebuild(args):
    base = Dump(args.dump)
    beat = base.header.get("desync", {}).get("dump_beat")
    if not isinstance(beat, int) or beat <= 0:
        raise BadInput("%s has no dump beat" % args.dump)
    out = os.path.abspath(args.out or os.path.join(os.path.dirname(os.path.abspath(args.dump)), "rebuilt"))
    os.makedirs(out, exist_ok=True)
    log = os.path.join(out, "game.log")
    if os.path.exists(log):
        os.remove(log)
    command = [args.exe, "--replay", args.replay, "/init", args.init, "/nosound", "/log", log,
               "/desyncrecorder", "/desyncdumpbeat", str(beat)] + args.engine_args
    print("running: " + subprocess.list2cmdline(command))
    with open(os.path.join(out, "headless.txt"), "w") as console:
        try:
            process = subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT)
        except OSError as error:
            raise BadInput("can't run %s (%s)" % (args.exe, error))
    wrote = re.compile(r"Desync recorder: wrote (.+?\.zip)")
    written, deadline = None, time.time() + args.timeout
    while written is None and time.time() < deadline:
        if os.path.exists(log):
            with open(log, errors="replace") as handle:
                match = wrote.search(handle.read())
            if match:
                written = match.group(1)
                break
        if process.poll() is not None:
            break
        time.sleep(1)
    if process.poll() is None:
        process.kill()  # the dump is written; the rest of the replay isn't needed
        process.wait()
    if written is None:
        raise BadInput("the replay run wrote no dump (log: %s)" % log)
    print("wrote: " + written)
    if args.no_compare:
        return 0
    print()
    return compare([args.dump, written], args.context, args.states, args.force)


def main():
    argv = sys.argv[1:]
    engine_args = []
    if "--" in argv:  # everything after `--` goes to the engine untouched
        engine_args = argv[argv.index("--") + 1:]
        argv = argv[:argv.index("--")]
    if argv and argv[0] not in ("compare", "rebuild", "-h", "--help"):
        argv = ["compare"] + argv
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    cmp = commands.add_parser("compare", help="compare two or more dumps")
    cmp.add_argument("dumps", nargs="+")
    reb = commands.add_parser("rebuild", help="rebuild the other side from a replay, then compare")
    reb.add_argument("dump")
    reb.add_argument("--exe", required=True, help="the other player's headless exe")
    reb.add_argument("--replay", required=True)
    reb.add_argument("--init", required=True, help="init file that mounts the game data and the map")
    reb.add_argument("--out", help="folder for the run (default: rebuilt/ next to the dump)")
    reb.add_argument("--timeout", type=int, default=1800, help="seconds to wait for the dump")
    reb.add_argument("--no-compare", action="store_true")
    for sub in (cmp, reb):
        sub.add_argument("-C", "--context", type=int, default=10, help="lines of context (10)")
        sub.add_argument("--states", type=int, default=20, help="state differences to print (20)")
        sub.add_argument("--force", action="store_true", help="compare dumps from different games")
    args = parser.parse_args(argv)
    args.engine_args = engine_args
    try:
        if args.command == "rebuild":
            return rebuild(args)
        if len(args.dumps) < 2:
            raise BadInput("compare needs two dumps or more")
        return compare(args.dumps, args.context, args.states, args.force)
    except BadInput as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except (OSError, zipfile.BadZipFile, zlib.error, KeyError, IndexError, ValueError, csv.Error) as error:
        # A dump that opened but is damaged inside (a client that crashed while writing it).
        print("error: a dump is damaged (%s: %s)" % (type(error).__name__, error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
