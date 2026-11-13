#!/usr/bin/env python3
"""Generates the Lua `Sync` routing policy of the game server from lockstep runs of real replays.

A lockstep client builds the sim Lua's `Sync` table under its own focus army; a game server builds one table at
focus -1 and splits it per player by a policy, one route per top-level key (src/remote/SyncRouting.h, ESyncRoute).
This tool works the policy out from what lockstep clients really received:

    observe     one replay: its focus -1 run and one run focused on each army (headless --sync-dump, plus
                --sync-allies of any one of them), compared beat by beat and key by key. For each key and each
                generic route (Observers, EntityOwner, EntityAllies, Everyone) it counts the beats on which that route,
                applied to the focus -1 value, gives every army exactly what its lockstep client got (as
                tools/sync-routing/compare.py compares) and the beats on which it doesn't (counterexamples).
                Writes one JSON summary per replay.
    generate    the summaries of a corpus (one FAF game version) against the accepted policy file: a key gets a
                generated rule only when the narrowest route without a counterexample was seen in at least K
                different games, and no route was contradicted for it in any game; a key no generic route explains
                (its content depends on the focus in another way) is observer-only. Writes the generated policy, the
                merged policy and a review report. A rule already accepted is never changed without --accept.
    candidates  the functions that write focus-dependent keys (headless --sync-writers call sites, the FAF Lua
                source) and how the router covers each: a fan-out wrapper with the call-hook guard, an owned thread,
                a route of its own, or nothing yet.
    export-compiled / emit-cpp   the compiled table (kRoutes in src/remote/SyncRouting.cpp) as a policy file, and a
                policy file as kRoutes lines.

Policy files: `# game-version: <n>`, then `<key>\\t<route>\\t<source>\\t<games>\\t<note>` lines, sorted by key. The
server and headless read the first two columns (--sync-policy); source is `generated` (the generator's, accepted),
`hand` (written by people, not yet confirmed by K games), `special` (a route with code of its own, which the
generator can't produce), `unclassified` or `context` (observer-only: no generic route explains it, or it is only
ever written under a player's focus). Exit codes of generate: 0 nothing to review, 2 the review report lists
changes (held ones need --accept), 1 bad input.
"""
import argparse
import collections
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare import decode, normal, records  # noqa: E402  (the Lua byte stream, as compare.py reads it)

# Narrowest first: the generator picks the first one without a counterexample.
GENERIC_ROUTES = ("Observers", "EntityOwner", "EntityAllies", "Everyone")
# Routes with code of their own (a transform, not a split by audience); the generator never produces them.
SPECIAL_ROUTES = ("Reclaim", "ReleasedIds", "Score", "ScoreAccum", "NukeLaunch", "Chat")
ALL_ROUTES = GENERIC_ROUTES + SPECIAL_ROUTES
# A lockstep client gets every unit's death (`false` in UnitData, `true` in ReleaseIds: lua/sim/Unit.lua:2167-2173),
# seen or not; a player that never got that unit's data has nothing to clear, so the server keeps those with the
# owner (compare.py --army does the same). Only these keys get that allowance.
DEFAULT_RELEASE_KEYS = ("UnitData", "ReleaseIds")
# K: see docs in the module and generate's --min-games.
DEFAULT_MIN_GAMES = 5
SMALLEST_NUMBER_ID = 1 << 20


def entity_id(key):
    """The entity id a table key names, or None: a string of digits, or a whole number past list indices."""
    if isinstance(key, str):
        return int(key) if key.isdigit() and int(key) < 1 << 32 else None
    if isinstance(key, float) and key == int(key) and SMALLEST_NUMBER_ID <= key < 1 << 32:
        return int(key)
    return None


def unit_owner(eid):
    """The army of a unit's id (its source index), or -1 for any other family (props, projectiles)."""
    return (eid >> 20) & 0xFF if (eid >> 28) & 0xF == 0 else -1


def is_empty(value):
    return value is None or (isinstance(value, dict) and not value)


def route_output(route, value, army, allies):
    """What the server sends `army` of a focus -1 value under a generic route (CSyncRouter::RouteKey/RouteById)."""
    if route == "Observers":
        return None
    if route == "Everyone" or not isinstance(value, dict):
        return value  # a value that isn't a table goes to everyone under the by-id routes too
    out = {}
    for key, entry in value.items():
        eid = entity_id(key)
        if eid is None:
            out[key] = entry  # not a unit's: every player's (`Sync.UnitData.Chat`)
            continue
        owner = unit_owner(eid)
        if route == "EntityOwner":
            wanted = owner < 0 or owner == army
        else:  # EntityAllies: `Allied` is false for no army
            wanted = owner >= 0 and (owner == army or owner in allies.get(army, ()))
        if wanted:
            out[key] = entry
    return out


def drop_releases(lockstep, routed, army, key, release_keys):
    """Lockstep's deaths of units this view's route didn't give it, for the keys whose deaths stay with the owner."""
    if key not in release_keys or not isinstance(lockstep, dict):
        return lockstep
    kept = {}
    for k, v in lockstep.items():
        eid = entity_id(k)
        if isinstance(v, bool) and eid is not None and unit_owner(eid) != army and not (
                isinstance(routed, dict) and k in routed):
            continue
        kept[k] = v
    return kept


ADDRESS_RE = re.compile(r"^(table|function|userdata|thread|cfunction): ?[0-9A-Fa-fx]+$")


def without_addresses(value):
    """`tostring` of a Lua table (`table: 21399C08`) differs from run to run: all such strings made one."""
    if isinstance(value, dict):
        return {without_addresses(k): without_addresses(v) for k, v in value.items()}
    if isinstance(value, str) and ADDRESS_RE.match(value):
        return value.split(":", 1)[0] + ": *"
    return value


def same(a, b):
    if is_empty(a) and is_empty(b):
        return True
    if is_empty(a) or is_empty(b):
        return False
    return normal(a) == normal(b) or normal(without_addresses(a)) == normal(without_addresses(b))


def read_allies(path):
    """--sync-allies: `<beat> <army>:<ally>,...;...` lines -> sorted [(beat, {army: set(allies)})]."""
    out = []
    if not path:
        return out
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 1:
                continue
            beat = int(parts[0])
            table = {}
            for item in (parts[1] if len(parts) > 1 else "").split(";"):
                if ":" not in item:
                    continue
                army, rest = item.split(":", 1)
                table[int(army)] = {int(x) for x in rest.split(",") if x}
            out.append((beat, table))
    return out


def allies_at(timeline, beat):
    current = {}
    for b, table in timeline:
        if b > beat:
            break
        current = table
    return current


def replay_game_version(path):
    """The FAF game version in a replay's header (`... v1.50.3840`), or 0."""
    try:
        with open(path, "rb") as f:
            head = f.read(256)
        text = head.split(b"\0", 1)[0].decode("latin1")
        match = re.search(r"(\d+)\s*$", text)
        return int(match.group(1)) if match else 0
    except OSError:
        return 0


def merged_records(paths):
    """Yields (beat, [body or None per path]) over the beats every file has, in order."""
    streams = [records(p) for p in paths]
    heads = [next(s, None) for s in streams]
    while all(h is not None for h in heads):
        beat = max(h[0] for h in heads)
        for i, s in enumerate(streams):
            while heads[i] is not None and heads[i][0] < beat:
                heads[i] = next(s, None)
        if any(h is None for h in heads):
            return
        if all(h[0] == beat for h in heads):
            yield beat, [bytes(h[1]) for h in heads]
            heads = [next(s, None) for s in streams]


class KeyStats:
    def __init__(self):
        self.beats = 0              # beats with a value at focus -1
        self.context_beats = 0      # beats it reached some army's lockstep client and focus -1 had none
        self.focus_dependent = 0    # beats on which some army's lockstep value differed from focus -1's
        self.counter = collections.Counter()   # route -> beats with a counterexample
        self.distinct = collections.Counter()  # route -> beats on which it sends something other than Everyone
        self.example = {}           # route -> first counterexample

    def to_json(self):
        return {"beats": self.beats, "context_beats": self.context_beats, "focus_dependent": self.focus_dependent,
                "counter": dict(self.counter), "distinct": dict(self.distinct), "example": self.example}


def observe_beat(stats, minus, focused, allies, beat, release_keys):
    """One beat: `minus` the focus -1 table, `focused[a]` army a's lockstep table."""
    keys = set(minus)
    for table in focused:
        keys |= set(table)
    for key in sorted(keys, key=str):
        if not isinstance(key, str):
            continue
        value = minus.get(key)
        st = stats[key]
        if is_empty(value):
            if any(not is_empty(t.get(key)) for t in focused):
                st.context_beats += 1
            continue
        st.beats += 1
        if any(not same(t.get(key), value) for t in focused):
            st.focus_dependent += 1
        for route in GENERIC_ROUTES:
            bad = None
            differs = False
            for army, table in enumerate(focused):
                routed = route_output(route, value, army, allies)
                lockstep = drop_releases(table.get(key), routed, army, key, release_keys)
                if not same(lockstep, routed) and bad is None:
                    bad = (army, lockstep, routed)
                if route != "Everyone" and not same(routed, value):
                    differs = True
            if differs:
                st.distinct[route] += 1
            if bad is not None:
                st.counter[route] += 1
                if route not in st.example:
                    army, lockstep, routed = bad
                    st.example[route] = {"beat": beat, "army": army, "lockstep": repr(lockstep)[:200],
                                         "routed": repr(routed)[:200]}


def observe(minus_path, focus_paths, allies_path, release_keys=DEFAULT_RELEASE_KEYS):
    """Per-key statistics of one replay. `focus_paths[a]` is army a's --sync-dump."""
    timeline = read_allies(allies_path)
    stats = collections.defaultdict(KeyStats)
    beats = 0
    for beat, bodies in merged_records([minus_path] + list(focus_paths)):
        tables = [decode(b)[0] if b else {} for b in bodies]
        tables = [t if isinstance(t, dict) else {} for t in tables]
        observe_beat(stats, tables[0], tables[1:], allies_at(timeline, beat), beat, release_keys)
        beats += 1
    return beats, stats


# ---- policy files ----

def read_policy(path):
    """{key: {"route", "source", "games", "note"}}, game version."""
    rules = {}
    version = 0
    with open(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith("# game-version:"):
                version = int(line.split(":", 1)[1])
                continue
            if not line.strip() or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) < 2 or cols[1] not in ALL_ROUTES:
                raise ValueError("%s: bad line %r" % (path, line))
            if cols[0] in rules:
                raise ValueError("%s: %s listed twice" % (path, cols[0]))
            rules[cols[0]] = {"route": cols[1], "source": cols[2] if len(cols) > 2 else "hand",
                              "games": int(cols[3]) if len(cols) > 3 and cols[3].isdigit() else 0,
                              "note": cols[4] if len(cols) > 4 else ""}
    return rules, version


def write_policy(path, rules, version, header):
    with open(path, "w", newline="\n") as f:
        f.write("# Lua Sync routing policy (src/remote/SyncRouting.h). %s\n" % header)
        f.write("# key\troute\tsource\tgames\tnote\n")
        f.write("# game-version: %d\n" % version)
        for key in sorted(rules):
            r = rules[key]
            line = "%s\t%s\t%s\t%d" % (key, r["route"], r["source"], r["games"])
            f.write(line + ("\t" + r["note"] if r.get("note") else "") + "\n")


def compiled_routes(cpp_path):
    """kRoutes of src/remote/SyncRouting.cpp: [(key, route)]."""
    with open(cpp_path, encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"constexpr SSyncKeyRoute kRoutes\[\] = \{(.*?)\n    \};", text, re.S)
    if not block:
        raise ValueError("no kRoutes in " + cpp_path)
    return re.findall(r'\{"([^"]+)", ESyncRoute::(\w+)\}', block.group(1))


# ---- generate ----

def aggregate(summaries, game_version):
    """Per key over the corpus: games seen, counterexamples and distinct beats per route."""
    keys = collections.defaultdict(lambda: {"games": set(), "context_games": set(), "focus_dependent": 0,
                                            "counter": collections.Counter(), "counter_games": collections.defaultdict(set),
                                            "distinct": collections.Counter(), "example": {}})
    games = set()
    for s in summaries:
        if s["game_version"] != game_version:
            continue
        if s["game"] in games:
            continue  # two replays of one game are one observation
        games.add(s["game"])
        for key, st in s["keys"].items():
            k = keys[key]
            if st["beats"]:
                k["games"].add(s["game"])
            if st["context_beats"]:
                k["context_games"].add(s["game"])
            k["focus_dependent"] += st["focus_dependent"]
            for route, n in st["counter"].items():
                k["counter"][route] += n
                k["counter_games"][route].add(s["game"])
            for route, n in st["distinct"].items():
                k["distinct"][route] += n
            for route, ex in st["example"].items():
                k["example"].setdefault(route, dict(ex, game=s["game"]))
    return keys, games


def classify(k, min_games):
    """(route, source, games, note) generated for one key from its aggregate."""
    seen = len(k["games"])
    if not seen and not k["context_games"]:
        return "Observers", "unclassified", 0, "only ever an empty table"
    if not seen:
        return "Observers", "context", 0, "only ever written under a player's focus (%d games)" % len(k["context_games"])
    for route in GENERIC_ROUTES:
        if k["counter"][route]:
            continue
        if route != "Everyone" and not k["distinct"][route]:
            continue  # never told apart from a wider route: no evidence for it
        if seen >= min_games:
            return route, "generated", seen, ""
        return "Observers", "unclassified", seen, "%s in %d games, below K=%d" % (route, seen, min_games)
    return "Observers", "unclassified", seen, "no generic route explains it (focus-dependent on %d beats)" % (
        k["focus_dependent"])


def generate(summaries, accepted, game_version, min_games, accept):
    """The generated policy, the merged one and the review lines."""
    agg, games = aggregate(summaries, game_version)
    generated = {}
    findings = {}
    for key in sorted(agg):
        route, source, n, note = classify(agg[key], min_games)
        findings[key] = {"route": route, "source": source, "games": n, "note": note}
        generated[key] = dict(findings[key])
    # The generated policy is one a server can run: the routes with code of their own come from the accepted file, as
    # the generator can't produce them; every other key is the generator's alone.
    for key, acc in accepted.items():
        if acc["route"] in SPECIAL_ROUTES:
            seen = findings.get(key, {}).get("games", 0)
            generated[key] = {"route": acc["route"], "source": "special", "games": seen,
                              "note": "a route of its own, kept from the accepted policy"}

    merged = {}
    review = []
    held = 0
    for key in sorted(set(accepted) | set(findings)):
        acc = accepted.get(key)
        gen = findings.get(key)
        k = agg.get(key)
        if acc is None:
            merged[key] = dict(gen)
            review.append(("NEW", key, "-", "%s (%s, %d games)" % (gen["route"], gen["source"], gen["games"]), gen["note"]))
            continue
        if gen is None or gen["note"] == "only ever an empty table":
            merged[key] = dict(acc)
            review.append(("UNSEEN", key, acc["route"], "-", "kept: no game of the corpus wrote it"))
            continue
        contradicted = acc["route"] in GENERIC_ROUTES and k is not None and k["counter"][acc["route"]] > 0
        ex = k["example"].get(acc["route"]) if contradicted else None
        if acc["route"] in SPECIAL_ROUTES:
            merged[key] = dict(acc)
            review.append(("SPECIAL", key, acc["route"], "%s (%s, %d games)" % (gen["route"], gen["source"], gen["games"]),
                           "kept: a route of its own; " + (gen["note"] or "generic finding only")))
        elif gen["source"] == "generated" and gen["route"] == acc["route"]:
            merged[key] = dict(acc, source="generated", games=gen["games"], note="")
            review.append(("CONFIRMED", key, acc["route"], gen["route"], "%d games" % gen["games"]))
        elif gen["source"] in ("unclassified", "context") and acc["route"] == "Observers" and not (
                gen["source"] == "unclassified" and "below K" in gen["note"]):
            merged[key] = dict(acc, source=gen["source"], games=gen["games"], note=gen["note"])
            review.append(("CONFIRMED", key, "Observers", "Observers (%s)" % gen["source"], gen["note"]))
        elif gen["source"] == "context":
            merged[key] = dict(acc)
            review.append(("CONTEXT", key, acc["route"], "Observers (context)",
                           "kept: never at focus -1 in the corpus, so the route is unused there; " + gen["note"]))
        elif gen["source"] == "unclassified" and "below K" in gen["note"] and not contradicted:
            merged[key] = dict(acc)
            review.append(("BELOW-K", key, acc["route"], gen["note"].split(" in ")[0], "kept: " + gen["note"]))
        else:
            what = "CONTRADICTED" if contradicted else "CHANGE"
            note = gen["note"]
            if ex:
                note = ("%s; counterexample game %s beat %d army %d: lockstep %s, route %s" % (
                    note, ex["game"], ex["beat"], ex["army"], ex["lockstep"][:80], ex["routed"][:80])).lstrip("; ")
            if accept:
                merged[key] = dict(gen)
                review.append((what + " (applied)", key, acc["route"], gen["route"], note))
            else:
                merged[key] = dict(acc)
                held += 1
                review.append((what + " (held)", key, acc["route"], "%s (%s)" % (gen["route"], gen["source"]), note))
    return generated, merged, review, games, held


def cmd_observe(args):
    focus_paths = args.focus
    beats, stats = observe(args.minus, focus_paths, args.allies, tuple(args.release_keys.split(",")))
    version = args.game_version
    if not version and args.replay:
        version = replay_game_version(args.replay)
    out = {"game": args.game, "game_version": version, "armies": len(focus_paths), "beats": beats,
           "keys": {k: v.to_json() for k, v in sorted(stats.items())}}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("observed game %s (version %s): %d beats, %d armies, %d keys" % (args.game, version, beats,
                                                                           len(focus_paths), len(stats)))
    return 0


def cmd_generate(args):
    summaries = []
    for path in args.summaries:
        with open(path) as f:
            summaries.append(json.load(f))
    accepted, acc_version = read_policy(args.accepted) if args.accepted else ({}, 0)
    if args.accepted and acc_version != args.game_version:
        print("the accepted policy is for game version %d, not %d" % (acc_version, args.game_version))
        return 1
    generated, merged, review, games, held = generate(summaries, accepted, args.game_version, args.min_games,
                                                      args.accept)
    others = sorted({s["game_version"] for s in summaries} - {args.game_version})
    header = "Generated by tools/sync-routing/policy_gen.py from %d games, K=%d." % (len(games), args.min_games)
    write_policy(args.out_generated, generated, args.game_version, header)
    write_policy(args.out_merged, merged, args.game_version, header + " Accepted rules kept unless --accept.")
    changes = [r for r in review if r[0] not in ("CONFIRMED", "UNSEEN", "SPECIAL", "BELOW-K", "CONTEXT")]
    with open(args.report, "w", newline="\n") as f:
        f.write("Sync routing policy review: FAF game version %d, %d games (%s), K=%d\n" % (
            args.game_version, len(games), ", ".join(sorted(map(str, games))), args.min_games))
        if others:
            f.write("ignored summaries of other game versions: %s\n" % ", ".join(map(str, others)))
        counts = collections.Counter(r[0].split(" ")[0] for r in review)
        f.write("totals: %s\n\n" % ", ".join("%s %d" % kv for kv in sorted(counts.items())))
        f.write("%-22s %-28s %-14s %-34s %s\n" % ("status", "key", "accepted", "generated", "note"))
        for status, key, acc, gen, note in review:
            f.write("%-22s %-28s %-14s %-34s %s\n" % (status, key, acc, gen, note))
    print("%d games, %d keys generated; review: %s; %d changes, %d held" % (
        len(games), len(generated), args.report, len(changes), held))
    return 2 if changes else 0


def lua_functions(lua_root):
    """{"lua/x.lua": [lines]} from a folder or a .nx2/.zip archive, paths lower-cased."""
    files = {}
    if os.path.isdir(lua_root):
        for base, _, names in os.walk(lua_root):
            for name in names:
                if name.endswith(".lua"):
                    path = os.path.join(base, name)
                    rel = os.path.relpath(path, os.path.dirname(lua_root.rstrip("/\\")) if os.path.basename(
                        lua_root.rstrip("/\\")).lower() == "lua" else lua_root).replace("\\", "/").lower()
                    with open(path, encoding="latin1") as f:
                        files[rel] = f.read().split("\n")
    else:
        with zipfile.ZipFile(lua_root) as z:
            for name in z.namelist():
                if name.lower().endswith(".lua"):
                    files[name.lower().lstrip("/")] = z.read(name).decode("latin1").split("\n")
    return files


FUNCTION_RE = re.compile(r"^\s*(?:local\s+)?function\s+([\w.:]+)\s*\(|^\s*(?:local\s+)?([\w.]+)\s*=\s*function\s*\(")


def callers(lua, name):
    """The functions of the sim's Lua that call `name` (by its short name), as {function: "path:line"}."""
    out = {}
    pattern = re.compile(r"(?<!\w)%s\s*\(" % re.escape(name))
    # `self.Field = ForkThread(self.Name, ...)`: the thread is known by the field it is kept in.
    forked = re.compile(r"([\w.]+)\s*=\s*[\w.:]*ForkThread\(\s*[\w.:]*(?<!\w)%s\b" % re.escape(name))
    for path, lines in lua.items():
        if path.startswith(("lua/ui/", "lua/user/")):
            continue
        for number, line in enumerate(lines, 1):
            code = line.split("--", 1)[0]
            fork = forked.search(code)
            if fork:
                out.setdefault(re.split(r"[.:]", fork.group(1))[-1], "%s:%d" % (path, number))
            elif pattern.search(code) and not FUNCTION_RE.match(code):
                out.setdefault(enclosing_function(lines, number), "%s:%d" % (path, number))
    return out


def coverage(lua, covered, function, depth=2):
    """How the router covers a writer: itself wrapped, or called from a wrapped function or owned thread."""
    short = re.split(r"[.:]", function)[-1]
    if function in covered:
        return covered[function]
    if short in covered:
        return covered[short]
    if depth == 0 or not lua or function == "(main chunk)":
        return None
    for caller, site in sorted(callers(lua, short).items()):
        how = coverage(lua, covered, caller, depth - 1)
        if how:
            return "via %s (%s): %s" % (re.split(r"[.:]", caller)[-1], site, how)
    return None


LUA_TOKEN_RE = re.compile(r"\b(function|if|do|repeat|end|until)\b")
LUA_STRING_RE = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")


def enclosing_function(lines, line_number):
    """The name of the innermost named function a 1-based line is in, or '(main chunk)'. Blocks are followed by their
    keywords (`function`, `if`, `do`, `repeat` against `end`, `until`), with strings and `--` comments left out; a
    function without a name of its own (`ForkThread(function() ... end)`) is skipped over to the one around it."""
    stack = []
    for i in range(min(line_number, len(lines))):
        code = LUA_STRING_RE.sub('""', lines[i]).split("--", 1)[0]
        named = FUNCTION_RE.match(lines[i])
        for token in LUA_TOKEN_RE.findall(code):
            if i == line_number - 1 and token in ("end", "until"):
                break  # the line itself counts as inside the block it closes
            if token == "function":
                stack.append(named.group(1) or named.group(2) if named else None)
                named = None
            elif token in ("if", "do", "repeat"):
                stack.append(False)
            elif stack:
                stack.pop()
    for frame in reversed(stack):
        if frame:
            return frame
    return "(main chunk)"


def static_writers(lua, keys):
    """Without --sync-writers files: the sim-side source lines that write each key (`Sync.K = `, `Sync.K[...] = `,
    `Sync['K'] = `, `table.insert(Sync.K, ...)`, and a local alias of `Sync.K` assigned within the next lines), as
    the static audit reads them. Counts are 0: these are places, not runs."""
    sites = collections.defaultdict(collections.Counter)
    for path, lines in lua.items():
        if path.startswith(("lua/ui/", "lua/user/")):
            continue
        for number, line in enumerate(lines, 1):
            code = line.split("--", 1)[0]
            for key in keys:
                pattern = (r"Sync\s*(?:\.\s*%s\b|\[\s*['\"]%s['\"]\s*\])" % (key, key))
                m = re.search(pattern, code)
                if not m:
                    continue
                rest = code[m.end():]
                write = re.match(r"\s*(?:\[[^\]]*\]\s*)*=(?!=)", rest) or re.search(
                    r"table\.insert\s*\(\s*$", code[:m.start()])
                alias = re.match(r"\s*local\s+(\w+)\s*=\s*$", code[:m.start()])
                if write:
                    sites[key]["%s:%d" % (path, number)] += 0
                elif alias:
                    name = alias.group(1)
                    for later in range(number, min(number + 15, len(lines))):
                        if re.search(r"\b%s\s*(?:\[[^\]]*\]|\.\w+)\s*=[^=]" % re.escape(name), lines[later]):
                            sites[key]["%s:%d" % (path, later + 1)] += 0
    return sites


def wrapped_functions(cpp_path):
    """kWrapped and kOwnedThreads of SyncRouting.cpp: {function name: how it is covered}."""
    with open(cpp_path, encoding="utf-8") as f:
        text = f.read()
    out = {}
    block = re.search(r"constexpr SWrappedFunction kWrapped\[\] = \{(.*?)\n    \};", text, re.S)
    for module, cls, name, thunk in re.findall(
            r'\{(nullptr|"[^"]*"), (nullptr|"[^"]*"), "(\w+)", &(\w+)\}', block.group(1) if block else ""):
        out[name] = "wrapped (%s%s)" % (thunk, ", " + cls.strip('"') if cls != "nullptr" else "")
    block = re.search(r"constexpr SOwnedThread kOwnedThreads\[\] = \{(.*?)\n    \};", text, re.S)
    for module, cls, name in re.findall(r'\{"([^"]*)", "(\w+)", "(\w+)"\}', block.group(1) if block else ""):
        out[name] = "owned thread (%s)" % cls
    block = re.search(r"constexpr const char\* kOwnedThreadFields\[\] = \{([^}]*)\}", text)
    for name in re.findall(r'"(\w+)"', block.group(1) if block else ""):
        out[name] = "owned thread (the brain's %s field)" % name
    # Sim callbacks (`Callbacks.<name>`, run by `DoCallback`) that DoCallbackThunk runs for each view itself.
    for name in re.findall(r'std::strcmp\(name, "(\w+)"\) == 0', text):
        out.setdefault("Callbacks." + name, "callback run by DoCallbackThunk for each view")
    # Functions the router runs under each view's focus by name: focus moves and reconnects.
    for name in sorted(set(re.findall(r'GetGlobal\("(\w+)"\)|\)\["(OnPostLoad)"\]', text)) - {("", "")}):
        name = name[0] or name[1]
        out.setdefault(name, "run per view by the router (%s)" % name)
    return out


def cmd_candidates(args):
    summaries = []
    for path in args.summaries:
        with open(path) as f:
            summaries.append(json.load(f))
    agg, games = aggregate(summaries, args.game_version)
    policy = {}
    if args.policy:
        policy, _ = read_policy(args.policy)
    sites = collections.defaultdict(collections.Counter)
    for path in args.writers:
        with open(path) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                key, count, site = line.rstrip("\n").split("\t")
                sites[key][site] += int(count)
    lua = lua_functions(args.lua) if args.lua else {}
    if not sites and lua:
        sites = static_writers(lua, agg)
    covered = wrapped_functions(args.cpp)
    rows = []
    for key in sorted(agg):
        k = agg[key]
        # Focus-dependent and no generic route explains it, or only ever written under a player's focus.
        explained = k["games"] and any(not k["counter"][r] for r in GENERIC_ROUTES)
        dependent = (k["focus_dependent"] > 0 and not explained) or bool(k["context_games"])
        if not dependent:
            continue
        route = policy.get(key, {}).get("route", "-")
        for site, count in sorted(sites.get(key, {}).items()) or [("(no call site recorded)", 0)]:
            m = re.match(r"(.+):(\d+)$", site)
            function = enclosing_function(lua.get(m.group(1), []), int(m.group(2))) if m and lua else "?"
            how = coverage(lua, covered, function) or (
                "a route of its own (%s)" % route if route in SPECIAL_ROUTES else "not covered")
            rows.append((key, route, site, function, count, how))
    print("Focus-dependent Sync keys of game version %d over %d games and the functions that write them" % (
        args.game_version, len(games)))
    print("%-26s %-12s %-46s %-36s %7s %s" % ("key", "route", "call site", "function", "writes", "coverage"))
    for row in rows:
        print("%-26s %-12s %-46s %-36s %7d %s" % row)
    return 0


def cmd_export_compiled(args):
    rules = {key: {"route": route, "source": "special" if route in SPECIAL_ROUTES else "hand", "games": 0, "note": ""}
             for key, route in compiled_routes(args.cpp)}
    write_policy(args.out, rules, args.game_version, "Exported from the compiled table.")
    print("%d keys" % len(rules))
    return 0


def cmd_emit_cpp(args):
    rules, _ = read_policy(args.policy)
    for key in sorted(rules):
        print('      {"%s", ESyncRoute::%s},' % (key, rules[key]["route"]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("observe", help="one replay's focus runs into a JSON summary")
    p.add_argument("--minus", required=True, help="--sync-dump of the focus -1 run")
    p.add_argument("--focus", nargs="+", required=True, help="--sync-dump of each army's run, army 0 first")
    p.add_argument("--allies", help="--sync-allies of any of the runs")
    p.add_argument("--game", required=True, help="the game's id (replays of one game count once)")
    p.add_argument("--replay", help="the replay, for its FAF game version")
    p.add_argument("--game-version", type=int, default=0)
    p.add_argument("--release-keys", default=",".join(DEFAULT_RELEASE_KEYS))
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_observe)
    p = sub.add_parser("generate", help="summaries of a corpus into a policy and a review report")
    p.add_argument("summaries", nargs="+")
    p.add_argument("--game-version", type=int, required=True)
    p.add_argument("--accepted", help="the accepted policy file of that version")
    p.add_argument("--min-games", type=int, default=DEFAULT_MIN_GAMES, help="K (default %(default)s)")
    p.add_argument("--accept", action="store_true", help="apply changes to accepted rules (after review)")
    p.add_argument("--out-generated", required=True)
    p.add_argument("--out-merged", required=True)
    p.add_argument("--report", required=True)
    p.set_defaults(func=cmd_generate)
    p = sub.add_parser("candidates", help="fan-out candidates: writers of focus-dependent keys")
    p.add_argument("summaries", nargs="+")
    p.add_argument("--game-version", type=int, required=True)
    p.add_argument("--writers", nargs="*", default=[], help="headless --sync-writers files of focused runs")
    p.add_argument("--lua", help="the FAF Lua: a folder or lua.nx2")
    p.add_argument("--cpp", required=True, help="src/remote/SyncRouting.cpp")
    p.add_argument("--policy", help="a policy file, for each key's route")
    p.set_defaults(func=cmd_candidates)
    p = sub.add_parser("export-compiled", help="kRoutes as a policy file")
    p.add_argument("--cpp", required=True)
    p.add_argument("--game-version", type=int, required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_export_compiled)
    p = sub.add_parser("emit-cpp", help="a policy file as kRoutes lines")
    p.add_argument("policy")
    p.set_defaults(func=cmd_emit_cpp)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
