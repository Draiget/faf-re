#!/usr/bin/env python3
"""Tests of policy_gen.py: routes against lockstep tables, the acceptance rule (K games, no counterexample), the
review of accepted rules and the policy files. Run: python tools/sync-routing/test_policy_gen.py"""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy_gen as pg  # noqa: E402


def enc(value):
    """LuaObject::ToByteStream's encoding, as compare.decode reads it."""
    if value is None:
        return b"\x02"
    if isinstance(value, bool):
        return b"\x03" + (b"\x01" if value else b"\x00")
    if isinstance(value, (int, float)):
        return b"\x00" + struct.pack("<f", float(value))
    if isinstance(value, str):
        return b"\x01" + value.encode("latin1") + b"\x00"
    if isinstance(value, dict):
        return b"\x04" + b"".join(enc(k) + enc(v) for k, v in value.items()) + b"\x05"
    raise TypeError(value)


def unit(army, serial):
    return str((army << 20) | serial)


PROP = str((2 << 28) | 5)


def write_dump(path, beats):
    with open(path, "wb") as f:
        for beat, table in beats:
            body = enc(table)
            f.write(struct.pack("<II", beat, len(body)) + body)


class Game:
    """A synthetic replay: per beat the focus -1 table and each army's lockstep table."""

    def __init__(self, armies, allies=None):
        self.armies = armies
        self.allies = allies or {}
        self.beats = []  # (beat, minus, [army tables])

    def beat(self, minus, per_army):
        self.beats.append((len(self.beats) + 1, minus, per_army))

    def summary(self, game, version=3840):
        with tempfile.TemporaryDirectory() as d:
            minus = os.path.join(d, "m.bin")
            write_dump(minus, [(b, m) for b, m, _ in self.beats])
            focus = []
            for a in range(self.armies):
                p = os.path.join(d, "f%d.bin" % a)
                write_dump(p, [(b, t[a]) for b, _, t in self.beats])
                focus.append(p)
            allies = os.path.join(d, "allies.txt")
            with open(allies, "w") as f:
                f.write("1 %s\n" % "".join("%d:%s;" % (a, ",".join(map(str, sorted(self.allies.get(a, ())))))
                                           for a in range(self.armies)))
            beats, stats = pg.observe(minus, focus, allies)
        return {"game": game, "game_version": version, "armies": self.armies, "beats": beats,
                "keys": {k: v.to_json() for k, v in stats.items()}}


def team_game(game_id, extra=None):
    """Four armies, 0+1 against 2+3, with the usual kinds of key."""
    g = Game(4, {0: {1}, 1: {0}, 2: {3}, 3: {2}})
    data = {unit(a, 1): {"x": a} for a in range(4)}
    enh = {unit(a, 2): {"Back": "Shield"} for a in range(4)}
    for _ in range(3):
        minus = {"UnitData": dict(data), "UserUnitEnhancements": dict(enh), "GameHasAIs": True,
                 "Score": {"1": {"general": {"score": 5, "kills": 1}}}, "Debug": {"x": 1}}
        per = []
        for a in range(4):
            team = {a, *g.allies[a]}
            per.append({"UnitData": {unit(a, 1): {"x": a}},
                        "UserUnitEnhancements": {k: v for k, v in enh.items() if (int(k) >> 20) in team},
                        "GameHasAIs": True,
                        "Score": {"1": {"general": {"score": 5}}} if a > 0 else minus["Score"]})
        if extra:
            extra(minus, per)
        g.beat(minus, per)
    return g.summary(game_id)


class RouteTests(unittest.TestCase):
    def test_by_id_routes(self):
        value = {unit(0, 1): 1, unit(1, 1): 2, PROP: 3, "Chat": 4}
        allies = {0: {1}}
        self.assertEqual(pg.route_output("EntityOwner", value, 0, allies), {unit(0, 1): 1, PROP: 3, "Chat": 4})
        # Allies: no army's ids (a prop's) go to nobody, as `Allied` says no.
        self.assertEqual(pg.route_output("EntityAllies", value, 0, allies), {unit(0, 1): 1, unit(1, 1): 2, "Chat": 4})
        self.assertEqual(pg.route_output("Everyone", value, 1, allies), value)
        self.assertIsNone(pg.route_output("Observers", value, 1, allies))
        self.assertEqual(pg.route_output("EntityOwner", True, 1, allies), True)

    def test_entity_ids(self):
        self.assertEqual(pg.entity_id("1048577"), 1048577)
        self.assertIsNone(pg.entity_id("Chat"))
        self.assertIsNone(pg.entity_id(1.0))  # a list index
        self.assertEqual(pg.unit_owner(int(unit(3, 7))), 3)
        self.assertEqual(pg.unit_owner(int(PROP)), -1)


class ObserveTests(unittest.TestCase):
    def test_team_game(self):
        s = team_game("g1")
        keys = s["keys"]
        self.assertEqual(s["beats"], 3)
        self.assertEqual(keys["UnitData"]["counter"].get("EntityOwner", 0), 0)
        self.assertEqual(keys["UnitData"]["counter"]["Everyone"], 3)
        self.assertEqual(keys["UserUnitEnhancements"]["counter"]["EntityOwner"], 3)
        self.assertEqual(keys["UserUnitEnhancements"]["counter"].get("EntityAllies", 0), 0)
        self.assertEqual(keys["GameHasAIs"]["counter"].get("Everyone", 0), 0)
        self.assertEqual(keys["Debug"]["counter"].get("Observers", 0), 0)
        for route in pg.GENERIC_ROUTES:
            self.assertGreater(keys["Score"]["counter"][route], 0, route)

    def test_release_allowance(self):
        dead = unit(1, 9)
        g = Game(2)
        g.beat({"UnitData": {dead: False}, "Other": {dead: False}},
               [{"UnitData": {dead: False}, "Other": {dead: False}}, {"UnitData": {dead: False}, "Other": {dead: False}}])
        keys = g.summary("g")["keys"]
        # UnitData's deaths stay with the owner; another key gets no such allowance.
        self.assertEqual(keys["UnitData"]["counter"].get("EntityOwner", 0), 0)
        self.assertEqual(keys["Other"]["counter"]["EntityOwner"], 1)

    def test_context_only(self):
        g = Game(2)
        g.beat({}, [{"Ping": {"1": 1.0}}, {}])
        keys = g.summary("g")["keys"]
        self.assertEqual(keys["Ping"]["beats"], 0)
        self.assertEqual(keys["Ping"]["context_beats"], 1)

    def test_table_addresses_ignored(self):
        g = Game(1)
        g.beat({"P": {"id": "table: 21399C08"}}, [{"P": {"id": "table: 0BADF00D"}}])
        self.assertEqual(g.summary("g")["keys"]["P"]["counter"].get("Everyone", 0), 0)

    def test_always_empty_is_unseen(self):
        g = Game(2)
        g.beat({"E": {}, "K": 1.0}, [{"E": {}, "K": 1.0}, {"E": {}, "K": 1.0}])
        s = g.summary("g")
        gen, merged, review, _, _ = pg.generate([s], {"E": {"route": "Everyone", "source": "hand", "games": 0,
                                                            "note": ""}}, 3840, 1, False)
        self.assertEqual(gen["E"]["note"], "only ever an empty table")
        self.assertEqual({r[1]: r[0] for r in review}["E"], "UNSEEN")
        self.assertEqual(merged["E"]["route"], "Everyone")

    def test_list_order_ignored(self):
        g = Game(1)
        g.beat({"L": {1.0: "a", 2.0: "b"}}, [{"L": {1.0: "b", 2.0: "a"}}])
        self.assertEqual(g.summary("g")["keys"]["L"]["counter"].get("Everyone", 0), 0)


class GenerateTests(unittest.TestCase):
    def corpus(self, n, extra=None):
        return [team_game("g%d" % i, extra) for i in range(n)]

    def test_k_rule(self):
        accepted = {}
        gen, merged, review, games, held = pg.generate(self.corpus(4), accepted, 3840, 5, False)
        self.assertEqual(len(games), 4)
        self.assertEqual(gen["UnitData"]["route"], "Observers")
        self.assertEqual(gen["UnitData"]["source"], "unclassified")
        self.assertIn("below K=5", gen["UnitData"]["note"])
        gen, merged, review, games, held = pg.generate(self.corpus(5), accepted, 3840, 5, False)
        self.assertEqual((gen["UnitData"]["route"], gen["UnitData"]["source"], gen["UnitData"]["games"]),
                         ("EntityOwner", "generated", 5))
        self.assertEqual(gen["UserUnitEnhancements"]["route"], "EntityAllies")
        self.assertEqual(gen["GameHasAIs"]["route"], "Everyone")
        self.assertEqual(gen["Debug"]["route"], "Observers")
        self.assertEqual(gen["Debug"]["source"], "generated")
        self.assertEqual(gen["Score"]["source"], "unclassified")
        self.assertTrue(all(r[0] == "NEW" for r in review))

    def test_duplicate_game_counts_once(self):
        corpus = self.corpus(4) + [team_game("g0")]
        gen, _, _, games, _ = pg.generate(corpus, {}, 3840, 5, False)
        self.assertEqual(len(games), 4)
        self.assertEqual(gen["UnitData"]["source"], "unclassified")

    def test_other_version_ignored(self):
        corpus = self.corpus(5)
        corpus[0]["game_version"] = 3835
        gen, _, _, games, _ = pg.generate(corpus, {}, 3840, 5, False)
        self.assertEqual(len(games), 4)
        self.assertEqual(gen["GameHasAIs"]["source"], "unclassified")

    def test_one_counterexample_vetoes(self):
        def leak(minus, per):
            per[2]["UnitData"][unit(0, 1)] = {"x": 0}  # once, an enemy's client held army 0's unit data
        corpus = self.corpus(5) + [team_game("odd", leak)]
        gen, _, _, _, _ = pg.generate(corpus, {}, 3840, 5, False)
        self.assertNotEqual(gen["UnitData"]["route"], "EntityOwner")

    def test_accepted_rules_held(self):
        accepted = {
            "UnitData": {"route": "EntityOwner", "source": "hand", "games": 0, "note": ""},
            "GameHasAIs": {"route": "Observers", "source": "hand", "games": 0, "note": ""},
            "Score": {"route": "Score", "source": "special", "games": 0, "note": ""},
            "HelpPrompt": {"route": "Everyone", "source": "hand", "games": 0, "note": ""},
        }
        gen, merged, review, _, held = pg.generate(self.corpus(5), accepted, 3840, 5, False)
        status = {r[1]: r[0] for r in review}
        self.assertEqual(status["UnitData"], "CONFIRMED")
        self.assertEqual(merged["UnitData"]["source"], "generated")
        self.assertEqual(status["GameHasAIs"], "CONTRADICTED (held)")
        self.assertEqual(merged["GameHasAIs"]["route"], "Observers")  # kept until accepted
        self.assertEqual(held, 1)
        self.assertEqual(status["Score"], "SPECIAL")
        self.assertEqual(merged["Score"]["route"], "Score")
        # The generated policy keeps the route with code of its own, so a server can run it.
        self.assertEqual((gen["Score"]["route"], gen["Score"]["source"]), ("Score", "special"))
        self.assertEqual(status["HelpPrompt"], "UNSEEN")
        self.assertEqual(merged["HelpPrompt"]["route"], "Everyone")
        self.assertEqual(status["UserUnitEnhancements"], "NEW")
        _, merged, review, _, held = pg.generate(self.corpus(5), accepted, 3840, 5, True)
        self.assertEqual(merged["GameHasAIs"]["route"], "Everyone")
        self.assertEqual(held, 0)


class FileTests(unittest.TestCase):
    def test_round_trip_and_cpp(self):
        rules = {"B": {"route": "Everyone", "source": "generated", "games": 7, "note": ""},
                 "A": {"route": "Score", "source": "special", "games": 0, "note": "x"}}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.tsv")
            pg.write_policy(path, rules, 3840, "test")
            read, version = pg.read_policy(path)
            self.assertEqual(version, 3840)
            self.assertEqual(read, rules)
            with open(path) as f:
                lines = [l for l in f if not l.startswith("#")]
            self.assertEqual([l.split("\t")[0] for l in lines], ["A", "B"])
            with open(path, "a") as f:
                f.write("C\tNoSuchRoute\n")
            with self.assertRaises(ValueError):
                pg.read_policy(path)

    def test_compiled_table_matches_policy_file(self):
        """The committed policy of each version is the compiled table (src/remote/SyncRouting.cpp kRoutes)."""
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
        compiled = dict(pg.compiled_routes(os.path.join(root, "src", "remote", "SyncRouting.cpp")))
        folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy")
        files = [f for f in os.listdir(folder) if f.endswith(".tsv")]
        self.assertTrue(files)
        for name in files:
            rules, version = pg.read_policy(os.path.join(folder, name))
            self.assertEqual(name, "%d.tsv" % version)
            self.assertEqual({k: r["route"] for k, r in rules.items()}, compiled, name)

    def test_static_writers(self):
        lua = {"lua/sim/a.lua": ["function F()", "  Sync.Ping = {}", "  if Sync.Ping == nil then end",
                                 "  table.insert(Sync.Voice, 1)", "  local s = Sync.Score", "  s[1] = 2", "end"],
               "lua/ui/b.lua": ["Sync.Ping = 1"]}
        sites = pg.static_writers(lua, ["Ping", "Voice", "Score"])
        self.assertEqual(sorted(sites["Ping"]), ["lua/sim/a.lua:2"])
        self.assertEqual(sorted(sites["Voice"]), ["lua/sim/a.lua:4"])
        self.assertEqual(sorted(sites["Score"]), ["lua/sim/a.lua:6"])

    def test_coverage_through_callers(self):
        lua = {"lua/a.lua": ["function SyncVoice(d)", "  Sync.Voice = d", "end"],
               "lua/b.lua": ["Brain = Class {", "  VoThread = function(self)", "    import('/lua/a.lua').SyncVoice(1)",
                             "  end,", "}", "local Paint = function(d)", "  Sync.P = d", "end",
                             "Callbacks.Share = function(d)", "  Paint(d)", "end"]}
        covered = {"VoThread": "owned thread (Brain)", "Callbacks.Share": "callback"}
        self.assertIn("owned thread", pg.coverage(lua, covered, "SyncVoice"))
        self.assertIn("callback", pg.coverage(lua, covered, "Paint"))
        self.assertIsNone(pg.coverage(lua, {}, "SyncVoice"))

    def test_enclosing_function(self):
        lines = ["local x = 1", "function A(self)", "  Sync.K = 1", "end", "Unit = Class {", "  Notify = function(self)",
                 "    Sync.E = 2", "  end,", "}"]
        self.assertEqual(pg.enclosing_function(lines, 3), "A")
        self.assertEqual(pg.enclosing_function(lines, 7), "Notify")
        self.assertEqual(pg.enclosing_function(lines, 1), "(main chunk)")
        nested = ["Brain = Class {", "  Toggle = function(self)", "    local function Inner(u)", "      u:Off()", "    end",
                  "    while true do", "      if x then", "        Sync.MassFabs = 'end'", "      end", "    end", "  end,",
                  "  Start = function(self)", "    self.EnergyThread = ForkThread(self.Toggle, self)", "  end,", "}"]
        self.assertEqual(pg.enclosing_function(nested, 4), "Inner")
        self.assertEqual(pg.enclosing_function(nested, 8), "Toggle")
        self.assertEqual(pg.coverage({"lua/b.lua": nested}, {"EnergyThread": "owned thread (field)"}, "Toggle"),
                         "via EnergyThread (lua/b.lua:13): owned thread (field)")


if __name__ == "__main__":
    unittest.main()
