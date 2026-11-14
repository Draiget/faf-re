"""Run with Python + lupa (Lua 5.1); no game or network connection required."""
import heapq
from pathlib import Path
import unittest

from lupa.lua51 import LuaRuntime

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "data/fafengine/lua/ui/lobby"


class Network:
    def __init__(self, names):
        self.names = names.copy()
        self.nodes = {}
        self.queue = []
        self.serial = 0
        self.now = 0.0
        self.drop = lambda sender, receiver, data: False

    def send(self, sender, receiver, table):
        def plain(value):
            if hasattr(value, "items"):
                return {key: plain(item) for key, item in value.items()}
            return value

        data = plain(table)
        if self.drop(sender, receiver, data):
            return
        data["SenderID"] = sender  # Transport-authenticated identity.
        self.serial += 1
        heapq.heappush(self.queue, (self.now + .02, self.serial, receiver, data))

    def advance(self, seconds):
        for _ in range(round(seconds / .05)):
            self.now = round(self.now + .05, 5)
            for node in self.nodes.values():
                node.lua.globals().now = self.now
                node.lua.globals().peerNames = node.lua.table_from(self.names)
            while self.queue and self.queue[0][0] <= self.now:
                _, _, receiver, data = heapq.heappop(self.queue)
                if receiver in self.nodes and receiver in self.names:
                    node = self.nodes[receiver]
                    node.comm.DataReceived(node.comm, node.lua.table_from(data, recursive=True))
            for node in self.nodes.values():
                node.lua.execute("coroutine.resume(worker)")


class Node:
    def __init__(self, network, uid, host=1):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.now, g.uid, g.peerNames = network.now, uid, self.lua.table_from(network.names)
        g.transport = lambda receiver, data: network.send(uid, int(receiver), data)
        self.lua.execute("""
            buttons = {}
            preferences, commands = {}, {}
            function GetPreference(key, fallback)
                if preferences[key] == nil then return fallback end
                return preferences[key]
            end
            function SetPreference(key, value) preferences[key] = value end
            function ConExecute(command) table.insert(commands, command) end
            function LOG() end
            function IsDestroyed(control) return control.destroyed end
            function control()
                local c = {}
                for _, name in ipairs({'Width', 'Height', 'Depth'}) do c[name] = {Set=function() end} end
                c.Destroy = function(self) self.destroyed = true end
                c.SetFont = function() end
                c.SetText = function(self, text) displayText = text end
                return c
            end
            ui = {bodyFont='body', titleFont='title', CreateText=control}
            ui.CreateButtonStd = function(parent, texture, text)
                local c = control(); c.label={text=text, SetText=function(self,value) self.text=value end}; table.insert(buttons, c); return c
            end
            layout = setmetatable({}, {__index=function() return function() end end})
            function GetSystemTimeSeconds() return now end
            function WaitSeconds() coroutine.yield() end
            function ForkThread(fn) worker=coroutine.create(fn) end
            comm = {
                GetLocalPlayerID=function() return uid end,
                GetLocalPlayerName=function() return peerNames[uid] end,
                IsHost=function() return uid == 1 end,
                GetPeers=function()
                    local peers={}
                    for id,name in pairs(peerNames) do
                        if id ~= uid then table.insert(peers,{id=tostring(id),name=name,status='Established'}) end
                    end
                    return peers
                end,
                SendData=function(self,id,data) transport(id,data) end,
                Hosting=function() end,
                ConnectionToHostEstablished=function(self, localId, localName, hostId)
                    assert(localId == uid and localName == peerNames[uid] and hostId == 1,
                        'Join callback arguments were changed by the hook')
                    connectedName, connectedHost = localName, hostId
                end,
                DataReceived=function() end, Destroy=function() end,
            }
        """)
        score = self.lua.execute((SOURCE / "connectionscore.lua").read_text())

        def import_module(path):
            if path.endswith("connectionscore.lua"):
                return score
            if path.endswith("uiutil.lua"):
                return g.ui
            if path.endswith("layouthelpers.lua"):
                return g.layout
            if path.endswith("group.lua"):
                return self.lua.table_from({"Group": g.control})
            if path.endswith("popup.lua"):
                return self.lua.table_from({"Popup": g.control})
            if path.endswith("textarea.lua"):
                return self.lua.table_from({"TextArea": g.control})
            raise AssertionError(path)

        g["import"] = import_module
        self.lua.execute((SOURCE / "connectiontest.lua").read_text())
        self.comm = g.comm
        g.Attach(self.comm)
        if uid == host:
            self.comm.Hosting(self.comm)
        else:
            self.comm.ConnectionToHostEstablished(self.comm, uid, network.names[uid], host)
        g.Show(g.control())
        self.lua.execute("buttons[1].OnClick()")
        network.nodes[uid] = self

    def start(self):
        self.lua.execute("buttons[3].OnClick()")

    @property
    def text(self):
        return self.lua.globals().displayText


class ConnectionTests(unittest.TestCase):
    def test_builder_threading_hook_applies_before_lobby_creation(self):
        source = (SOURCE / "lobby.lua").read_text()
        for workers in (None, 0, 4):
            lua = LuaRuntime(unpack_returned_tuples=True)
            lua.execute("""
                commands = {}
                function ConExecute(value) assert(not created); table.insert(commands, value) end
                function LOG() end
                function WARN(text) error(text) end
                function UpdateGame() end
                function TryLaunch() end
                function ReallyCreateLobby() created = true end
                function CreateUI() end
                Prefs = {GetFromCurrentProfile=function() end}
                function import(path)
                    return {CreateLobbyComm=function() end, CreateButtonStd=function() end,
                        CreateScreenGroup=function() end, Reset=function() end}
                end
            """)
            configured = source if workers is None else source.replace(
                "local microchipSimWorkers = nil", "local microchipSimWorkers = " + str(workers))
            lua.execute(configured)
            lua.globals().ReallyCreateLobby()
            self.assertTrue(lua.globals().created)
            self.assertEqual(lua.globals().commands[1], None if workers is None else "sim_Workers " + str(workers))

    def test_checksum_toggle_is_local_persistent_and_applied_before_game(self):
        net = Network({1: "Alice", 2: "Bob"})
        alice, bob = Node(net, 1), Node(net, 2)
        alice.lua.execute("""
            assert(commands[1] == 'net_CheckOrderStreams 1')
            assert(commands[2] == 'net_MaxSendRate 8192')
            buttons[2].OnClick()
            assert(preferences.microchip_extra_checksums == false)
            assert(commands[3] == 'net_CheckOrderStreams 0')
            assert(buttons[2].label.text == 'Checksums: Off')
            Show(control())
            assert(commands[4] == 'net_CheckOrderStreams 0')
            buttons[6].OnClick()
            assert(preferences.microchip_extra_checksums == true)
            assert(commands[5] == 'net_CheckOrderStreams 1')
            assert(commands[6] == 'net_MaxSendRate 8192')
        """)
        self.assertEqual(bob.lua.globals().commands[1], 'net_CheckOrderStreams 1')
        self.assertEqual(net.serial, 0)

    def test_join_callback_preserves_player_name_and_host_id(self):
        net = Network({1: "Alice", 2: "Bob"})
        bob = Node(net, 2)
        self.assertEqual(bob.lua.globals().connectedName, "Bob")
        self.assertEqual(bob.lua.globals().connectedHost, 1)

    def test_probe_flood_is_bounded_and_duplicate_probes_are_not_echoed(self):
        net = Network({1: "Alice", 2: "Bob"})
        alice, bob = Node(net, 1), Node(net, 2)
        net.advance(1)
        alice.start()
        token = next(item[3]["token"] for item in net.queue if item[3].get("action") == "start")
        net.advance(.1)
        packet = {"Type": "FafConnectionTest1", "version": 1, "SenderID": 1,
                  "action": "probe", "token": token, "sequence": 42}
        before = net.serial
        for _ in range(100):
            bob.comm.DataReceived(bob.comm, bob.lua.table_from(packet))
        self.assertEqual(net.serial - before, 1)
        packet["sequence"] = 43
        bob.comm.DataReceived(bob.comm, bob.lua.table_from(packet))
        self.assertEqual(net.serial - before, 1)

    def test_deadlines_duplicates_and_missing_replies(self):
        lua = LuaRuntime()
        score = lua.execute((SOURCE / "connectionscore.lua").read_text())
        link = score.New()
        link.Send(link, 1, 10)
        link.Reply(link, 1, 10.5)
        link.Reply(link, 1, 10.5)
        link.Send(link, 2, 11)
        link.Reply(link, 2, 11.501)
        link.Send(link, 3, 12)  # Lost reply stays in the denominator.
        self.assertEqual((link.sent, link.onTime), (3, 1))

    def test_three_peers_share_worst_score_and_name(self):
        net = Network({1: "Alice", 2: "Bob", 3: "Carol"})
        nodes = [Node(net, i) for i in net.names]
        net.drop = lambda a, b, d: (a, b, d.get("action")) == (1, 3, "probe") and d["sequence"] % 10 == 0
        net.advance(1)
        nodes[0].start()
        net.advance(70)
        for node in nodes:
            self.assertIn("Alice: 90.0% -> Carol", node.text)
            self.assertIn("Bob: 100.0% -> Alice", node.text)
            self.assertIn("Test complete.", node.text)
        net.names.pop(3)
        net.advance(.1)
        self.assertIn("Results cleared", nodes[0].text)
        self.assertNotIn("90.0%", nodes[0].text)

    def test_unsupported_peer_and_non_host_cannot_start(self):
        net = Network({1: "Alice", 2: "Bob", 3: "Unmodified"})
        alice, bob = Node(net, 1), Node(net, 2)
        net.advance(1)
        bob.start()
        self.assertIn("Only the host", bob.text)
        alice.start()
        self.assertIn("Unmodified has not advertised", alice.text)
        self.assertNotIn("100.0%", alice.text)

    def test_local_pause_does_not_accuse_a_connection(self):
        net = Network({1: "Alice", 2: "Bob"})
        alice, bob = Node(net, 1), Node(net, 2)
        net.advance(1)
        alice.start()
        net.advance(2)
        # Simulate Alice's UI scheduler not running for half a second.
        alice.lua.execute("workerPaused=worker; worker=coroutine.create(function() end)")
        net.advance(.5)
        alice.lua.execute("worker=workerPaused")
        net.advance(70)
        for node in (alice, bob):
            self.assertIn("Inconclusive", node.text)
            self.assertNotIn("100.0%", node.text)

    def test_malformed_report_cannot_crash_score_display(self):
        lua = LuaRuntime(unpack_returned_tuples=True)
        score = lua.execute((SOURCE / "connectionscore.lua").read_text())
        roster = lua.table_from({1: "Alice", 2: "Bob"})
        for bad in (False, 42, "bad", lua.table_from({2: "bad"})):
            reports = lua.table_from({1: {"links": bad}}, recursive=True)
            value, _, _ = score.Worst(reports, 1, roster)
            self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
