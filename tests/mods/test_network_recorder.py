"""Passive recorder and engine-hook tests; no live game or network required."""
from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime
ROOT = Path(__file__).resolve().parents[2]

class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.core = self.lua.execute((ROOT/'data/fafengine/lua/diagnostics/networkrecorder.lua').read_text(encoding='utf-8-sig'))
        self.recorder = self.core.New()

    def test_records_raw_rate_buffers_and_frame_gap(self):
        clients = self.lua.table_from({1: {'name': 'Alice', 'local': True, 'connected': True, 'maxSP': -2,
            'quiet': 0, 'ping': 0, 'fafReNetwork': {'dispatched': 100, 'available': 0, 'actualRate': -2,
                'requestedRate': 0, 'bottleneck': 'ack', 'buffers': {1: 8, 2: -1}}},
            2: {'name': 'Bob', 'connected': True, 'quiet': 200, 'ping': 80}}, recursive=True)
        self.recorder.Capture(self.recorder, clients, 10, 100)
        lines = self.recorder.Capture(self.recorder, clients, 14, 120)
        self.assertIn('elapsed=4.000', lines[1])
        self.assertIn('ticks_per_second=5.000', lines[1])
        self.assertIn('maxsp=-2.000', lines[2])
        self.assertIn('bottleneck="ack"', lines[2])
        self.assertIn('2:-1.000', lines[2])
        self.assertEqual(clients[1]['name'], 'Alice')

    def test_bounds_log_and_sanitizes_names(self):
        clients = self.lua.table_from({i: {'name': 'name\n"|spoof', 'maxSP': float('nan')} for i in range(1, 100)}, recursive=True)
        lines = self.recorder.Capture(self.recorder, clients, 10, 100)
        self.assertEqual(len(lines), 33)
        self.assertNotIn('\n', lines[2])
        self.assertIn('maxsp=-', lines[2])

    def hook(self, enabled, replay=False, faf_timeline=True):
        g = self.lua.globals()
        g.core = self.core
        g.enabled = enabled
        g.fafTimeline = faf_timeline
        self.lua.execute('''
            created = 0; logs = {}; killed = 0; timelines = 0
            function CreateUI(replay) created=created+1; receivedReplay=replay; return 42 end
            function GetPreference(key, default) return enabled end
            function SessionIsMultiplayer() return true end
            function DiskGetFileInfo() return fafTimeline end
            function ForkThread(fn) thread=coroutine.create(fn); return thread end
            function KillThread() killed=killed+1 end
            function import(path)
                if string.find(path, 'replay_timeline') then return {Create=function() timelines=timelines+1 end} end
                return core
            end
            function LOG(text) table.insert(logs,text) end
            function WARN(text) error(text) end
            function GetSystemTimeSeconds() return 10 end
            function GameTick() return 100 end
            function GetSessionClients() return {{name='Alice', maxSP=10}} end
            function WaitSeconds(seconds) waited=seconds; coroutine.yield() end
        ''')
        self.lua.execute((ROOT/'data/fafengine/lua/ui/game/gamemain.lua').read_text(encoding='utf-8-sig'))
        self.assertEqual(g.CreateUI(replay), 42)
        self.assertEqual(g.created, 1)
        return g

    def test_opt_in_and_replay_guards(self):
        self.assertIsNone(self.hook(False).thread)
        self.setUp()
        self.assertIsNone(self.hook(True, replay=True).thread)

    def test_replay_timeline_coexists_without_duplicate_creation(self):
        for supplied_by_faf in (False, True):
            self.setUp()
            g = self.hook(True, replay=True, faf_timeline=supplied_by_faf)
            self.assertEqual(g.timelines, 0 if supplied_by_faf else 1)
            self.assertIsNone(g.thread)

    def test_opt_in_sampler_runs_at_bounded_interval_and_stops_at_session_end(self):
        g = self.hook(True)
        self.lua.execute('assert(coroutine.resume(thread))')
        self.assertEqual(g.waited, 2)
        self.assertEqual(len(g.logs), 3)  # START, SAMPLE, PEER.
        self.lua.execute('function GetSessionClients() return nil end; assert(coroutine.resume(thread))')
        self.assertEqual(g.logs[4], 'MicrochipNetDiag STOP')

    def test_waits_for_session_start_instead_of_stopping_before_first_sample(self):
        g = self.hook(True)
        self.lua.execute('saved=GetSessionClients; function GetSessionClients() return nil end; assert(coroutine.resume(thread))')
        self.assertEqual(len(g.logs), 1)
        self.lua.execute('GetSessionClients=saved; assert(coroutine.resume(thread))')
        self.assertEqual(len(g.logs), 3)

if __name__ == '__main__': unittest.main()
