"""F11 diagnostics tests. Run with the existing Python+lupa test runtime."""
from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime

ROOT = Path(__file__).resolve().parents[2]
MOD = ROOT / 'mods/Microchip-F11-Lag-Connectivity-Screen'

class F11Tests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.core = self.lua.execute((MOD / 'modules/analysis.lua').read_text(encoding='utf-8-sig'))
        self.tracker = self.core.New()

    def clients(self, buffers=None, bridge=True):
        rows = {}
        for i, name in enumerate(('Alice', 'Bob', 'Carol'), 1):
            row = {'uid': str(i), 'name': name, 'connected': True, 'quiet': 0, 'ping': 30, 'local': i == 1}
            if bridge:
                row['fafReNetwork'] = {'version': 1, 'dispatched': 100, 'available': 8,
                    'buffers': {j: 8 for j in range(1, 4)}}
            rows[i] = row
        if buffers is not None:
            rows[1]['fafReNetwork']['buffers'] = buffers
        return self.lua.table_from(rows, recursive=True)

    def update(self, clients, now):
        return self.tracker.Update(self.tracker, clients, now)

    def test_persistent_direction_and_recovery(self):
        c = self.clients({1: 8, 2: 0, 3: 9})
        self.assertIsNone(self.update(c, 10)[0][1])
        labels, full = self.update(c, 11.6)
        self.assertTrue(full)
        self.assertIn('waits for Bob', labels[1])  # Alice receives slowly from Bob.
        self.assertIsNone(labels[2])
        self.assertIsNone(self.update(self.clients(), 12)[0][1])
        self.assertIsNone(self.update(c, 12.1)[0][1])

    def test_uniform_cpu_or_pause_does_not_blame_a_pair(self):
        c = self.clients({1: 0, 2: 0, 3: 0})
        self.update(c, 0)
        self.assertIsNone(self.update(c, 10)[0][1])

    def test_worst_incoming_source_is_named_when_multiple_are_delayed(self):
        c = self.clients({1: 8, 2: 0, 3: -4, 4: 10})
        c[4] = self.lua.table_from({'uid': '4', 'name': 'Dave', 'connected': True, 'quiet': 0, 'ping': 30})
        self.update(c, 0)
        self.assertIn('waits for Carol +1', self.update(c, 2)[0][1])

    def test_old_engine_and_local_ping_warning_are_explicit(self):
        c = self.clients(bridge=False)
        c[2]['ping'] = 500
        labels, full = self.update(c, 0)
        self.assertFalse(full)
        self.assertIn('local links only', labels[1])
        self.assertIn('high ping to you', labels[2])
        self.assertNotIn('waits', labels[2])

    def test_disconnected_and_stale_rows_do_not_make_remote_claims(self):
        c = self.clients({1: 8, 2: 0, 3: 9})
        c[2]['quiet'] = 4000
        self.update(c, 0)
        labels, _ = self.update(c, 10)
        self.assertIsNone(labels[1])
        self.assertIn('no packets to you', labels[2])

    def test_roster_change_and_clock_reset_restart_persistence(self):
        c = self.clients({1: 8, 2: 0, 3: 9})
        self.update(c, 0)
        c[3]['uid'] = 'new-player'
        self.assertIsNone(self.update(c, 2)[0][1])
        self.assertIn('waits for Bob', self.update(c, 4)[0][1])
        self.assertIsNone(self.update(c, 1)[0][1])

    def test_ranking_uses_measured_waits_not_ping(self):
        c = self.clients(bridge=False)
        c[2]['ping'], c[3]['ping'] = 20, 350
        for i, percent, longest in ((2, 18, 420), (3, 6, 180)):
            c[i]['fafReNetwork'] = self.lua.table_from({'waitVersion': 1, 'waitObservedSeconds': 30,
                'waitPercent': percent, 'longestWaitMs': longest})
        ranked = self.core.Ranked(c)
        self.assertEqual([ranked[i]['id'] for i in (1, 2)], [2, 3])
        c[3]['fafReNetwork']['waitPercent'] = 18
        c[3]['fafReNetwork']['longestWaitMs'] = 600
        self.assertEqual(self.core.Ranked(c)[1]['id'], 3)
        c[3]['connected'] = False
        self.assertEqual(self.core.Ranked(c)[1]['id'], 2)

    def test_unavailable_waits_are_not_displayed_as_zero(self):
        c = self.clients(bridge=False)
        self.assertFalse(self.core.Ranked(c)[1]['measured'])
        c[3]['fafReNetwork'] = self.lua.table_from({'waitVersion': 1, 'waitObservedSeconds': 30,
            'waitPercent': 0, 'longestWaitMs': 0})
        ranked = self.core.Ranked(c)
        self.assertEqual(ranked[1]['id'], 3)
        self.assertTrue(ranked[1]['measured'])
        c[3]['fafReNetwork']['waitPercent'] = float('nan')
        self.assertFalse(self.core.Ranked(c)[2]['measured'])

    def test_table_keeps_snapshot_untouched_and_closes_cleanly(self):
        c = self.clients(bridge=False)
        c[2]['fafReNetwork'] = self.lua.table_from({'waitVersion': 1, 'waitObservedSeconds': 30,
            'waitPercent': 2, 'longestWaitMs': 100, 'gameWaitSeconds': 120, 'gameWaitPercent': 25})
        g = self.lua.globals(); g.snapshot = c; g.core = self.core
        self.lua.execute("""
            texts = {}; buttons = {}
            function bound(value)
                return setmetatable({value=value or 0, Set=function(self,v) self.value=v end},
                    {__call=function(self) return self.value end})
            end
            function control()
                local c={Width=bound(1600), Height=bound(860), Depth=bound(0)}
                c.SetText=function(self,t) self.text=t end
                c.SetColor=function() end; c.Show=function() end; c.Hide=function() end
                c.Destroy=function() destroyed=true end; c.GetTopmostDepth=function() return 20 end
                return c
            end
            ui={bodyFont='body', UIFile=function(p) return p end, GetNetworkBool=function() return true,true end,
                CreateWorldCover=control, CreateDialogBrackets=control,
                CreateSCXMenuPanelBorder=function() return {tm=control(),bm=control()} end}
            ui.CreateText=function(parent,text) local c=control(); c.text=text; table.insert(texts,c); return c end
            ui.CreateButtonStd=function() local c=control(); table.insert(buttons,c); return c end
            function import(path)
                if string.find(path,'analysis.lua',1,true) then return core end
                if string.find(path,'uiutil.lua',1,true) then return ui end
                if string.find(path,'layouthelpers.lua',1,true) then return setmetatable({}, {__index=function() return function() end end}) end
                if string.find(path,'bitmap.lua',1,true) then return {Bitmap=control} end
                return {FastInterval=function() fast=true end, ResetInterval=function() reset=true end}
            end
            function GetSessionClients() return snapshot end
            function GetSystemTimeSeconds() return 10 end
            function SessionIsMultiplayer() return true end
            function GetFrame() return control() end
            function ConExecute() end; function AddInputCapture() end; function RemoveInputCapture() end
            function ForkThread(fn) return coroutine.create(fn) end; function KillThread() killed=true end
        """)
        self.lua.execute((MOD / 'hook/lua/ui/game/connectivity.lua').read_text(encoding='utf-8-sig'))
        g.CreateUI(); g.PingUpdate()
        self.assertEqual(c[1]['name'], 'Alice')
        text = [v['text'] for _, v in g.texts.items()]
        self.assertIn('Wait 30s', text)
        self.assertIn('Wait game', text)
        self.assertIn('Total wait', text)
        self.assertIn('Avg wait', text)
        self.assertIn('30.0s', text)
        self.assertIn('Ping', text)
        self.assertIn('Wait timing unavailable: requires the updated faf-re engine.', text)
        g.CloseWindow()
        self.assertTrue(g.reset and g.killed and g.destroyed)

    def test_total_wait_uses_whole_game_not_rolling_window(self):
        c = self.clients(bridge=False)
        c[2]['fafReNetwork'] = self.lua.table_from({'gameWaitSeconds': 600, 'gameWaitPercent': 12.5})
        row = next(row for _, row in self.core.Ranked(c).items() if row['id'] == 2)
        self.assertEqual(row['totalWaitSeconds'], 75)
        self.tracker = self.core.New()  # opening/closing the UI cannot reset the engine counter
        row = next(row for _, row in self.core.Ranked(c).items() if row['id'] == 2)
        self.assertEqual(row['totalWaitSeconds'], 75)
        c[2]['fafReNetwork']['gameWaitPercent'] = 0
        row = next(row for _, row in self.core.Ranked(c).items() if row['id'] == 2)
        self.assertEqual(row['totalWaitSeconds'], 0)

    def test_average_wait_engine_metrics_and_unavailable(self):
        c = self.clients(bridge=False)
        data = self.lua.table_from({'gameWaitSeconds': 600, 'gameWaitPercent': 12.5,
                                    'gameWaitEpisodes': 150, 'gameAverageWaitMs': 500})
        c[2]['fafReNetwork'] = data
        def average():
            return next(row for _, row in self.core.Ranked(c).items() if row['id'] == 2)['averageWaitMs']
        self.assertEqual(average(), 500)
        for invalid in (None, -1, float('nan'), float('inf')):
            data['gameAverageWaitMs'] = invalid
            self.assertIsNone(average())
        data['gameAverageWaitMs'] = 0
        data['gameWaitEpisodes'] = 0
        self.assertEqual(average(), 0)
        data['gameWaitEpisodes'] = None
        self.assertIsNone(average())

    def test_total_wait_duration_formatting(self):
        fmt = self.core.FormatWaitDuration
        self.assertEqual(fmt(0), '0.0s')
        self.assertEqual(fmt(12.34), '12.3s')
        self.assertEqual(fmt(59.99), '1:00.0')
        self.assertEqual(fmt(75), '1:15.0')
        self.assertEqual(fmt(3723), '1:02:03')
        for invalid in (None, -1, float('nan'), float('inf')):
            self.assertEqual(fmt(invalid), '--')

if __name__ == '__main__': unittest.main()
