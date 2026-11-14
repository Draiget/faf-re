from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime
ROOT = Path(__file__).resolve().parents[2]
MOD = ROOT / 'mods/Microchip-Threat-Alerts'
class ThreatTests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.core = self.lua.execute((MOD/'modules/detection.lua').read_text(encoding='utf-8-sig'))
        self.assertIsNotNone(self.lua.globals().Threat)  # FAF imports expose module globals, not returned tables
        self.detector = self.core.New()
    def item(self, id, cats, position=(10,0,20)):
        return {'id':id, 'blueprint':{'Categories':list(cats), 'General':{'UnitName':'Example'}}, 'position':list(position)}
    def update(self, items, now):
        return self.detector.Update(self.detector, self.lua.table_from(items, recursive=True), now)
    def test_major_threat_classes_and_priority(self):
        cases=[(['NUKE','STRATEGIC','STRUCTURE','TECH3'], 'Strategic nuke'),
            (['EXPERIMENTAL','MOBILE'], 'Experimental'),
            (['ARTILLERY','TECH3','STRUCTURE'], 'T3 artillery'),
            (['ANTIMISSILE','TECH3','STRUCTURE'], 'Strategic missile defence')]
        for cats,name in cases:
            bp=self.lua.table_from({'Categories':cats},recursive=True)
            self.assertEqual(self.core.Threat(bp)[0],name)
        threats=[self.item(1,['EXPERIMENTAL']),self.item(2,['NUKE','STRATEGIC'])]
        self.assertEqual(self.update(threats,0)['id'],2)
    def test_normal_units_and_tactical_defence_do_not_alert(self):
        for cats in (['LAND','TECH1'],['COMMAND'],['ANTIMISSILE','TECH2','STRUCTURE'],['ARTILLERY','TECH3','MOBILE']):
            self.assertIsNone(self.update([self.item(1,cats)],0))
    def test_once_per_unit_and_global_cooldown(self):
        a=self.item(1,['EXPERIMENTAL']);b=self.item(2,['EXPERIMENTAL'])
        self.assertEqual(self.update([a,b],0)['id'],1)
        self.assertIsNone(self.update([a,b],7))
        self.assertEqual(self.update([a,b],8)['id'],2)
        self.assertIsNone(self.update([a,b],30))
    def test_lost_vision_does_not_leave_pending_alert_or_position_tracking(self):
        a=self.item(1,['EXPERIMENTAL']);b=self.item(2,['EXPERIMENTAL'])
        self.update([a,b],0)
        self.assertIsNone(self.update([],9))
        self.assertIsNone(self.update([a],10))
        self.assertEqual(self.update([b],11)['id'],2)
    def test_invalid_positions_and_clock_reset(self):
        for bad in (float('nan'),float('inf'),10000000):
            self.assertIsNone(self.update([self.item(1,['EXPERIMENTAL'],(bad,0,0))],0))
        self.assertIsNotNone(self.update([self.item(1,['EXPERIMENTAL'])],10))
        self.assertIsNotNone(self.update([self.item(1,['EXPERIMENTAL'])],0))
    def test_no_simulation_or_network_ping_calls(self):
        hook=(MOD/'hook/lua/ui/game/gamemain.lua').read_text(encoding='utf-8-sig')
        self.assertIn('Ping.DisplayPing({ping})',hook)
        for call in ('SimCallback(', 'SessionSendChatMessage(', '.DoPing('): self.assertNotIn(call,hook)
        self.lua.execute('function CreateUI() end; function GetFocusArmy() return -1 end')
        self.lua.execute(hook)
        self.lua.globals().CreateUI(False) # observers exit before starting any detector
if __name__=='__main__': unittest.main()
