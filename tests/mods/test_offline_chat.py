"""Chat routing tests: translations must only append locally after filtering."""
from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime

ROOT = Path(__file__).resolve().parents[2]


class ChatTests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute('''
            entries = {}; requests = {}; callbacks = {}; resets = 0
            MicrochipQueueTranslation = function() end
            GetFocusArmy = function() return 1 end
            GetSessionClients = function() return {{name='Me', ['local']=true}} end
            OnReceive = function(sender, message) AppendEntry(message) end
            table.copy = function(t) local n={} for k,v in pairs(t) do n[k]=v end return n end
            AppendEntry = function(e) table.insert(entries, e) end
            translator = {
              Reset = function() resets=resets+1 end,
              Translate = function(text, cb) table.insert(requests,text); table.insert(callbacks,cb) end
            }
            import = function() return translator end
        ''')
        source = ROOT/'mods/Microchip-Offline-Chat/hook/lua/ui/game/chat/ChatController.lua'
        self.lua.execute(source.read_text(encoding='utf-8-sig'))

    def test_only_local_append_and_preserves_channel(self):
        self.lua.execute("AppendEntry{ArmyID=2,Name='Ally:',Text='bonjour',Recipient='allies',Id='unique'}")
        self.lua.execute("callbacks[1]('[English / FR] hello')")
        g = self.lua.globals()
        self.assertEqual(len(g.entries), 2)
        self.assertEqual(g.entries[2].Recipient, 'allies')
        self.assertEqual(g.entries[2].Name, 'Ally:')
        self.assertIsNone(g.entries[2].Id)
        self.assertEqual(g.entries[1].Id, 'unique')
        self.assertEqual(len(g.requests), 1)  # no recursive translation

    def test_system_and_camera_not_translated(self):
        self.lua.execute("AppendEntry{ArmyID=0,Text='system'}; AppendEntry{ArmyID=2,Text='camera',Camera={}}")
        self.assertEqual(len(self.lua.globals().requests), 0)
        self.assertEqual(len(self.lua.globals().entries), 2)

    def test_own_message_not_translated_or_repeated(self):
        self.lua.execute("OnReceive('Me', {ArmyID=1,Name='Me:',Text='bonjour',Id='own'})")
        self.assertEqual(len(self.lua.globals().entries), 1)
        self.assertEqual(len(self.lua.globals().requests), 0)

    def test_remote_observer_with_own_army_fallback_still_translates(self):
        self.lua.execute("OnReceive('Other', {ArmyID=1,Name='Other:',Text='bonjour',Id='other'})")
        self.assertEqual(len(self.lua.globals().requests), 1)

    def test_own_private_echo_not_translated(self):
        self.lua.execute("AppendEntry{ArmyID=1,Name='To Ally:',Text='bonjour'}")
        self.assertEqual(len(self.lua.globals().requests), 0)


if __name__ == '__main__':
    unittest.main()
