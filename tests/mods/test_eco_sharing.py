from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime

ROOT = Path(__file__).resolve().parents[2]
MOD = ROOT/'mods/Microchip-Eco-Sharing'


class AllocationTests(unittest.TestCase):
    def setUp(self):
        self.lua=LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute((MOD/'modules/allocation.lua').read_text(encoding='utf-8-sig'))
        self.lua.execute('''
            s=Defaults(); s.enabled=true
            s.targets={High={MASS=true,ENERGY=true},Low={MASS=true,ENERGY=true}}
            own={stored={MASS=1000,ENERGY=1000},maxStorage={MASS=1000,ENERGY=1000}}
            allies={{id=2,name='Low',rating=900},{id=3,name='High',rating=1800}}
            scores={
                [2]={tick=100,data={resources={storage={storedMass=0,maxMass=1000,storedEnergy=0,maxEnergy=1000}}}},
                [3]={tick=100,data={resources={storage={storedMass=0,maxMass=1000,storedEnergy=0,maxEnergy=1000}}}}
            }
            last={}; tick=100
            function run() return Plan(s,own,allies,scores,tick,last) end
        ''')

    def test_equal_and_sequential_fractions_preserve_reserves(self):
        self.lua.execute('''
            local plan=run(); assert(table.getn(plan)==2)
            local mass,energy=1000,1000
            for _,gift in ipairs(plan) do
                assert(gift.MassAmount==199 and gift.EnergyAmount==124)
                mass=mass*(1-gift.Mass); energy=energy*(1-gift.Energy)
            end
            assert(math.abs(mass-602)<.001 and math.abs(energy-752)<.001)
        ''')

    def test_rank_higher_rating_first(self):
        self.lua.execute("s.mode='Rank'; local p=run(); assert(table.getn(p)==1 and p[1].name=='High' and p[1].MassAmount==399)")

    def test_manual_override_and_reset(self):
        self.lua.execute("s.mode='Rank'; s.order={'Low','High'}; assert(run()[1].name=='Low'); s.order={}; assert(run()[1].name=='High')")

    def test_equal_redistributes_limited_capacity(self):
        self.lua.execute('''
            scores[2].data.resources.storage.maxMass=50
            local p=run(); assert(p[1].name=='High' and p[1].MassAmount==349 and p[2].MassAmount==50)
        ''')

    def test_separate_recipient_ticks(self):
        self.lua.execute('''
            s.targets.High.MASS=false; s.targets.Low.ENERGY=false
            local p=run(); assert(p[1].Mass==0 and p[1].EnergyAmount==249)
            assert(p[2].Energy==0 and p[2].MassAmount==399)
        ''')

    def test_only_empty_fresh_selected_storage(self):
        self.lua.execute('''
            scores[2].data.resources.storage.storedMass=20
            scores[2].data.resources.storage.storedEnergy=20
            scores[3].tick=60; assert(table.getn(run())==0)
            scores[3].tick=100; scores[3].data.resources=nil; assert(table.getn(run())==0)
        ''')

    def test_disabled_and_full_reserves(self):
        self.lua.execute('''
            s.enabled=false; assert(table.getn(run())==0)
            s.enabled=true; s.massReserve=100; s.energyReserve=100; assert(table.getn(run())==0)
        ''')

    def test_cooldown_and_unrated_last(self):
        self.lua.execute('''
            s.mode='Rank'; last[3]={MASS=90,ENERGY=90}; assert(run()[1].name=='Low')
            last={}; allies[2].rating=nil; assert(run()[1].name=='Low')
        ''')

    def test_game_lua_without_math_huge_can_allocate_and_sort_unrated_allies(self):
        self.lua.execute('''
            math.huge=nil; allies[1].rating=nil
            local p=run(); assert(table.getn(p)==2 and p[1].name=='High')
        ''')

    def test_nonfinite_storage_is_never_allocated(self):
        self.lua.execute('''
            own.stored.MASS=math.huge; own.stored.ENERGY=0/0
            assert(table.getn(run())==0)
        ''')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        lua=self.lua=LuaRuntime(unpack_returned_tuples=True)
        lua.execute((MOD/'modules/allocation.lua').read_text(encoding='utf-8-sig'))
        lua.execute('''
            allocate={Defaults=Defaults,Plan=Plan}
            allocate.Ordered=Ordered
            saved=Defaults(); saved.enabled=true; saved.mode='Rank'; saved.targets={Ally={MASS=true,ENERGY=true},Enemy={MASS=true,ENERGY=true}}
            sent={}; chats={}; replay=false; observer=false; tick=100; now=10
            function import(path) if string.find(path,'allocation') then return allocate end
                if string.find(path,'ChatController') then return {FindClients=function() return {1,2} end} end
                return {GetFromCurrentProfile=function() return saved end,SetToCurrentProfile=function(key,v) saved=v end} end
            function AddOnSyncHashedCallback(cb,cat,id) receive=cb; assert(cat=='Score') end
            function RemoveOnSyncHashedCallback() receive=nil end
            function GameTick() return tick end
            function GetSystemTimeSeconds() return now end
            function SessionSendChatMessage(clients,message) table.insert(chats,{clients=clients,message=message}) end
            function WARN(message) warning=message end
            function GetFocusArmy() return 1 end
            function IsObserver() return observer end
            function SessionIsReplay() return replay end
            function IsAlly(a,b) return b==2 end
            function SessionGetScenarioInfo() return {Options={Ratings={Ally=2000}}} end
            function GetArmiesTable() return {armiesTable={[1]={nickname='Me'},[2]={nickname='Ally'},[3]={nickname='Enemy'}}} end
            function GetEconomyTotals() return {stored={MASS=1000,ENERGY=1000},maxStorage={MASS=1000,ENERGY=1000}} end
            function SimCallback(data) table.insert(sent,data) end
        ''')
        lua.execute((MOD/'modules/sharing.lua').read_text(encoding='utf-8-sig'))
        lua.execute('''
            data={[2]={resources={storage={storedMass=0,maxMass=1000,storedEnergy=0,maxEnergy=1000}}}}
            Initialize()
        ''')

    def test_enabled_without_selected_resources_is_explained(self):
        self.lua.execute('saved.targets.Ally={}; receive(data)')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 0)
        self.assertIn('Choose Energy or Mass', self.lua.eval('Status()'))
        self.assertEqual(self.lua.eval('table.getn(chats)'), 0)

    def test_one_allies_chat_message_reports_round_amounts(self):
        self.lua.execute('receive(data)')
        self.assertEqual(self.lua.eval('table.getn(chats)'), 1)
        self.assertEqual(self.lua.eval('chats[1].message.to'), 'allies')
        self.assertIn('399 mass and 249 energy to Ally', self.lua.eval('chats[1].message.text'))

    def test_rounds_require_three_wall_seconds_and_thirty_game_ticks(self):
        self.lua.execute('receive(data); tick=130; now=12.99; receive(data)')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 1)
        self.lua.execute('tick=130; now=13; receive(data)')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 2)
        self.assertEqual(self.lua.eval('table.getn(chats)'), 2)
        self.lua.execute('tick=159; now=16; receive(data)')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 2)
        self.lua.execute('tick=160; now=16; receive(data)')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 3)

    def test_switching_recipients_cannot_bypass_round_cooldown(self):
        self.lua.execute('''
            saved.targets.Ally={MASS=true}; receive(data)
            function IsAlly(a,b) return b==2 or b==4 end
            function GetArmiesTable() return {armiesTable={
                [1]={nickname='Me'},[2]={nickname='Ally'},[4]={nickname='Other'}}} end
            saved.targets.Ally={}; saved.targets.Other={ENERGY=true}
            data[4]={resources={storage={storedMass=0,maxMass=1000,storedEnergy=0,maxEnergy=1000}}}
            tick=110; now=11
            receive(data)
        ''')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 1)

    def test_paused_game_cannot_send_again_when_wall_time_passes(self):
        self.lua.execute('receive(data); now=20; receive(data)')
        self.assertEqual(self.lua.eval('table.getn(sent)'), 1)

    def test_chat_failure_does_not_stop_resource_transfers(self):
        self.lua.execute("SessionSendChatMessage=function() error('chat unavailable') end; receive(data)")
        self.assertEqual(self.lua.eval('table.getn(sent)'), 1)
        self.assertIn('chat unavailable', self.lua.eval('warning'))

    def test_real_faf_sim_callback_moves_resources_and_preserves_reserves(self):
        import zipfile
        # Exercise the installed callback itself, not a reimplementation of its fractions.
        archive = Path(r'C:\ProgramData\FAForever\gamedata\lua.nx2')
        if not archive.is_file():
            self.skipTest('Installed FAF game data not available')
        with zipfile.ZipFile(archive) as z:
            source = z.read('lua/SimUtils.lua').decode('utf-8-sig')
        callback = source[source.index('function GiveResourcesToPlayer(data)'):]
        callback = callback[:callback.index('\nend') + 4]
        self.lua.execute('''
            function OkayToMessWithArmy(army) return army==1 end
            function brain(name,mass,energy)
                local b={Nickname=name,stored={MASS=mass,ENERGY=energy}}
                function b:IsDefeated() return false end
                function b:GetEconomyStored(resource) return self.stored[resource] end
                function b:TakeResource(resource,n)
                    local taken=math.min(n,self.stored[resource]); self.stored[resource]=self.stored[resource]-taken
                    return taken
                end
                function b:GiveResource(resource,n) self.stored[resource]=math.min(1000,self.stored[resource]+n) end
                function b:GetArmyStat() return {Value=1000} end
                function b:SendChatToAllies() end
                return b
            end
            ArmyBrains={[1]=brain('Me',1000,1000),[2]=brain('Ally',0,0)}
        ''')
        self.lua.execute(callback)
        self.lua.execute('''
            function SimCallback(packet) GiveResourcesToPlayer(packet.Args) end
            receive(data)
        ''')
        self.assertAlmostEqual(self.lua.eval('ArmyBrains[1].stored.MASS'), 601)
        self.assertAlmostEqual(self.lua.eval('ArmyBrains[1].stored.ENERGY'), 751)
        self.assertAlmostEqual(self.lua.eval('ArmyBrains[2].stored.MASS'), 399)
        self.assertAlmostEqual(self.lua.eval('ArmyBrains[2].stored.ENERGY'), 249)

    def test_sync_registration_authority_and_dispatch(self):
        lua=self.lua
        lua.execute('''
            Initialize()
            local data={[2]={resources={storage={storedMass=0,maxMass=1000,storedEnergy=0,maxEnergy=1000}}},
                        [3]={resources={storage={storedMass=0,maxMass=1000,storedEnergy=0,maxEnergy=1000}}}}
            observer=true; receive(data); assert(table.getn(sent)==0)
            observer=false; replay=true; receive(data); assert(table.getn(sent)==0)
            replay=false; receive(data); assert(table.getn(sent)==1)
            assert(sent[1].Func=='GiveResourcesToPlayer' and sent[1].Args.From==1 and sent[1].Args.To==2)
            receive(data); assert(table.getn(sent)==1)
            Stop(); assert(receive==nil)
        ''')


if __name__=='__main__': unittest.main()
