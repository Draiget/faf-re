from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime

ROOT=Path(__file__).resolve().parents[2]
MOD=ROOT/'mods/Microchip-Evil-Stamp'


class StampTests(unittest.TestCase):
    def setUp(self):
        self.lua=LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute('math.huge=nil')
        self.lua.execute((MOD/'modules/drawing.lua').read_text(encoding='utf-8-sig'))

    def test_approved_geometry_within_normal_limits(self):
        self.lua.execute('''
            assert(table.getn(Paths)==3)
            local count=0
            for _,path in ipairs(Paths) do assert(table.getn(path)<=128); count=count+table.getn(path) end
            assert(count==50 and table.getn(Paths[1])==41)
        ''')

    def test_husky_geometry_and_unknown_design(self):
        self.lua.execute("""
            local p=Project(function(x,y) return {x,0,y} end,{500,400},2,{0,0,1000,800},{1000,800},'husky')
            assert(table.getn(p)==13)
            local count=0
            for _,stroke in ipairs(p) do count=count+table.getn(stroke.CoordinatesX) end
            assert(count<128)
            assert(Project(function(x,y) return {x,0,y} end,{500,400},2,{0,0,1000,800},nil,'unknown')==nil)
        """)

    def test_screen_to_ground_projection_preserves_shape(self):
        self.lua.execute('''
            local p=Project(function(x,y) return {x,13,y} end,{500,400},2,{0,0,1000,800},{1000,800})
            assert(table.getn(p)==3 and table.getn(p[1].CoordinatesX)==41)
            assert(p[1].CoordinatesX[1]==420 and p[1].CoordinatesZ[1]==320 and p[1].CoordinatesY[1]==13)
        ''')

    def test_rejects_partial_and_out_of_map_drawings(self):
        self.lua.execute('''
            assert(Project(function(x,y) return {x,0,y} end,{2,400},2,{0,0,1000,800},{1000,800})==nil)
            assert(Project(function() return {2000,0,2000} end,{500,400},2,{0,0,1000,800},{1000,800})==nil)
            assert(Project(function() return {1/0,0,10} end,{500,400},2,{0,0,1000,800},{1000,800})==nil)
            assert(Project(function() return {0/0,0,10} end,{500,400},2,{0,0,1000,800},{1000,800})==nil)
        ''')

    def test_rejects_modified_over_budget_paths(self):
        self.lua.execute('''
            for i=1,80 do table.insert(Paths[1],{0,0}) end
            assert(Project(function(x,y) return {x,0,y} end,{500,400},2,{0,0,1000,800})==nil)
        ''')

    def test_hotkey_overlay_does_not_modify_saved_mapping(self):
        self.lua.execute('''
            original={['Shift-Ctrl-L']='factory',A='attack'}
            function GetCurrentKeyMap() return original end
            function NormalizeKeyBinding(k) return k=='Shift-Ctrl-L' and 'Ctrl-Shift-L' or k end
            table.copy=function(t) local r={} for k,v in pairs(t) do r[k]=v end return r end
        ''')
        self.lua.execute((MOD/'hook/lua/keymap/keymapper.lua').read_text(encoding='utf-8-sig'))
        self.lua.execute("local m=GetCurrentKeyMap(); assert(m['Ctrl-Shift-L']=='microchip_evil_stamp' and m['Shift-Ctrl-L']==nil and m.A=='attack'); assert(original['Shift-Ctrl-L']=='factory')")

    def test_shortcut_registered_when_ui_opens(self):
        self.lua.execute("function CreateUI(replay) created=replay end; function IN_AddKeyMapTable(t) bindings=t end")
        self.lua.execute((MOD/'hook/lua/ui/game/gamemain.lua').read_text(encoding='utf-8-sig'))
        self.lua.execute("CreateUI(true); assert(created==true); assert(string.find(bindings['Ctrl-Shift-L'].action,'picker.lua',1,true))")

    def test_picker_waits_for_selection_and_cancel_sends_nothing(self):
        self.lua.execute("""
            published=0; prepared=0; buttons={}; captured=false
            function control()
                return {Width={Set=function() end},Height={Set=function() end},Depth={Set=function() end},
                    GetTopmostDepth=function() return 0 end,Destroy=function(self) self.dead=true end,
                    Disable=function() end}
            end
            function GetFrame() return control() end
            function GetMouseScreenPos() return {500,400} end
            function IsDestroyed(c) return c.dead end
            function AddInputCapture() captured=true end
            function RemoveInputCapture() captured=false end
            function import(path)
                if string.find(path,'stamp.lua',1,true) then return {
                    Prepare=function(id,mouse) prepared=prepared+1; assert(mouse[1]==500); return {id=id} end,
                    Publish=function(d) published=published+1; chosen=d.id end} end
                if string.find(path,'uiutil',1,true) then return {bodyFont='body',VK_ESCAPE=27,UIFile=function(p) return p end,
                    CreateWorldCover=control,CreateSCXMenuPanelBorder=control,CreateText=control,
                    CreateButtonStd=function(parent,path,label) local b=control(); buttons[label]=b; return b end} end
                if string.find(path,'bitmap',1,true) then return {Bitmap=control} end
                return setmetatable({}, {__index=function() return function() end end})
            end
        """)
        self.lua.execute((MOD/'modules/picker.lua').read_text(encoding='utf-8-sig'))
        self.lua.execute("""
            Toggle(); assert(prepared==2 and published==0 and captured)
            buttons['Drunk Husky'].OnClick(); assert(published==1 and chosen=='husky' and not captured)
            Toggle(); buttons.Cancel.OnClick(); assert(published==1 and not captured)
            Toggle(); Toggle(); assert(published==1 and not captured)
        """)

    def test_normal_painting_adapter_and_cooldown(self):
        self.lua.execute('''
            drawing={Project=Project}
            now=100; shared=0; destroyed=0; enabled=false
            view={Depth=function() return 1 end,IsHidden=function() return false end,HitTest=function() return true end,
                  Left=function() return 0 end,Top=function() return 0 end,Right=function() return 1000 end,Bottom=function() return 800 end,
                  }
            view.PaintingCanvas={IsEnabledByGameOptions=function() return enabled end,
                Adapter={SharePaintingBrushStroke=function(self,s) shared=shared+1; assert(table.getn(s.points.CoordinatesX)<=128) end}}
            function import(path)
                if string.find(path,'drawing') then return drawing end
                if string.find(path,'worldview') then return {GetWorldViews=function() return {view} end} end
                if string.find(path,'layouthelpers') then return {ScaleNumber=function(n) return n end} end
                if string.find(path,'BrushStroke') then return {CreateBrushStroke=function(p,c)
                    return {points=p,Destroy=function() destroyed=destroyed+1 end} end} end
                if string.find(path,'gamemain') then return {gameUIHidden=false} end
                if string.find(path,'commandmode') then return {InCommandMode=function() return false end} end
                error(path)
            end
            function UnProject(v,p) assert(v==view); return {p[1],0,p[2]} end
            function CurrentTime() return now end
            function GetMouseScreenPos() return {500,400} end
            function IsDestroyed() return false end
            function SessionGetScenarioInfo() return {size={1000,800}} end
            function GetFocusArmy() return 1 end
            function GetArmiesTable() return {armiesTable={{color='ffffffff'}}} end
            function LOG() end
        ''')
        self.lua.execute((MOD/'modules/stamp.lua').read_text(encoding='utf-8-sig'))
        self.lua.execute('''
            assert(Stamp()==false and shared==0)
            enabled=true; assert(Stamp()==true and shared==3 and destroyed==3)
            assert(Stamp()==false and shared==3)
            now=106; assert(Stamp()==true and shared==6)
            now=1; assert(Stamp()==true and shared==9)
        ''')


if __name__=='__main__': unittest.main()
