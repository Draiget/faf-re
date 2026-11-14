from pathlib import Path
import re
import unittest

from lupa.lua51 import LuaRuntime

ROOT = Path(__file__).resolve().parents[2]
MOD = ROOT / 'mods/Microchip-Icon-Mod'


class IconScaleTests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute((MOD / 'modules/catalog.lua').read_text())
        self.lua.execute('''
            saved = {}; calls = 0; writes = 0; accepted = true
            function import(path)
                if string.find(path, 'catalog.lua', 1, true) then return {Icons=Icons} end
                return {
                    GetFromCurrentProfile=function() return saved end,
                    SetToCurrentProfile=function(key, value) saved=value; writes=writes+1 end
                }
            end
            function SetStrategicIconScales(value)
                calls=calls+1; payload=value; return accepted
            end
        ''')
        self.lua.execute((MOD / 'modules/scales.lua').read_text())

    def test_apply_updates_all_states_as_one_set_and_persists(self):
        self.lua.execute("draft=Load(); draft.icon_bomber3_directfire='200'; ok=Apply(draft,true)")
        self.assertTrue(self.lua.globals().ok)
        self.assertEqual(self.lua.eval('calls'), 1)
        self.assertEqual(self.lua.eval('writes'), 1)
        self.assertEqual(self.lua.eval('saved.icon_bomber3_directfire'), 200)
        self.assertEqual(self.lua.eval("payload['/mods/Microchip-Icon-Mod/custom-strategic-icons/icon_bomber3_directfire']"), 200)
        self.assertEqual(self.lua.eval('saved.icon_fighter1_intel'), 100)

    def test_invalid_edits_cannot_partially_apply_or_save(self):
        for value in ('', 'abc', '0', '401', '12.5', '-1', 'nan'):
            self.lua.globals().bad = value
            self.lua.execute('draft=Load(); draft.icon_fighter1_intel=bad; ok=Apply(draft,true)')
            self.assertFalse(self.lua.globals().ok, value)
        self.assertEqual(self.lua.eval('calls'), 0)
        self.assertEqual(self.lua.eval('writes'), 0)

    def test_engine_failure_or_missing_support_never_saves(self):
        self.lua.execute('accepted=false; ok=Apply(Load(),true)')
        self.assertFalse(self.lua.globals().ok)
        self.lua.execute('SetStrategicIconScales=nil; ok=Apply(Load(),true)')
        self.assertFalse(self.lua.globals().ok)
        self.assertEqual(self.lua.eval('writes'), 0)

    def test_game_cfunction_type_is_accepted(self):
        self.lua.execute('''
            local native=SetStrategicIconScales
            local originalType=type
            type=function(value)
                if value==native then return 'cfunction' end
                return originalType(value)
            end
            ok=Apply(Load(),false)
        ''')
        self.assertTrue(self.lua.globals().ok)

    def test_reset_clears_existing_engine_overrides(self):
        self.lua.execute('draft=Load(); draft.icon_fighter3_intel=400; Apply(draft,true); Apply({},true)')
        self.assertIsNone(self.lua.eval('next(payload)'))
        self.assertEqual(self.lua.eval('saved.icon_fighter3_intel'), 100)

    def test_startup_restore_does_not_write_preferences(self):
        self.lua.execute('saved={icon_fighter1_intel=125,icon_bomber3_directfire=200}; Apply(Load(),false)')
        self.assertEqual(self.lua.eval('writes'), 0)
        self.assertEqual(self.lua.eval("payload['/mods/Microchip-Icon-Mod/custom-strategic-icons/icon_fighter1_intel']"), 125)

    def test_catalog_covers_every_texture_set_and_all_four_states(self):
        keys = re.findall(r'key = "([^"]+)"', (MOD / 'modules/catalog.lua').read_text())
        icons = MOD / 'custom-strategic-icons'
        self.assertEqual(set(keys), {p.name[:-9] for p in icons.glob('*_rest.dds')})
        self.assertEqual(len(keys), len(set(keys)))
        for key in keys:
            for state in ('rest', 'over', 'selected', 'selectedover'):
                self.assertTrue((icons / f'{key}_{state}.dds').is_file(), (key, state))

    def open_panel(self):
        self.lua.execute('''
            local oldImport=import
            buttons={}; edits={}; objects={}
            local function control()
                local c={text='',HandleEvent=function() return false end}
                for _,key in ipairs({'Width','Height'}) do c[key]={Set=function() end} end
                function c:SetText(text) self.text=text; if self.OnTextChanged then self:OnTextChanged(text) end end
                function c:GetText() return self.text end
                function c:SetColor() end
                function c:SetSolidColor() end
                function c:SetTexture(path) self.texture=path end
                function c:DisableHitTest() end
                function c:Show() self.hidden=false end
                function c:Hide() self.hidden=true end
                table.insert(objects,c)
                return c
            end
            local ui={bodyFont='Arial',SetupEditStd=function() end}
            function ui.CreateText(parent,text) local c=control(); c:SetText(text); return c end
            function ui.CreateButtonWithDropshadow(parent,path,label)
                local c=control(); buttons[label]=c; return c
            end
            function ui.CreateVertScrollbarFor(target) scrollTarget=target; return control() end
            function import(path)
                if string.find(path,'catalog.lua',1,true) then return {Icons=Icons} end
                if string.find(path,'scales.lua',1,true) then return {Apply=Apply,Load=Load} end
                if string.find(path,'uiutil.lua',1,true) then return ui end
                if string.find(path,'layouthelpers.lua',1,true) then return {ScaleNumber=function(n) return n end,AtLeftTopIn=function() end} end
                if string.find(path,'group.lua',1,true) then return {Group=control} end
                if string.find(path,'bitmap.lua',1,true) then return {Bitmap=control} end
                if string.find(path,'edit.lua',1,true) then return {Edit=function() local c=control(); table.insert(edits,c); return c end} end
                if string.find(path,'popup.lua',1,true) then return {Popup=function()
                    local c=control(); c.OnClosed=function() end
                    function c:Close() self:OnClosed(); self.destroyed=true end
                    return c
                end} end
                return oldImport(path)
            end
            function GetFrame() return control() end
            function IsDestroyed(c) return not c or c.destroyed end
        ''')
        self.lua.execute((MOD / 'modules/panel.lua').read_text())
        self.lua.execute('panel=Open(GetFrame())')

    def test_search_edit_apply_uses_visible_icon_key(self):
        self.open_panel()
        self.lua.execute("edits[1]:SetText('Strategic Bomber'); edits[2]:SetText('175'); buttons.Apply.OnClick()")
        self.assertEqual(self.lua.eval('saved.icon_bomber3_directfire'), 175)

    def test_scroll_keeps_unapplied_edits(self):
        self.open_panel()
        self.lua.execute("edits[2]:SetText('150'); scrollTarget:ScrollSetTop(nil,30); scrollTarget:ScrollSetTop(nil,0)")
        self.assertEqual(self.lua.eval('edits[2]:GetText()'), '150')
        self.assertEqual(self.lua.eval('calls'), 0)

    def test_close_discards_pending_changes(self):
        self.open_panel()
        self.lua.execute("edits[2]:SetText('250'); buttons.Close.OnClick()")
        self.assertEqual(self.lua.eval('calls'), 0)
        self.assertEqual(self.lua.eval('writes'), 0)

    def test_reset_is_pending_until_apply(self):
        self.lua.execute('saved={icon_bomber3_directfire=200}')
        self.open_panel()
        self.lua.execute("buttons['Reset Defaults'].OnClick()")
        self.assertEqual(self.lua.eval('saved.icon_bomber3_directfire'), 200)
        self.lua.execute('buttons.Apply.OnClick()')
        self.assertEqual(self.lua.eval('saved.icon_bomber3_directfire'), 100)


if __name__ == '__main__':
    unittest.main()
