-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/uiutil.lua.
--
-- The rotate-skin key (UI_RotateSkin) calls RotateSkin, which calls SetCurrentSkin(name) without the override table
-- SetCurrentSkin reads (`overrideTable.faction_font_color`), so the key stopped with a Lua error. An empty table
-- is what "no overrides" means there.

do
    local OldSetCurrentSkin = SetCurrentSkin
    function SetCurrentSkin(skin, overrideTable)
        return OldSetCurrentSkin(skin, overrideTable or {})
    end
end
