-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/maui/text.lua.
--
-- The interface scale without a restart (/fafengine/modules/lua/ui/uiscale.lua): a text's font size stays a computed
-- value of the size it was given, so a later scale change reaches it (FAF's SetFont stores the scaled size once).

do
    local ScaleNumber = import('/lua/maui/layouthelpers.lua').ScaleNumber
    local OldSetFont = Text.SetFont
    Text.SetFont = function(self, family, pointsize)
        OldSetFont(self, family, pointsize)
        if self._font and type(pointsize) == 'number' then
            self._lockFontChanges = true
            self._font._pointsize:SetFunction(function() return ScaleNumber(pointsize) end)
            self._lockFontChanges = false
        end
    end
end
