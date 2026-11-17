-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/maui/layouthelpers.lua.
--
-- The interface scale without a restart (/fafengine/modules/lua/ui/uiscale.lua): the scale starts from the display's
-- when the player lets it follow the display, and SetWidth / SetHeight keep a number as a computed size, so a later
-- scale change reaches it (FAF's versions store the scaled value once).

do
    local UiScale = import('/fafengine/modules/lua/ui/uiscale.lua')
    SetPixelScaleFactor(UiScale.StartupScale())

    local MathFloor = math.floor

    function SetWidth(control, width)
        if width then
            if type(width) == 'number' then
                control.Width:SetFunction(function() return MathFloor(width * GetPixelScaleFactor()) end)
            else
                control.Width:Set(width)
            end
        end
    end

    function SetHeight(control, height)
        if height then
            if type(height) == 'number' then
                control.Height:SetFunction(function() return MathFloor(height * GetPixelScaleFactor()) end)
            else
                control.Height:Set(height)
            end
        end
    end

    -- The fluent Layouter's Width(n) / Height(n) likewise (FAF's Lua from 2025 on; older Lua has no Layouter).
    local LayouterClass = rawget(getfenv(1), 'Layouter')
    if type(LayouterClass) == 'table' and rawget(LayouterClass, 'Width') and rawget(LayouterClass, 'Height') then
        LayouterClass.Width = function(self, width)
            local controlWidth = self.layoutControl.Width
            if iscallable(width) then
                controlWidth:SetFunction(width)
            else
                controlWidth:SetFunction(function() return ScaleNumber(width) end)
            end
            return self
        end
        LayouterClass.Height = function(self, height)
            local controlHeight = self.layoutControl.Height
            if iscallable(height) then
                controlHeight:SetFunction(height)
            else
                controlHeight:SetFunction(function() return ScaleNumber(height) end)
            end
            return self
        end
    end
end
