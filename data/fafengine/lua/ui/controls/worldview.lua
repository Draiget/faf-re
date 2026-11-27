-- data/fafengine/lua/ui/controls/worldview.lua
-- Minimal, non-invasive WorldView click interception for transport cargo holograms. A band box over
-- holograms is handled by the engine's selection dragger, against the dragging view's own camera.

local oldWorldViewHandleEvent = WorldView.HandleEvent

local Holograms = nil
local function GetHolograms()
    if not Holograms then
        local ok, mod = pcall(import, '/fafengine/modules/lua/ui/game/transport_holograms.lua')
        if ok and type(mod) == 'table' then
            Holograms = mod
        end
    end
    return Holograms
end

function WorldView:HandleEvent(event)
    -- Left button only: a middle-button press near a hologram must still reach the camera.
    if event.Type == 'ButtonPress' and event.Modifiers and event.Modifiers.Left then
        local holo = GetHolograms()
        local clickFn = holo and rawget(holo, 'HandleWorldClick')
        if clickFn then
            local ok, handled = pcall(clickFn, self, event)
            if ok and handled then
                return true
            end
        end
    end

    if oldWorldViewHandleEvent then
        return oldWorldViewHandleEvent(self, event)
    end
    return false
end
