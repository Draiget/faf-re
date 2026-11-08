-- data/fafengine/lua/ui/controls/worldview.lua
-- Minimal, non-invasive WorldView click & drag interception for transport cargo holograms.

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

local _drag = { startX = nil, startY = nil, active = false, isShift = false }

function WorldView:HandleEvent(event)
    local holo = GetHolograms()
    if holo then
        local clickFn = rawget(holo, 'HandleWorldClick')
        local dragFn = rawget(holo, 'HandleWorldDrag')

        if event.Type == 'ButtonPress' and not (event.Modifiers and event.Modifiers.Right) then
            _drag.startX = event.MouseX
            _drag.startY = event.MouseY
            _drag.isShift = (event.Modifiers and event.Modifiers.Shift == true) or false
            _drag.active = true

            if clickFn then
                local ok, handled = pcall(clickFn, self, event)
                if ok and handled then
                    _drag.active = false
                    return true
                end
            end
        elseif event.Type == 'ButtonRelease' and _drag.active then
            local sx, sy = _drag.startX, _drag.startY
            local ex, ey = event.MouseX or sx, event.MouseY or sy
            local shift = _drag.isShift
            _drag.active = false

            local dx = math.abs(ex - sx)
            local dy = math.abs(ey - sy)
            if dx > 10 or dy > 10 then
                if dragFn then
                    local ok, handled = pcall(dragFn, self, sx, sy, ex, ey, shift)
                    if ok and handled then
                        return true
                    end
                end
            end
        end
    end

    if oldWorldViewHandleEvent then
        return oldWorldViewHandleEvent(self, event)
    end
    return false
end
