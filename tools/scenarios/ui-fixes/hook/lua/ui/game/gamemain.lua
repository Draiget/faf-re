-- UI half of the UI fix check (tools/scenarios/1p-uifix-main.yaml); drive.ps1 answers the lines
-- this logs:
--   "UITEST CURSOR <x> <y>"                 move the cursor to that client-area pixel
--   "UITEST SHOT <name>"                    save the game window as <name>.png
--   "UITEST RDRAG <x1> <y1> <x2> <y2> <name>"  right-drag between two client pixels, shot mid-drag
-- 1. Factory click: the cursor goes onto a factory with a tank on its pad; the rollover must be the
--    factory (ueb0101), not the tank being built (uel0201).
-- 2. Formation preview (issue #19): the 24 tanks are selected and a right-drag is made zoomed out;
--    the preview shows each tank's strategic icon at its slot.
local UiTestOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    UiTestOnFirstUpdate()

    ForkThread(function()
        local function FindUnits(category, blueprintId)
            UISelectionByCategory(category, false, false, false, false)
            local found = {}
            for _, unit in GetSelectedUnits() or {} do
                if unit:GetUnitId() == blueprintId then
                    table.insert(found, unit)
                end
            end
            SelectUnits(nil)
            return found
        end

        local factories, tanks = {}, {}
        for _ = 1, 90 do
            WaitSeconds(1)
            factories = FindUnits('FACTORY', 'ueb0101')
            tanks = FindUnits('LAND MOBILE', 'uel0201')
            if table.getn(factories) > 0 and table.getn(tanks) >= 24 then
                break
            end
        end
        LOG(string.format('UITEST factories %d, tanks %d', table.getn(factories), table.getn(tanks)))
        if table.getn(factories) == 0 or table.getn(tanks) < 24 then
            LOG('UITEST DONE (units missing)')
            return
        end

        local view = import('/lua/ui/game/worldview.lua').viewLeft
        local camera = GetCamera('WorldCamera')
        local settings = camera:SaveSettings()
        local function ClientPixel(position)
            local coords = view:Project(Vector(position[1], position[2], position[3]))
            return math.floor(view.Left() + coords.x), math.floor(view.Top() + coords.y)
        end

        -- 1. Factory click. Give the factory time to start its first tank.
        local factory = factories[1]
        local fpos = factory:GetPosition()
        camera:SnapTo(Vector(fpos[1], fpos[2], fpos[3]), { settings.Heading, settings.Pitch, 0 }, 45)
        WaitSeconds(5)
        local x, y = ClientPixel(fpos)
        LOG(string.format('UITEST t=%.1f factory world (%.1f, %.1f)', GetSystemTimeSeconds(), fpos[1], fpos[3]))
        LOG(string.format('UITEST CURSOR %d %d', x, y))
        -- The log reaches drive.ps1 with a delay, so wait for the rollover rather than a fixed time.
        local info
        for i = 1, 200 do
            WaitSeconds(0.1)
            info = GetRolloverInfo()
            if math.mod(i, 10) == 0 then
                local m = GetMouseWorldPos()
                LOG(string.format('UITEST t=%.1f mouse world (%.1f, %.1f) rollover %s', GetSystemTimeSeconds(),
                    m and m[1] or -1, m and m[3] or -1, info and tostring(info.blueprintId) or 'nothing'))
            end
            if info then
                break
            end
        end
        WaitSeconds(1)
        info = GetRolloverInfo()
        LOG(string.format('UITEST HOVER %s (factory is %s)', info and tostring(info.blueprintId) or 'nothing',
            tostring(factory:GetEntityId())))
        LOG('UITEST SHOT factory-hover')
        WaitSeconds(5)

        -- 2. Formation preview, zoomed out far enough for strategic icons.
        SelectUnits(tanks)
        local cx, cy, cz = 0, 0, 0
        for _, unit in tanks do
            local p = unit:GetPosition()
            cx, cy, cz = cx + p[1], cy + p[2], cz + p[3]
        end
        cx, cy, cz = cx / 24, cy / 24, cz / 24
        camera:SnapTo(Vector(cx, cy, cz), { settings.Heading, settings.Pitch, 0 }, 260)
        WaitSeconds(3)
        local x1, y1 = ClientPixel({ cx - 25, cy, cz - 20 })
        local x2, y2 = ClientPixel({ cx + 25, cy, cz - 20 })
        LOG(string.format('UITEST RDRAG %d %d %d %d formation-preview', x1, y1, x2, y2))
        WaitSeconds(25)
        LOG('UITEST DONE')
    end)
end
