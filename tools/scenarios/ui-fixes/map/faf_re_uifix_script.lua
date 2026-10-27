-- faf_re_uifix: sim half of the UI fix check (tools/scenarios/1p-uifix-main.yaml).
-- Spawns, on open land away from the start position:
--   a UEF T1 land factory that keeps building tanks, so a unit is always on its pad, and
--   a block of 24 UEF T1 tanks for the formation preview.

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local Factory = 'ueb0101'
local Tank = 'uel0201'

local function IsLand(x, z)
    if x < 64 or z < 64 or x > 960 or z > 960 then
        return false
    end
    return GetTerrainHeight(x, z) >= GetSurfaceHeight(x, z)
end

local function IsOpenLand(x, z, radius)
    if not IsLand(x, z) then
        return false
    end
    for i = 0, 7 do
        local a = i * math.pi / 4
        if not IsLand(x + math.cos(a) * radius, z + math.sin(a) * radius) then
            return false
        end
    end
    return true
end

local function Distance(ax, az, bx, bz)
    return math.sqrt((ax - bx) * (ax - bx) + (az - bz) * (az - bz))
end

local function FindSpot(cx, cz, sx, sz, minFromStart, ox, oz, minFromOther)
    for r = 40, 400, 8 do
        for i = 0, 31 do
            local a = i * math.pi / 16
            local x, z = cx + math.cos(a) * r, cz + math.sin(a) * r
            if IsOpenLand(x, z, 24) and Distance(x, z, sx, sz) >= minFromStart and
                (ox == nil or Distance(x, z, ox, oz) >= minFromOther) then
                return x, z
            end
        end
    end
    return nil
end

function OnPopulate(scenario)
    ScenarioUtils.InitializeArmies()
end

function OnStart(self)
    ForkThread(function()
        local start = ScenarioUtils.GetMarker('ARMY_1').position
        local sx, sz = start[1], start[3]
        local fx, fz = FindSpot(sx, sz, sx, sz, 45)
        if fx == nil then
            LOG('UITEST no land for the factory')
            return
        end
        local tx, tz = FindSpot(fx, fz, sx, sz, 45, fx, fz, 70)
        if tx == nil then
            LOG('UITEST no land for the tanks')
            return
        end

        local brain = ArmyBrains[1]
        local army = brain.Name
        -- Plenty of resources, so the factory never stalls.
        brain:GiveStorage('Mass', 100000)
        brain:GiveStorage('Energy', 100000)
        brain:GiveResource('Mass', 100000)
        brain:GiveResource('Energy', 100000)

        local factory = CreateUnitHPR(Factory, army, fx, GetTerrainHeight(fx, fz), fz, 0, 0, 0)
        IssueBuildFactory({factory}, Tank, 50)

        for i = 0, 23 do
            local x = tx + math.mod(i, 6) * 3
            local z = tz + math.floor(i / 6) * 3
            CreateUnitHPR(Tank, army, x, GetTerrainHeight(x, z), z, 0, 0, 0)
        end
        LOG(string.format('UITEST spawned factory at (%.0f, %.0f), tanks at (%.0f, %.0f)', fx, fz, tx, tz))
    end)
end
