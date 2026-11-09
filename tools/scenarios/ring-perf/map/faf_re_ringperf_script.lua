-- faf_re_ringperf: sim half of the range-ring render cost test (tools/scenarios/1p-ringperf-main.yaml).
-- Packs 2000 UEF T1 engineers into a 45 x 45 grid, one unit apart, on open land away from the
-- start position, pinned so they stay put: well over 128 build rings overlap at the centre, so
-- every stencil batching path runs.

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local Engineer = 'uel0105'
local Count = 2000
local Columns = 45
local Spacing = 1
local LandRadius = 40

local function IsLand(x, z)
    if x < 64 or z < 64 or x > 960 or z > 960 then
        return false
    end
    return GetTerrainHeight(x, z) >= GetSurfaceHeight(x, z)
end

-- Land all around (x, z) out to LandRadius.
local function IsOpenLand(x, z)
    if not IsLand(x, z) then
        return false
    end
    for i = 0, 15 do
        local a = i * math.pi / 8
        for _, r in { LandRadius / 2, LandRadius } do
            if not IsLand(x + math.cos(a) * r, z + math.sin(a) * r) then
                return false
            end
        end
    end
    return true
end

local function FindSpot(sx, sz)
    for r = 60, 480, 8 do
        for i = 0, 31 do
            local a = i * math.pi / 16
            local x, z = sx + math.cos(a) * r, sz + math.sin(a) * r
            if IsOpenLand(x, z) then
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
        SetArmyUnitCap(1, 4000)
        local start = ScenarioUtils.GetMarker('ARMY_1').position
        local cx, cz = FindSpot(start[1], start[3])
        if cx == nil then
            LOG('RINGPERF no land for the grid')
            return
        end
        local army = ArmyBrains[1].Name
        local half = (Columns - 1) * Spacing / 2
        for i = 0, Count - 1 do
            local x = cx - half + math.mod(i, Columns) * Spacing
            local z = cz - half + math.floor(i / Columns) * Spacing
            local unit = CreateUnitHPR(Engineer, army, x, GetTerrainHeight(x, z), z, 0, 0, 0)
            unit:SetImmobile(true)
            unit:SetCollisionShape('None')
        end
        LOG(string.format('RINGPERF spawned %d at (%.0f, %.0f)', Count, cx, cz))
    end)
end
