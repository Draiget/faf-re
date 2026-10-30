-- faf_re_ringgpu: sim half of the range-ring A/B test (tools/scenarios/1p-ringgpu-*.yaml).
-- Two packs on open land, pinned so they stay put: 2000 UEF T1 engineers one unit apart (small
-- build rings, thousands overlapping) and 500 UEF artillery two units apart, 300 T1 mobile
-- artillery and 200 T2 mobile missile launchers (weapon rings larger than a close-up view).

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local LandRadius = 60

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

-- The nearest open land to (sx, sz) at least minDistance from every point in `avoid`.
local function FindSpot(sx, sz, avoid, minDistance)
    for r = 60, 480, 8 do
        for i = 0, 31 do
            local a = i * math.pi / 16
            local x, z = sx + math.cos(a) * r, sz + math.sin(a) * r
            local clear = IsOpenLand(x, z)
            for _, p in avoid do
                if clear and VDist2(x, z, p[1], p[2]) < minDistance then
                    clear = false
                end
            end
            if clear then
                return x, z
            end
        end
    end
    return nil
end

local function SpawnGrid(army, blueprints, count, columns, spacing, cx, cz)
    local half = (columns - 1) * spacing / 2
    for i = 0, count - 1 do
        local x = cx - half + math.mod(i, columns) * spacing
        local z = cz - half + math.floor(i / columns) * spacing
        local blueprint = blueprints[math.mod(i, table.getn(blueprints)) + 1]
        local unit = CreateUnitHPR(blueprint, army, x, GetTerrainHeight(x, z), z, 0, 0, 0)
        unit:SetImmobile(true)
        unit:SetCollisionShape('None')
    end
end

function OnPopulate(scenario)
    ScenarioUtils.InitializeArmies()
end

function OnStart(self)
    ForkThread(function()
        SetArmyUnitCap(1, 4000)
        local army = ArmyBrains[1].Name
        local start = ScenarioUtils.GetMarker('ARMY_1').position
        local ex, ez = FindSpot(start[1], start[3], {}, 0)
        if ex == nil then
            LOG('RINGGPU no land for the engineers')
            return
        end
        local ax, az = FindSpot(ex, ez, { { ex, ez } }, 220)
        if ax == nil then
            LOG('RINGGPU no land for the artillery')
            return
        end
        SpawnGrid(army, { 'uel0105' }, 2000, 45, 1, ex, ez)
        -- Every third unit a missile launcher, so both weapon rings are in the pack.
        SpawnGrid(army, { 'uel0103', 'uel0103', 'uel0111' }, 500, 25, 2, ax, az)
        LOG(string.format('RINGGPU spawned engineers at (%.0f, %.0f), artillery at (%.0f, %.0f)', ex, ez, ax, az))
    end)
end
