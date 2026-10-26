-- faf_re_rangerings: sim half of the range-ring stencil overflow test
-- (tools/scenarios/1p-rangerings-main.yaml). Spawns two engineer clusters on open land away from
-- the start position:
--   A (the smaller x): 128 engineers stacked on one point. Every ring and outline band there
--     counts exactly 128, which the 7-bit stencil count wraps to 0: the original draws nothing,
--     FAF #149 alone draws the fill without its outline.
--   B: 200 engineers in a tight sunflower spiral. Ring counts cross 128 inside the merged fill
--     (ring outlines inside it) and along the outer outline (gaps in it).

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local Engineer = 'uel0105'
local ClusterRadius = 6
local LandRadius = 16

local function IsLand(x, z)
    if x < 64 or z < 64 or x > 960 or z > 960 then
        return false
    end
    return GetTerrainHeight(x, z) >= GetSurfaceHeight(x, z)
end

-- Land all around (x, z) out to LandRadius, so every ring lies on land.
local function IsOpenLand(x, z)
    if not IsLand(x, z) then
        return false
    end
    for i = 0, 7 do
        local a = i * math.pi / 4
        if not IsLand(x + math.cos(a) * LandRadius, z + math.sin(a) * LandRadius) then
            return false
        end
    end
    return true
end

local function Distance(ax, az, bx, bz)
    return math.sqrt((ax - bx) * (ax - bx) + (az - bz) * (az - bz))
end

-- First open-land point on rings of growing radius around (cx, cz), at least minFromStart from
-- the start position and minFromOther from (ox, oz).
local function FindSpot(cx, cz, sx, sz, minFromStart, ox, oz, minFromOther)
    for r = 40, 400, 8 do
        for i = 0, 31 do
            local a = i * math.pi / 16
            local x, z = cx + math.cos(a) * r, cz + math.sin(a) * r
            if IsOpenLand(x, z) and Distance(x, z, sx, sz) >= minFromStart and
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
        local ax, az = FindSpot(sx, sz, sx, sz, 45)
        if ax == nil then
            LOG('RINGTEST no land for cluster A')
            return
        end
        local bx, bz = FindSpot(ax, az, sx, sz, 45, ax, az, 60)
        if bx == nil then
            LOG('RINGTEST no land for cluster B')
            return
        end
        if bx < ax then
            ax, az, bx, bz = bx, bz, ax, az
        end

        local army = ArmyBrains[1].Name
        -- Pinned with no collision shape, so collision cannot push the stack apart: every ring
        -- and band of A then counts exactly 128.
        for _ = 1, 128 do
            local unit = CreateUnitHPR(Engineer, army, ax, GetTerrainHeight(ax, az), az, 0, 0, 0)
            unit:SetImmobile(true)
            unit:SetCollisionShape('None')
        end
        for i = 0, 199 do
            local r = ClusterRadius * math.sqrt((i + 0.5) / 200)
            local a = i * 2.399963
            local x, z = bx + math.cos(a) * r, bz + math.sin(a) * r
            CreateUnitHPR(Engineer, army, x, GetTerrainHeight(x, z), z, 0, 0, 0)
        end
        LOG(string.format('RINGTEST spawned A at (%.0f, %.0f), B at (%.0f, %.0f)', ax, az, bx, bz))
    end)
end
