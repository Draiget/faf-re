-- faf_re_shipwake: sim half of the ship-wake comparison (tools/scenarios/1p-shipwake-*.yaml).
-- Finds the longest straight run of deep water on the map and sails three UEF ships along it,
-- back and forth, so their wakes are visible to the camera the UI hook points at them.

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local MinDepth = 3
local Step = 4
-- Keep the lane well inside the map so the camera never looks past its edge, which
-- renders differently from the playable area and would muddy the comparison.
local EdgeMargin = 128

local function IsDeep(x, z)
    if x < EdgeMargin or z < EdgeMargin or x > 1024 - EdgeMargin or z > 1024 - EdgeMargin then
        return false
    end
    return GetSurfaceHeight(x, z) - GetTerrainHeight(x, z) >= MinDepth
end

-- Length of the water run from (x, z) along (dx, dz), in steps.
local function RunLength(x, z, dx, dz, maxSteps)
    local n = 0
    while n < maxSteps and IsDeep(x + dx * (n + 1) * Step, z + dz * (n + 1) * Step) do
        n = n + 1
    end
    return n
end

local function FindLane()
    local best = { len = 0 }
    for gx = 16, 1008, 32 do
        for gz = 16, 1008, 32 do
            if IsDeep(gx, gz) then
                for i = 0, 15 do
                    local a = i * math.pi / 8
                    local dx, dz = math.cos(a), math.sin(a)
                    local len = RunLength(gx, gz, dx, dz, 60)
                    if len > best.len then
                        best = { len = len, x = gx, z = gz, dx = dx, dz = dz }
                    end
                end
            end
        end
    end
    return best
end

function OnPopulate(scenario)
    ScenarioUtils.InitializeArmies()
end

function OnStart(self)
    ForkThread(function()
        local lane = FindLane()
        if lane.len == 0 then
            LOG('WAKETEST no deep water found')
            return
        end
        -- Keep a margin at both ends so the ships do not run aground while turning.
        local len = (lane.len - 4) * Step
        local x0, z0 = lane.x + lane.dx * 2 * Step, lane.z + lane.dz * 2 * Step
        local x1, z1 = x0 + lane.dx * len, z0 + lane.dz * len
        LOG(string.format('WAKETEST lane from (%.0f, %.0f) to (%.0f, %.0f), %.0f units', x0, z0, x1, z1, len))

        local heading = math.atan2(lane.dx, lane.dz)
        local brain = ArmyBrains[1]
        local ships = {}
        local offsets = { { 'ues0201', 0 }, { 'ues0103', -10 }, { 'ues0103', 10 } }
        for _, entry in offsets do
            local ox, oz = -lane.dz * entry[2], lane.dx * entry[2]
            local unit = CreateUnitHPR(entry[1], brain.Name, x0 + ox, GetSurfaceHeight(x0 + ox, z0 + oz), z0 + oz, 0, heading, 0)
            table.insert(ships, unit)
        end
        for _ = 1, 10 do
            IssueMove(ships, { x1, GetSurfaceHeight(x1, z1), z1 })
            IssueMove(ships, { x0, GetSurfaceHeight(x0, z0), z0 })
        end
        LOG('WAKETEST ships sailing')
    end)
end
