-- faf_re_waterlevels: sim half of the water-levels test (tools/scenarios/1p-waterlevels-main.yaml).
-- The map comes from tools/scenarios/water-levels/make_map.py. With sim_FixWaterBodies=1 every
-- check below passes; with it off (or on another engine) the bodies are not there and the lake,
-- pool and river checks fail, which is the control run. Each result is one "WATERTEST" log line.

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local Tolerance = 0.05
local passed, failed = 0, 0

local function Check(name, ok, detail)
    if ok then
        passed = passed + 1
    else
        failed = failed + 1
    end
    LOG(string.format('WATERTEST %s %s %s', ok and 'PASS' or 'FAIL', name, detail))
end

local function CheckSurface(name, x, z, expect)
    local surface = GetSurfaceHeight(x, z)
    Check('surface ' .. name, math.abs(surface - expect) <= Tolerance,
        string.format('at (%g, %g): surface %.3f terrain %.3f, expected %.3f', x, z, surface, GetTerrainHeight(x, z), expect))
end

local function CheckDry(name, x, z, below)
    local surface, terrain = GetSurfaceHeight(x, z), GetTerrainHeight(x, z)
    Check('dry ' .. name, surface == terrain and terrain < below,
        string.format('at (%g, %g): surface %.3f terrain %.3f, expected dry ground below %.3f', x, z, surface, terrain, below))
end

local function CheckUnit(name, unit, layer, y)
    if not unit or unit:IsDead() then
        Check('unit ' .. name, false, 'unit is gone')
        return
    end
    local pos = unit:GetPosition()
    local actual = unit:GetCurrentLayer()
    Check('unit ' .. name, actual == layer and math.abs(pos[2] - y) <= 1.0,
        string.format('at (%.1f, %.1f): layer %s y %.2f, expected %s at %.2f', pos[1], pos[3], tostring(actual), pos[2], layer, y))
end

function OnPopulate(scenario)
    ScenarioUtils.InitializeArmies()
end

function OnStart(self)
    ForkThread(function()
        WaitSeconds(1)

        -- Water surfaces where the generator put them.
        CheckSurface('crater lake', 88, 104, 30)
        CheckSurface('pool 1', 152, 152, 23)
        CheckSurface('pool 2', 172, 152, 20)
        CheckSurface('pool 3', 192, 152, 17)
        CheckSurface('river', 104, 200, 14)
        CheckSurface('sea bay', 20, 20, 3)
        CheckDry('polder', 196, 64, 3)
        CheckDry('desert', 128, 40, 30)

        local army = 'ARMY_1'
        local lakeShip = CreateUnitHPR('ues0103', army, 88, 30, 104, 0, 0, 0)
        local seaShip = CreateUnitHPR('ues0103', army, 20, 3, 20, 0, 0, 0)
        local hover = CreateUnitHPR('uel0203', army, 172, 20, 152, 0, 0, 0)
        local tank = CreateUnitHPR('uel0201', army, 196, 1, 64, 0, 0, 0)
        WaitSeconds(5)

        CheckUnit('frigate in the crater lake', lakeShip, 'Water', 30)
        CheckUnit('frigate in the sea bay', seaShip, 'Water', 3)
        CheckUnit('hover tank on pool 2', hover, 'Water', 20)
        CheckUnit('tank in the polder', tank, 'Land', 1)

        -- The crater lake is not connected to the sea: a move order there leaves the frigate in its lake.
        if lakeShip and not lakeShip:IsDead() then
            IssueMove({ lakeShip }, { 20, 3, 20 })
            WaitSeconds(20)
            local pos = lakeShip:GetPosition()
            -- No `^` here: this game's Lua doesn't take it as a power.
            local dx, dz = pos[1] - 88, pos[3] - 104
            local fromCentre = math.sqrt(dx * dx + dz * dz)
            Check('frigate stays in its lake', fromCentre < 22 and math.abs(pos[2] - 30) <= 1.0,
                string.format('after a move to the sea: at (%.1f, %.1f) y %.2f, %.1f from the lake centre', pos[1], pos[3], pos[2], fromCentre))
        end

        LOG(string.format('WATERTEST DONE passed %d failed %d', passed, failed))
    end)
end
