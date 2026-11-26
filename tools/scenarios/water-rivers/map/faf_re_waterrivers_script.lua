-- faf_re_waterrivers: sim half of the rivers test (tools/scenarios/1p-waterrivers-main.yaml).
-- The map comes from tools/scenarios/water-rivers/make_map.py. With sim_FixWaterBodies=1 and sim_FixRivers=1
-- every check passes. With sim_FixRivers=0 the rivers are flat lakes at their Elevation: the profile and fall
-- checks are not run (the script says "flat lakes") and the frigate has to cross the old fall line, which is the
-- control run of "nothing is blocked". Each result is one "RIVERTEST" log line.

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local passed, failed = 0, 0

local function Check(name, ok, detail)
    if ok then
        passed = passed + 1
    else
        failed = failed + 1
    end
    LOG(string.format('RIVERTEST %s %s %s', ok and 'PASS' or 'FAIL', name, detail))
end

local function Report(text)
    LOG('RIVERTEST INFO ' .. text)
end

local function CheckSurface(name, x, z, expect, tolerance)
    local surface = GetSurfaceHeight(x, z)
    Check('surface ' .. name, math.abs(surface - expect) <= tolerance,
        string.format('at (%g, %g): surface %.3f terrain %.3f, expected %.3f', x, z, surface, GetTerrainHeight(x, z), expect))
end

local function Spawn(id, x, z, dy)
    local y = GetSurfaceHeight(x, z) + (dy or 0)
    return CreateUnitHPR(id, 'ARMY_1', x, y, z, 0, 0, 0)
end

local function Pos(unit)
    if not unit or unit:IsDead() then
        return nil
    end
    local p = unit:GetPosition()
    return p[1], p[2], p[3]
end

local function Move(unit, x, z, dy)
    IssueMove({ unit }, { x, GetSurfaceHeight(x, z) + (dy or 0), z })
end

local function Dist(x0, z0, x1, z1)
    local dx, dz = x1 - x0, z1 - z0
    return math.sqrt(dx * dx + dz * dz)
end

local function Layer(unit)
    if not unit or unit:IsDead() then
        return 'dead'
    end
    return tostring(unit:GetCurrentLayer())
end

-- A unit that was sent over the fall: it came down the upper reach and stopped at the lip, not across it.
local function CheckStopsAbove(name, unit, nearX, fallX)
    local x, y, z = Pos(unit)
    if not x then
        Check(name, false, 'unit is gone')
        return
    end
    Check(name, x > nearX and x < fallX,
        string.format('at (%.1f, %.1f) layer %s: expected x between %g (came down the reach) and %g (the fall line)', x, z, Layer(unit),
            nearX, fallX))
end

function OnPopulate(scenario)
    ScenarioUtils.InitializeArmies()
end

function OnStart(self)
    ForkThread(function()
        WaitSeconds(1)

        local rivers = math.abs(GetSurfaceHeight(60, 52) - GetSurfaceHeight(205, 82)) > 1
        Report(rivers and 'sloped rivers (sim_FixRivers on)' or 'flat lakes (sim_FixRivers off or an engine without rivers)')

        if rivers then
            -- The surface at the points of river A (their vertices), 1/128 unit.
            CheckSurface('A start', 28, 64, 44.0, 0.02)
            CheckSurface('A 2', 64, 52, 43.0, 0.02)
            CheckSurface('A 3', 100, 60, 41.5, 0.02)
            CheckSurface('A lip', 130, 76, 39.0, 0.02)
            CheckSurface('A 5', 162, 86, 30.5, 0.02)
            CheckSurface('A end', 205, 82, 28.0, 0.02)
            -- The fall: the surface just below the lip.
            local below = GetSurfaceHeight(132, 77)
            Check('surface below the fall', below > 29 and below < 32.5, string.format('at (132, 77): %.3f', below))
            -- Downhill all the way along the centreline of the two reaches (not across the lip).
            local last, monotone = 100, true
            for _, p in { { 28, 64 }, { 40, 60 }, { 64, 52 }, { 80, 55 }, { 100, 60 }, { 115, 68 }, { 125, 74 } } do
                local h = GetSurfaceHeight(p[1], p[2])
                if h > last + 0.02 then
                    monotone = false
                end
                last = h
            end
            Check('upper reach runs downhill', monotone, string.format('last %.3f', last))
            -- River B: flat, a step of 0.75, flat; B2: the same heights without the fall.
            CheckSurface('B above', 60, 112, 41.0, 0.02)
            CheckSurface('B below', 90, 112, 40.25, 0.02)
            CheckSurface('B2 above', 60, 140, 41.0, 0.02)
            CheckSurface('B2 below', 90, 140, 40.25, 0.02)

            -- The terrain type the Lua navmesh reads: the fall is Blocking, the river beside it is not.
            local fallType = GetTerrainType(130, 76)
            local plainType = GetTerrainType(100, 60)
            Check('fall cell is a blocking terrain type', fallType and fallType.Blocking == true and not (plainType and plainType.Blocking),
                string.format('(130, 76) type %s blocking %s, (100, 60) blocking %s', tostring(fallType and fallType.Name),
                    tostring(fallType and fallType.Blocking), tostring(plainType and plainType.Blocking)))

            -- B and B2 have the same bed (a step of 0.75 down at x = 70, exactly the slope limit); only B's surface has a
            -- fall there, so only B's lip is a blocking terrain type.
            local bLip, b2Lip, bBefore = GetTerrainType(70, 112), GetTerrainType(70, 140), GetTerrainType(60, 112)
            Check('B lip is the fall, B2 and the shallows are not', bLip and bLip.Blocking == true and not (b2Lip and b2Lip.Blocking) and not (bBefore and bBefore.Blocking),
                string.format('(70, 112) blocking %s, (70, 140) %s, (60, 112) %s; bed step at the lip %.4f', tostring(bLip and bLip.Blocking),
                    tostring(b2Lip and b2Lip.Blocking), tostring(bBefore and bBefore.Blocking), GetTerrainHeight(70, 112) - GetTerrainHeight(71, 112)))

            -- A sonar (1 x 1, builds on water, so it goes through the single-cell check): on the river above and below
            -- the fall, not on the fall cells that the line across the lip crosses.
            local brain = GetArmyBrain('ARMY_1')
            local function Can(x, z)
                return brain:CanBuildStructureAt('ueb3102', { x, GetSurfaceHeight(x, z), z }) == true
            end
            local upOk = Can(100, 60) and Can(110, 63) and Can(118, 69)
            local downOk = Can(145, 81) and Can(160, 85) and Can(175, 85)
            local blocked, scan = 0, ''
            for k = -6, 6 do
                local x = 130 + k * 0.5
                local z = 76 + k * 0.5 * 0.38
                local ok = Can(x, z)
                if not ok then
                    blocked = blocked + 1
                end
                scan = scan .. (ok and 'y' or 'n')
            end
            Check('sonar: river yes, fall no', upOk and downOk and blocked >= 2,
                string.format('above the fall %s, below %s, along the lip x 127..133 (y = can build): %s (%d blocked)', tostring(upOk), tostring(downOk), scan, blocked))
        end

        -- Units. Everything starts at once and runs for the same minute.
        local frigateUp = Spawn('ues0103', 100, 60)
        local frigateDown = Spawn('ues0103', 165, 86)
        local frigateDownUp = Spawn('ues0103', 170, 86)
        local hover = Spawn('uel0203', 100, 60)
        local sub = Spawn('ues0203', 100, 60)
        local amphibious = Spawn('url0203', 100, 60)
        local air = Spawn('uea0102', 100, 60, 4)
        -- The shallows of B and B2 are too shallow for a ship and too wet for a tank (a land unit under any water
        -- drowns), so an amphibious unit walks them. A land tank is sent over the river at the fall.
        local ampB = Spawn('url0203', 50, 112)
        local ampB2 = Spawn('url0203', 50, 140)
        local tankLand = Spawn('uel0201', 130, 44)
        WaitSeconds(3)

        -- Naval: the upper reach is a waypoint, then the lower reach is over the fall.
        Move(frigateUp, 118, 69)
        Move(frigateUp, 175, 85)
        -- The lower reach on its own: nothing stops a ship there.
        Move(frigateDown, 200, 82)
        -- From below to above.
        Move(frigateDownUp, 110, 64)
        Move(hover, 118, 69)
        Move(hover, 175, 85)
        Move(sub, 118, 69)
        Move(sub, 175, 85)
        Move(amphibious, 118, 69)
        Move(amphibious, 175, 85)
        Move(air, 175, 85, 4)
        Move(ampB, 95, 112)
        Move(ampB2, 95, 140)
        Move(tankLand, 150, 125)

        WaitSeconds(75)

        -- (An interceptor loiters around its waypoint, so the check is the side of the fall it ended on.)
        local ax, ay, az = Pos(air)
        Check('air crosses the fall', ax ~= nil and ax > 150,
            string.format('at (%s, %s)', tostring(ax), tostring(az)))

        -- The land tank was ordered across the river: it goes around its end (or stops), it does not enter the water.
        local lx, ly, lz = Pos(tankLand)
        Check('land tank sent over the river stays on land', lx ~= nil and Layer(tankLand) == 'Land',
            string.format('at (%s, %s) layer %s health %s', tostring(lx), tostring(lz), Layer(tankLand), tostring(tankLand and not tankLand:IsDead() and tankLand:GetHealth())))

        local dx, dy, dz = Pos(frigateDown)
        Check('naval moves in the lower reach', dx ~= nil and Dist(dx, dz, 200, 82) <= 10,
            string.format('at (%s, %s) layer %s', tostring(dx), tostring(dz), Layer(frigateDown)))

        if rivers then
            CheckStopsAbove('naval stops above the fall', frigateUp, 112, 131)
            CheckStopsAbove('hover stops above the fall', hover, 112, 131)
            CheckStopsAbove('submarine stops above the fall', sub, 112, 131)
            CheckStopsAbove('amphibious stops above the fall', amphibious, 112, 131)
            local ux, uy, uz = Pos(frigateDownUp)
            Check('naval stays below the fall', ux ~= nil and ux > 129,
                string.format('at (%s, %s) layer %s', tostring(ux), tostring(uz), Layer(frigateDownUp)))
            local bx, by, bz = Pos(ampB)
            Check('amphibious stops at the fall of B', bx ~= nil and bx > 55 and bx < 71.5,
                string.format('at (%s, %s) layer %s', tostring(bx), tostring(bz), Layer(ampB)))
            local cx, cy, cz = Pos(ampB2)
            Check('amphibious crosses river B2 (no fall)', cx ~= nil and cx > 88 and Dist(cx, cz, 95, 140) <= 6,
                string.format('at (%s, %s) layer %s', tostring(cx), tostring(cz), Layer(ampB2)))
        else
            local fx, fy, fz = Pos(frigateUp)
            Check('flat lake: naval crosses the old fall line', fx ~= nil and fx > 140,
                string.format('at (%s, %s) layer %s', tostring(fx), tostring(fz), Layer(frigateUp)))
            local hx, hy, hz = Pos(hover)
            Check('flat lake: hover crosses the old fall line', hx ~= nil and hx > 140,
                string.format('at (%s, %s) layer %s', tostring(hx), tostring(hz), Layer(hover)))
            local ux, uy, uz = Pos(frigateDownUp)
            Check('flat lake: naval goes upstream', ux ~= nil and ux < 125,
                string.format('at (%s, %s) layer %s', tostring(ux), tostring(uz), Layer(frigateDownUp)))
        end

        LOG(string.format('RIVERTEST DONE passed %d failed %d', passed, failed))
    end)
end
