-- Staged battle for the light census (docs/DYNAMIC_LIGHTS.md, "Census"). Not part of the engine: copy this file as
-- <exe folder>/fafengine/lua/test/dynlights_test.lua (the name the sim hook looks for) and dynlights_camera.lua next to it for the camera
-- (the hook tests/lights/ingame/hooks/gamemain.lua runs it in the user interface), then start a skirmish with /con "ren_DynLights=4;ren_DynLightsCensus=900".
--
-- Two groups of mixed-faction units fight in front of the camera; four waves of rising tech, so that most effects of the game appear on screen:
--   t = 15 s   tier 1 land units (tanks, bots, mobile artillery, missile launchers)
--   t = 60 s   tier 2: heavy tanks, bombers, gunships, a point defence
--   t = 110 s  tier 3: assault bots, artillery, strategic bombers, air superiority fighters
--   t = 160 s  experimentals: Fatboy, Colossus, Monkeylord, Ythotha, Czar
--   t = 230 s  done
-- The AI armies play their own game elsewhere at the same time.

local function Say(text)
    LOG(string.format('DYNLIGHT-TEST: [%.1f s] %s', GetGameTimeSeconds(), text))
end

local function WaitUntil(seconds)
    while GetGameTimeSeconds() < seconds do
        WaitTicks(5)
    end
end

ForkThread(function()
    local brainA, brainB = ArmyBrains[1], ArmyBrains[2]
    local x0, z0 = brainA:GetArmyStartPos()
    SetAlliance(1, 2, 'Enemy')
    SetAlliance(2, 1, 'Enemy')
    Say(string.format('start position (%.1f, %.1f); army A %s, army B %s', x0, z0, brainA.Name, brainB.Name))

    local groups = { A = {}, B = {} }

    local function Wave(side, brain, baseX, dir, list, label)
        local x, z0w = baseX, z0
        local created, failed = 0, 0
        local units = {}
        local row = 0
        for _, entry in list do
            local bp, count = entry[1], entry[2]
            for i = 1, count do
                local ux = x + dir * math.floor(row / 5) * 4
                local uz = z0w - 14 + math.mod(row, 5) * 7
                local air = string.sub(bp, 3, 3) == 'a'   -- the third letter of a blueprint id: a = air, l = land, b = structure, s = sea
                local y = GetTerrainHeight(ux, uz) + (air and 12 or 0)
                local unit = CreateUnitHPR(bp, brain.Name, ux, y, uz, 0, dir > 0 and math.pi * 0.5 or -math.pi * 0.5, 0)
                if unit then
                    table.insert(units, unit)
                    table.insert(groups[side], unit)
                    created = created + 1
                else
                    failed = failed + 1
                end
                row = row + 1
            end
        end
        local targetX = baseX + (dir > 0 and 70 or -70)
        if units[1] then
            IssueAggressiveMove(units, { targetX, GetTerrainHeight(targetX, z0w), z0w })
        end
        Say(string.format('%s side %s: %d units created, %d failed', label, side, created, failed))
    end

    local westX, eastX = x0 - 45, x0 + 45

    WaitUntil(15)
    Wave('A', brainA, westX, 1, { { 'uel0106', 3 }, { 'uel0201', 3 }, { 'ual0106', 2 }, { 'ual0201', 2 }, { 'uel0103', 1 } }, 'tier 1')
    Wave('B', brainB, eastX, -1, { { 'url0106', 3 }, { 'url0107', 3 }, { 'xsl0101', 2 }, { 'xsl0201', 2 }, { 'url0111', 1 } }, 'tier 1')

    WaitUntil(60)
    Wave('A', brainA, westX, 1, { { 'uel0202', 2 }, { 'uel0203', 1 }, { 'ual0202', 2 }, { 'uea0103', 2 }, { 'uaa0103', 2 }, { 'ueb2301', 1 } }, 'tier 2')
    Wave('B', brainB, eastX, -1, { { 'url0202', 2 }, { 'url0203', 1 }, { 'xsl0202', 2 }, { 'ura0103', 2 }, { 'xsa0103', 2 }, { 'urb2301', 1 } }, 'tier 2')

    WaitUntil(110)
    Wave('A', brainA, westX, 1, { { 'uel0303', 1 }, { 'ual0303', 1 }, { 'uel0304', 1 }, { 'uea0304', 1 }, { 'uaa0303', 2 } }, 'tier 3')
    Wave('B', brainB, eastX, -1, { { 'url0303', 1 }, { 'xsl0303', 1 }, { 'url0304', 1 }, { 'xsa0303', 2 }, { 'ura0303', 1 } }, 'tier 3')

    WaitUntil(160)
    Wave('A', brainA, westX, 1, { { 'uel0401', 1 }, { 'ual0401', 1 }, { 'uaa0310', 1 } }, 'experimentals')
    Wave('B', brainB, eastX, -1, { { 'url0402', 1 }, { 'xsl0401', 1 }, { 'xsa0402', 1 } }, 'experimentals')

    WaitUntil(230)
    Say('done')
end)
