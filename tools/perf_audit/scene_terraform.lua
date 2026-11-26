-- Feature on/off capture scene. Not part of the engine: copy as <exe folder>/fafengine/lua/test/dynlights_test.lua with a header that
-- defines AB_SCENE ('scan' | 'static' | 'nuke') and AB_TX, AB_TZ (the nuke target / water position for 'scan' output).
--   scan   : logs the start position and the nearest water ("FEATAB: water at x z")
--   static : the census structures of four factions plus idle units, nothing moves (so unpaused frames of different settings are comparable)
--   nuke   : the static scene is skipped; a strategic missile is launched at t = 10 s at (AB_TX, AB_TZ)

local function Say(text)
    LOG(string.format('FEATAB: [%.1f s] %s', GetGameTimeSeconds(), text))
end

local function WaitUntil(seconds)
    while GetGameTimeSeconds() < seconds do
        WaitTicks(5)
    end
end

local FACTIONS = { 'ue', 'ua', 'ur', 'xs' }
local STRUCTURES = { '0101', '0102', '1101', '1102', '1103', '1104', '1201', '1301', '3101', '3201', '2101', '2104', '2301', '2302', '2305' }

ForkThread(function()
    local brainA, brainB = ArmyBrains[1], ArmyBrains[2]
    local x0, z0 = brainA:GetArmyStartPos()
    SetAlliance(1, 2, 'Enemy')
    SetAlliance(2, 1, 'Enemy')
    Say(string.format('start position (%.1f, %.1f)', x0, z0))
    -- The commanders are moved far away and out of view: an ACU at the start position fires at the test units and glows, and its lights and
    -- effects skewed every capture (they are only collected while on screen).
    for _, brain in { brainA, brainB } do
        for _, u in brain:GetListOfUnits(categories.COMMAND, false) do
            local fx, fz = 470, 40
            Warp(u, Vector(fx, GetTerrainHeight(fx, fz), fz))
        end
    end

    if AB_SCENE == 'scan' then
        for r = 10, 250, 4 do
            for i = 0, 23 do
                local a = i * math.pi / 12
                local x, z = x0 + r * math.cos(a), z0 + r * math.sin(a)
                if GetSurfaceHeight(x, z) > GetTerrainHeight(x, z) + 1.5 then
                    Say(string.format('water at %.1f %.1f (ground %.2f, surface %.2f, radius %d)', x, z, GetTerrainHeight(x, z), GetSurfaceHeight(x, z), r))
                    return
                end
            end
        end
        Say('no water found')
        return
    end

    if AB_SCENE == 'deepscan' then
        -- the deepest water within 150 units of the start position
        local bx, bz, bd = 0, 0, 0
        for r = 0, 150, 5 do
            for i = 0, 35 do
                local ang = i * math.pi / 18
                local x, z = x0 + r * math.cos(ang), z0 + r * math.sin(ang)
                local d = GetSurfaceHeight(x, z) - GetTerrainHeight(x, z)
                if d > bd then bx, bz, bd = x, z, d end
            end
        end
        Say(string.format('deepest water at %.1f %.1f depth %.2f', bx, bz, bd))
        return
    end
    if AB_SCENE == 'waterlight' then
        -- a lit lake: hover tanks on the water at (AB_TX, AB_TZ) carry long-lived light particles of three sizes
        WaitUntil(4)
        local sizes = rawget(_G, 'AB_SIZES') or { 6, 14, 30 }
        local anchors = {}
        for i = 1, table.getn(sizes) do
            local ux, uz = AB_TX - 24 + (i - 1) * 24, AB_TZ
            local u = CreateUnitHPR('uel0203', brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, 0, 0)
            table.insert(anchors, u)
            Say(string.format('waterlight unit %d at %.1f %.1f: %s', i, ux, uz, tostring(u ~= nil)))
        end
        for round = 1, 20 do
            for i = 1, table.getn(sizes) do
                if anchors[i] and not anchors[i].Dead then
                    CreateLightParticle(anchors[i], -1, brainA:GetArmyIndex(), sizes[i], 150, 'glow_03', 'ramp_flare_02')
                end
            end
            WaitSeconds(14)
        end
        return
    end

    if AB_SCENE == 'wake' then
        -- hover tanks patrolling a lake: their wakes should show in the water
        WaitUntil(4)
        local tanks = {}
        for i = 1, 4 do
            local ux, uz = AB_TX - 12 + i * 5, AB_TZ
            local u = CreateUnitHPR('uel0203', brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, 0, 0)
            if u then
                u:SetCanTakeDamage(false)
                table.insert(tanks, u)
            end
        end
        Say(string.format('wake scene: %d tanks', table.getn(tanks)))
        for round = 1, 30 do
            for i, u in ipairs(tanks) do
                if u and not u.Dead then
                    IssueClearCommands({ u })
                    local side = math.mod(round + i, 2) == 0 and 1 or -1
                    IssueMove({ u }, { AB_TX + side * 10, GetSurfaceHeight(AB_TX + side * 10, AB_TZ + (i - 2.5) * 3), AB_TZ + (i - 2.5) * 3 })
                end
            end
            WaitSeconds(6)
        end
        return
    end
    if AB_SCENE == 'ships' then
        -- ships sailing a bay: a destroyer, a cruiser, a frigate and the amphibious experimental, back and forth along x
        WaitUntil(4)
        local ids = { 'ues0201', 'ues0202', 'ues0103', 'uel0401' }
        local ships = {}
        for i, id in ipairs(ids) do
            local ux, uz = AB_TX - 60, AB_TZ + (i - 2.5) * 25
            local u = CreateUnitHPR(id, brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, 0, 0)
            if u then
                u:SetCanTakeDamage(false)
                table.insert(ships, { u, uz })
            end
            Say(string.format('ship %s at %.1f %.1f: %s (surface %.2f, ground %.2f)', id, ux, uz, tostring(u ~= nil), GetSurfaceHeight(ux, uz), GetTerrainHeight(ux, uz)))
        end
        for round = 1, 40 do
            for _, entry in ipairs(ships) do
                local u, uz = entry[1], entry[2]
                if u and not u.Dead then
                    IssueClearCommands({ u })
                    local x = AB_TX + (math.mod(round, 2) == 0 and -35 or 65)
                    IssueMove({ u }, { x, GetSurfaceHeight(x, uz), uz })
                end
            end
            WaitSeconds(12)
        end
        return
    end
    if AB_SCENE == 'fleet' then
        -- ships of all four factions sailing the bay, one lane each (a wake, foam and a bow wave should follow every one of them)
        WaitUntil(4)
        local ids = rawget(_G, 'AB_FLEET') or { 'uas0103', 'uas0201', 'uas0202', 'uas0302', 'urs0103', 'urs0201', 'urs0202', 'urs0302', 'xss0103', 'xss0201', 'xss0202', 'xss0302', 'ues0103', 'ues0201', 'ues0202', 'ues0302', 'uas0401' }
        local ships = {}
        -- a lane is a line along x (from AB_TX - 60 to AB_TX + 90) whose water is deep all the way; lanes 14 units apart, searched from AB_TZ outwards
        local function DeepLane(z)
            for x = AB_TX - 60, AB_TX + 90, 15 do
                if GetSurfaceHeight(x, z) - GetTerrainHeight(x, z) < 4 then return false end
            end
            return true
        end
        local lanes = {}
        for off = 0, 400, 14 do
            if table.getn(lanes) < table.getn(ids) and DeepLane(AB_TZ + off) then table.insert(lanes, AB_TZ + off) end
            if off > 0 and table.getn(lanes) < table.getn(ids) and DeepLane(AB_TZ - off) then table.insert(lanes, AB_TZ - off) end
        end
        Say(string.format('fleet: %d lanes for %d ships', table.getn(lanes), table.getn(ids)))
        for i, id in ipairs(ids) do
            local uz = lanes[i] or AB_TZ
            local ux = AB_TX - 60
            local u = CreateUnitHPR(id, brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, 0, 0)
            if u then
                u:SetCanTakeDamage(false)
                table.insert(ships, { u, uz })
            end
            Say(string.format('fleet %s lane %d: %s (depth %.1f)', id, i, tostring(u ~= nil), GetSurfaceHeight(ux, uz) - GetTerrainHeight(ux, uz)))
        end
        for round = 1, 40 do
            for _, entry in ipairs(ships) do
                local u, uz = entry[1], entry[2]
                if u and not u.Dead then
                    IssueClearCommands({ u })
                    local x = AB_TX + (math.mod(round, 2) == 0 and -50 or 90)
                    IssueMove({ u }, { x, GetSurfaceHeight(x, uz), uz })
                end
            end
            WaitSeconds(14)
        end
        return
    end
    if AB_SCENE == 'ship1' then
        -- one destroyer sails a straight line through (AB_TX, AB_TZ) along x, back and forth: the camera looks at the middle of the line
        WaitUntil(4)
        for dx = -90, 90, 15 do
            local x = AB_TX + dx
            Say(string.format('depth at dx %d: %.1f', dx, GetSurfaceHeight(x, AB_TZ) - GetTerrainHeight(x, AB_TZ)))
        end
        local id = rawget(_G, 'AB_SHIP') or 'ues0201'
        local span = rawget(_G, 'AB_SPAN') or 0
        local x0, x1 = AB_TX - 35, AB_TX + 65
        if span > 0 then x0, x1 = AB_TX - span, AB_TX + span end
        local u = CreateUnitHPR(id, brainA.Name, x0, GetSurfaceHeight(x0, AB_TZ), AB_TZ, 0, 0, 0)
        if u then u:SetCanTakeDamage(false) end
        for round = 1, 60 do
            if u and not u.Dead then
                IssueClearCommands({ u })
                local x = (math.mod(round, 2) == 0) and x0 or x1
                IssueMove({ u }, { x, GetSurfaceHeight(x, AB_TZ), AB_TZ })
            end
            WaitSeconds(16)
        end
        return
    end
    if AB_SCENE == 'shipsq' then
        -- one unit after the other sails the bay (the markers say which): a hover tank, a frigate, a destroyer, a cruiser, a battleship, the amphibious experimental
        WaitUntil(4)
        local ids = { 'uel0203', 'ues0103', 'ues0201', 'ues0202', 'ues0302', 'uel0401' }
        for _, id in ipairs(ids) do
            local u = CreateUnitHPR(id, brainA.Name, AB_TX - 35, GetSurfaceHeight(AB_TX - 35, AB_TZ), AB_TZ, 0, 0, 0)
            Say(string.format('SHIPSQ start %s: %s', id, tostring(u ~= nil)))
            if u then
                u:SetCanTakeDamage(false)
                IssueMove({ u }, { AB_TX + 65, GetSurfaceHeight(AB_TX + 65, AB_TZ), AB_TZ })
            end
            WaitSeconds(24)
            Say(string.format('SHIPSQ end %s', id))
            if u and not u.Dead then u:Destroy() end
            WaitSeconds(9)
        end
        return
    end
    if AB_SCENE == 'splash' then
        -- shells of growing damage land in the bay (the markers say which), then ships of growing size sink
        WaitUntil(4)
        local host = CreateUnitHPR('ues0201', brainA.Name, AB_TX + 35, GetSurfaceHeight(AB_TX + 35, AB_TZ), AB_TZ, 0, 0, 0)
        if host then host:SetCanTakeDamage(false) end
        for _, damage in ipairs({ 20, 100, 500, 3000, 20000 }) do
            Say(string.format('SPLASH start damage %d', damage))
            for i = 1, 3 do
                if host and not host.Dead then
                    local proj = host:CreateProjectile('/projectiles/TDFGauss01/TDFGauss01_proj.bp', -40 + i * 12, 6, 0, 0, -1, 0)
                    if proj then
                        proj:PassDamageData({ DamageAmount = damage, DamageRadius = 0, DamageType = 'Normal', DamageFriendly = false, DamageSelf = false })
                    end
                end
                WaitSeconds(1)
            end
            WaitSeconds(7)
        end
        for _, id in ipairs({ 'uel0203', 'ues0103', 'ues0201', 'ues0302' }) do
            local ux, uz = AB_TX - 15, AB_TZ
            Say(string.format('SPLASH death place depth %.1f', GetSurfaceHeight(ux, uz) - GetTerrainHeight(ux, uz)))
            local u = CreateUnitHPR(id, brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, 0, 0)
            Say(string.format('SPLASH death %s: %s', id, tostring(u ~= nil)))
            WaitSeconds(3)
            if u and not u.Dead then u:Kill() end
            WaitSeconds(10)
        end
        return
    end
    if AB_SCENE == 'aircrash' then
        -- aircraft shot down over the bay: a fighter, a gunship, a strategic bomber
        WaitUntil(4)
        for _, id in ipairs({ 'uea0102', 'uea0203', 'uea0304' }) do
            local ux, uz = AB_TX - 10, AB_TZ
            local u = CreateUnitHPR(id, brainA.Name, ux, GetSurfaceHeight(ux, uz) + 30, uz, 0, 0, 0)
            Say(string.format('CRASH start %s: %s', id, tostring(u ~= nil)))
            WaitSeconds(2)
            if u and not u.Dead then u:Kill() end
            WaitSeconds(14)
        end
        return
    end
    if AB_SCENE == 'build' then
        -- engineers of four factions build structures near the start position: the build beams (the camera looks at AB_TX, AB_TZ)
        WaitUntil(4)
        local engineers = { 'uel0105', 'ual0105', 'url0105', 'xsl0105' }
        local structures = { 'ueb1101', 'uab1101', 'urb1101', 'xsb1101' }
        for i, id in ipairs(engineers) do
            local ux, uz = AB_TX - 18 + (i - 1) * 12, AB_TZ
            local u = CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
            Say(string.format('BUILD engineer %s: %s', id, tostring(u ~= nil)))
            if u then
                u:SetCanTakeDamage(false)
                local bx, bz = ux, uz + 8
                IssueBuildMobile({ u }, { bx, GetTerrainHeight(bx, bz), bz }, structures[i], {})
            end
        end
        WaitSeconds(60)
        return
    end
    if AB_SCENE == 'titan' then
        -- two UEF assault bots standing near the start position (the camera looks at AB_TX, AB_TZ): the glow of units against the zoom
        WaitUntil(4)
        for i, id in ipairs({ 'uel0303', 'uel0202' }) do
            local ux, uz = AB_TX + (i - 1.5) * 10, AB_TZ
            local u = CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
            Say(string.format('TITAN unit %s: %s', id, tostring(u ~= nil)))
            if u then u:SetCanTakeDamage(false) end
        end
        WaitSeconds(120)
        return
    end
    if AB_SCENE == 'terraform' then
        -- a building going up somewhere every half second: the height field changes, its revision with it (terraform hitch test)
        WaitUntil(4)
        local k = 0
        while true do
            k = k + 1
            local bx, bz = x0 + math.mod(k * 37, 160) - 80, z0 + math.mod(k * 53, 160) - 80
            FlattenMapRect(bx, bz, 4, 4, GetTerrainHeight(bx, bz))
            WaitTicks(5)
        end
    end
    if AB_SCENE == 'none' then
        Say(string.format('ground height %.2f', GetTerrainHeight(x0, z0)))
        return
    end
    brainA:GiveResource('Energy', 100000)
    brainA:GiveResource('Mass', 100000)
    if AB_SCENE == 'rays' then
        WaitUntil(4)
        for fi, prefix in FACTIONS do
            for si, number in STRUCTURES do
                local id = prefix .. 'b' .. number
                local ux, uz = x0 - 40 + (si - 1) * 5, z0 - 30 + (fi - 1) * 12
                if __blueprints[id] then
                    CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
                end
            end
        end
        local ids = { 'uel0401', 'url0402', 'ual0401', 'xsl0401', 'xel0305', 'url0303', 'ual0303', 'uel0303' }
        for i = 1, 8 do
            local ux, uz = x0 - 35 + i * 9, z0 + 14
            if __blueprints[ids[i]] then
                CreateUnitHPR(ids[i], brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, math.pi * 0.25 * i, 0)
            end
        end
        -- a wall (thin), a fence of radars, gunships hovering, trees (alpha)
        for i = 0, 24 do
            local ux, uz = x0 - 12 + i, z0 + 28
            CreateUnitHPR('xsb5101', brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
        end
        for i = 0, 10 do
            local ux, uz = x0 - 12, z0 + 28 + i
            CreateUnitHPR('xsb5101', brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
        end
        for i = 1, 4 do
            local ux, uz = x0 - 25 + i * 12, z0 + 40
            local u = CreateUnitHPR('uea0203', brainA.Name, ux, GetTerrainHeight(ux, uz) + 8, uz, 0, 0, 0)
        end
        local trees = { '/env/Evergreen/Props/Trees/Pine06_Big_prop.bp', '/env/Evergreen/Props/Trees/Oak01_s1_prop.bp', '/env/Evergreen/Props/Trees/Groups/Pine06_GroupA_prop.bp', '/env/Evergreen/Props/Trees/DC01_s1_prop.bp' }
        for i = 1, 14 do
            local ux, uz = x0 + 18 + math.mod(i * 7, 23), z0 + 26 + math.mod(i * 5, 17)
            CreatePropHPR(trees[math.mod(i, 4) + 1], ux, GetTerrainHeight(ux, uz), uz, i * 0.7, 0, 0)
        end
        Say('rays scene created')
        return
    end
    if AB_SCENE == 'soak' then
        -- the rays scene (structures, wall, gunships, trees) plus a moving battle and a nuke every 25 s: a long run with every ray feature on
        WaitUntil(4)
        for fi, prefix in FACTIONS do
            for si, number in STRUCTURES do
                local id = prefix .. 'b' .. number
                local ux, uz = x0 - 40 + (si - 1) * 5, z0 - 30 + (fi - 1) * 12
                if __blueprints[id] then CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0) end
            end
        end
        for i = 0, 24 do
            local ux, uz = x0 - 12 + i, z0 + 28
            CreateUnitHPR('xsb5101', brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
        end
        local trees = { '/env/Evergreen/Props/Trees/Pine06_Big_prop.bp', '/env/Evergreen/Props/Trees/Oak01_s1_prop.bp', '/env/Evergreen/Props/Trees/Groups/Pine06_GroupA_prop.bp', '/env/Evergreen/Props/Trees/DC01_s1_prop.bp' }
        for i = 1, 14 do
            local ux, uz = x0 + 18 + math.mod(i * 7, 23), z0 + 26 + math.mod(i * 5, 17)
            CreatePropHPR(trees[math.mod(i, 4) + 1], ux, GetTerrainHeight(ux, uz), uz, i * 0.7, 0, 0)
        end
        local ids = { 'uel0201', 'url0202', 'ual0201', 'xsl0201', 'uel0303', 'url0303', 'ual0303', 'xsl0303',
                      'uel0202', 'url0107', 'ual0106', 'xsl0202', 'uel0401', 'url0402', 'ual0401', 'xsl0401' }
        local blue, red = {}, {}
        for i = 1, (rawget(_G, 'AB_COUNT') or 40) do
            local row, col = math.floor((i - 1) / 8), math.mod(i - 1, 8)
            local ax, az = x0 - 18 - row * 4, z0 + 50 + col * 4.5
            local bx, bz = x0 + 18 + row * 4, z0 + 50 + col * 4.5
            local a = CreateUnitHPR(ids[math.mod(i - 1, 16) + 1], brainA.Name, ax, GetTerrainHeight(ax, az), az, 0, math.pi * 0.5, 0)
            local b = CreateUnitHPR(ids[math.mod(i + 4, 16) + 1], brainB.Name, bx, GetTerrainHeight(bx, bz), bz, 0, -math.pi * 0.5, 0)
            if a then table.insert(blue, a) end
            if b then table.insert(red, b) end
        end
        IssueAggressiveMove(blue, Vector(x0 + 30, GetTerrainHeight(x0 + 30, z0 + 60), z0 + 60))
        IssueAggressiveMove(red, Vector(x0 - 30, GetTerrainHeight(x0 - 30, z0 + 60), z0 + 60))
        Say('soak scene created')
        for round = 1, 12 do
            WaitUntil(10 + round * 25)
            local launcher = CreateUnitHPR('xsb2305', brainB.Name, x0 + 60, GetTerrainHeight(x0 + 60, z0), z0, 0, 0, 0)
            if launcher then
                launcher:GiveNukeSiloAmmo(1)
                local nx, nz = x0 + math.mod(round * 13, 50) - 25, z0 + 10 + math.mod(round * 17, 60)
                IssueNuke({ launcher }, { nx, GetSurfaceHeight(nx, nz), nz })
                Say(string.format('nuke %d launched at %.1f %.1f', round, nx, nz))
            end
        end
        return
    end
    if AB_SCENE == 'static' then
        WaitUntil(4)
        for fi, prefix in FACTIONS do
            for si, number in STRUCTURES do
                local id = prefix .. 'b' .. number
                local ux, uz = x0 - 40 + (si - 1) * 5, z0 - 30 + (fi - 1) * 12
                if __blueprints[id] then
                    CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
                end
            end
        end
        local ids = { 'uel0401', 'url0402', 'ual0401', 'xsl0401', 'xel0305', 'url0303', 'ual0303', 'uel0303' }
        for i = 1, 8 do
            local ux, uz = x0 - 35 + i * 9, z0 + 14
            if __blueprints[ids[i]] then
                CreateUnitHPR(ids[i], brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, math.pi * 0.25 * i, 0)
            end
        end
        Say('static scene created')
        return
    end
    -- Shields need energy and shut down within seconds when the army has none (the test army has no economy): this keeps the tank full.
    local function KeepPowered()
        ForkThread(function()
            while true do
                brainA:GiveResource('Energy', 100000)
                WaitSeconds(1)
            end
        end)
    end
    if AB_SCENE == 'shield' then
        -- a shield generator with structures and units under its bubble (west), the same group without a shield (east) as the control
        WaitUntil(4)
        KeepPowered()
        local function Group(cx, cz, withShield)
            if withShield then
                local gen = CreateUnitHPR(rawget(_G, 'AB_SHIELDUNIT') or 'ueb4202', brainA.Name, cx, GetTerrainHeight(cx, cz), cz, 0, 0, 0)
                if gen and rawget(_G, 'AB_NOSHIELD') then
                    -- the control for the shield test: the same scene with the shield switched off (FEATAB_NOSHIELD=1)
                    ForkThread(function()
                        WaitSeconds(2)
                        gen:DisableShield()
                    end)
                end
                if gen then
                    -- what the shield is doing, in the log (a shield without energy is down within seconds)
                    ForkThread(function()
                        for i = 1, 12 do
                            WaitSeconds(3)
                            local shield = gen.MyShield
                            Say(string.format('generator: shield %s, up %s, consumed %.2f, energy stock %d, health %s', tostring(shield ~= nil),
                                shield and tostring(shield:IsUp()) or 'n/a', gen:GetResourceConsumed(), brainA:GetEconomyStored('ENERGY'),
                                shield and tostring(shield:GetHealth()) or 'n/a'))
                        end
                    end)
                end
            end
            local ids = { 'ueb1101', 'ueb2101', 'ueb0101', 'ueb2301', 'ueb1103', 'ueb3101' }
            for i = 1, 6 do
                local a = i * math.pi / 3
                local ux, uz = cx + 11 * math.cos(a), cz + 11 * math.sin(a)
                if __blueprints[ids[i]] then
                    CreateUnitHPR(ids[i], brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
                end
            end
            for i = 1, 3 do
                local ux, uz = cx - 6 + i * 6, cz + 3
                CreateUnitHPR('uel0303', brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0.5 * i, 0)
            end
        end
        Group(x0 - 25, z0, true)
        Group(x0 + 25, z0, false)
        Say(string.format('shield scene created, ground height %.2f', GetTerrainHeight(x0, z0)))
        return
    end
    if AB_SCENE == 'shieldwater' then
        -- a shield generator on the bed of a lake (its bubble is over the water) and a second one on dry ground beside it, as the control
        WaitUntil(4)
        KeepPowered()
        local gx, gz = AB_TX, AB_TZ
        local u = CreateUnitHPR('ueb4202', brainA.Name, gx, GetTerrainHeight(gx, gz), gz, 0, 0, 0)
        if u then u:SetCanTakeDamage(false) end
        Say(string.format('shieldwater: generator at %.1f %.1f, ground %.2f, surface %.2f', gx, gz, GetTerrainHeight(gx, gz), GetSurfaceHeight(gx, gz)))
        return
    end
    if AB_SCENE == 'fire' then
        -- weapons of all four factions (tanks, bots, point defence, artillery, the commanders) shoot at tanks of the other army that keep coming back
        local shooters = { 'l0201', 'l0202', 'l0303', 'l0103', 'l0001', 'b2101', 'b2301', 'b2303', 'l0203', 'l0106' }
        local n = 0
        for fi, prefix in FACTIONS do
            for si, sid in shooters do
                local id = prefix .. sid
                if __blueprints[id] then
                    local ux, uz = x0 - 28 + (si - 1) * 4.5, z0 - 24 + (fi - 1) * 9
                    CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, math.pi * 0.5, 0)
                    n = n + 1
                end
            end
        end
        Say(string.format('%d shooters created, ground height %.2f', n, GetTerrainHeight(x0, z0)))
        local targets = {}
        while GetGameTimeSeconds() < 120 do
            local alive = 0
            for _, t in targets do
                if t and not t.Dead then alive = alive + 1 end
            end
            if alive < 8 then
                for i = 1, 8 do
                    local ux, uz = x0 + 16 + math.mod(i, 3) * 4, z0 - 24 + i * 6
                    local u = CreateUnitHPR('uel0201', brainB.Name, ux, GetTerrainHeight(ux, uz), uz, 0, -math.pi * 0.5, 0)
                    if u then table.insert(targets, u) end
                end
            end
            local dead = 0
            for _, t in targets do
                if not t or t.Dead then dead = dead + 1 end
            end
            Say(string.format('targets alive %d, dead %d, total %d', alive, dead, table.getn(targets)))
            WaitSeconds(3)
        end
        return
    end
    if AB_SCENE == 'beam1' then
        -- one spider bot firing at one immortal tank: a single beam and its impact, nothing else
        local shooter = CreateUnitHPR('url0402', brainA.Name, x0, GetTerrainHeight(x0, z0), z0, 0, math.pi * 0.5, 0)
        local ux, uz = x0 + 28, z0
        local target = CreateUnitHPR('uel0201', brainB.Name, ux, GetTerrainHeight(ux, uz), uz, 0, -math.pi * 0.5, 0)
        if target then target:SetCanTakeDamage(false) end
        Say(string.format('beam scene: shooter %s target %s ground %.2f', tostring(shooter and shooter:GetBlueprint().BlueprintId), tostring(target ~= nil), GetTerrainHeight(x0, z0)))
        return
    end
    if AB_SCENE == 'battle' or AB_SCENE == 'battlestill' then
        local still = AB_SCENE == 'battlestill'   -- all immortal, nobody moves: the units keep their places, so frames of different settings compare
        local gap = still and 8 or 18
        -- 40 against 40 mobile units, 30 units apart, attack-moving into each other: tanks, T3 units and experimentals of all factions, half of
        -- them immortal so the fight lasts and the wreckage of the other half builds up
        local ids = { 'uel0201', 'url0202', 'ual0201', 'xsl0201', 'uel0303', 'url0303', 'ual0303', 'xsl0303',
                      'uel0202', 'url0107', 'ual0106', 'xsl0202', 'uel0401', 'url0402', 'ual0401', 'xsl0401' }
        local blue, red = {}, {}
        local count = rawget(_G, 'AB_COUNT') or 40
        for i = 1, count do
            local row, col = math.floor((i - 1) / 8), math.mod(i - 1, 8)
            local ax, az = x0 - gap - row * 4, z0 - 16 + col * 4.5
            local bx, bz = x0 + gap + row * 4, z0 - 16 + col * 4.5
            local a = CreateUnitHPR(ids[math.mod(i - 1, 16) + 1], brainA.Name, ax, GetTerrainHeight(ax, az), az, 0, math.pi * 0.5, 0)
            local b = CreateUnitHPR(ids[math.mod(i + 4, 16) + 1], brainB.Name, bx, GetTerrainHeight(bx, bz), bz, 0, -math.pi * 0.5, 0)
            if a then
                if still or math.mod(i, 2) == 0 then a:SetCanTakeDamage(false) end
                table.insert(blue, a)
            end
            if b then
                if still or math.mod(i, 2) == 1 then b:SetCanTakeDamage(false) end
                table.insert(red, b)
            end
        end
        if not still then
            IssueAggressiveMove(blue, Vector(x0 + 30, GetTerrainHeight(x0 + 30, z0), z0))
            IssueAggressiveMove(red, Vector(x0 - 30, GetTerrainHeight(x0 - 30, z0), z0))
        end
        Say(string.format('battle scene: %d against %d', table.getn(blue), table.getn(red)))
        return
    end
    if AB_SCENE == 'ring' then
        -- twelve spider bots around one immortal tank, all firing at it: the beams meet in one impact
        local ux, uz = x0, z0
        local target = CreateUnitHPR('uel0201', brainB.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
        if target then target:SetCanTakeDamage(false) end
        for i = 1, 12 do
            local a = i * math.pi / 6
            local sx, sz = ux + 26 * math.cos(a), uz + 26 * math.sin(a)
            CreateUnitHPR('url0402', brainA.Name, sx, GetTerrainHeight(sx, sz), sz, 0, a + math.pi, 0)
        end
        Say('ring scene created')
        return
    end
    if AB_SCENE == 'sources' then
        -- one shooter type at a time on the flat start area, firing at an immortal tank 24 units away; then units of different sizes are killed
        local ids = { 'url0402', 'uel0201', 'xel0305', 'xsl0201', 'xsl0202', 'xsl0303', 'uel0303', 'url0303', 'ual0303', 'xsl0305', 'uel0304', 'ual0202' }
        WaitUntil(6)
        Say('SLOT warm up')
        WaitSeconds(5)
        for i, id in ids do
            if __blueprints[id] then
                local s = CreateUnitHPR(id, brainA.Name, x0 - 12, GetTerrainHeight(x0 - 12, z0), z0, 0, math.pi * 0.5, 0)
                local t = CreateUnitHPR('ueb1103', brainB.Name, x0 + 12, GetTerrainHeight(x0 + 12, z0), z0, 0, 0, 0)
                if t then t:SetCanTakeDamage(false) end
                if s and t then IssueAttack({ s }, t) end
                Say(string.format('SLOT shoot %s', id))
                WaitSeconds(2)
                local w = s and s:GetWeapon(1)
                Say(string.format('weapon %s target %s unitsOK %s', id, tostring(w and w:GetCurrentTarget() ~= nil), tostring(s ~= nil and not s.Dead)))
                WaitSeconds(7)
                if s then s:Destroy() end
                if t then t:Destroy() end
                WaitSeconds(1.5)
            end
        end
        local dying = { 'uel0201', 'url0402', 'xsl0201', 'uel0303', 'uel0401', 'xsl0303', 'xel0305', 'xsb2301', 'uab2305' }
        for i, id in dying do
            if __blueprints[id] then
                local u = CreateUnitHPR(id, brainA.Name, x0, GetTerrainHeight(x0, z0), z0, 0, 0, 0)
                WaitSeconds(1)
                Say(string.format('SLOT dies %s', id))
                if u then u:Kill() end
                WaitSeconds(6)
                if u and not u.Dead then u:Destroy() end
            end
        end
        Say('SLOT end')
        return
    end
    if AB_SCENE == 'colossus' then
        -- one big walker (AB_SHOOTER from FEATAB_SHOOTER, default the Galactic Colossus) shooting at an immortal building 24 units away
        WaitUntil(4)
        local id = rawget(_G, 'AB_SHOOTER') or 'ual0401'
        local s = CreateUnitHPR(id, brainA.Name, x0 - 12, GetTerrainHeight(x0 - 12, z0), z0, 0, math.pi * 0.5, 0)
        local t = CreateUnitHPR('ueb1103', brainB.Name, x0 + 12, GetTerrainHeight(x0 + 12, z0), z0, 0, 0, 0)
        if t then t:SetCanTakeDamage(false) end
        if s and t then IssueAttack({ s }, t) end
        Say(string.format('colossus scene: %s %s ground %.2f', id, tostring(s ~= nil), GetTerrainHeight(x0, z0)))
        WaitSeconds(300)
        return
    end
    if AB_SCENE == 'shadow' then
        -- a steady light 3 units above the ground, with a heavy unit, a building and two tanks around it: what they shade is what the test shows
        WaitUntil(3)
        local lx, lz = x0, z0
        local ly = GetTerrainHeight(lx, lz) + 3
        local others = {
            { 'uel0303', lx + 4, lz + 0.5, 0 }, { 'ueb0101', lx - 6, lz + 1, 0 }, { 'url0402', lx + 1, lz - 5, 0 }, { 'uel0201', lx - 1, lz + 5, 0 },
        }
        for _, o in others do
            if __blueprints[o[1]] then
                CreateUnitHPR(o[1], brainA.Name, o[2], GetTerrainHeight(o[2], o[3]), o[3], 0, o[4], 0)
            end
        end
        Say(string.format('shadow scene: light at %.1f %.1f %.1f', lx, ly, lz))
        -- a Lua light: constant while it lives (the particle flash of the first version faded between the frames that were compared)
        local Light = import('/fafengine/lua/dynlights/light.lua')
        local lamp = Light.Create(nil, nil, 1.0, 0.7, 0.4, 24, 6)
        lamp:SetPosition(lx, ly, lz)
        WaitSeconds(300)
        return
    end
    if AB_SCENE == 'lightdisc' then
        -- long-lived light particles of different sizes at known places; the footprint of each should be a smooth disc
        WaitUntil(4)
        local sizes = AB_SIZES or { 6, 14, 30 }
        local anchors = {}
        for i = 1, table.getn(sizes) do
            local ux, uz = x0 - 50 + (i - 1) * 24, z0
            local u = CreateUnitHPR('ueb1101', brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
            table.insert(anchors, u)
        end
        for round = 1, 20 do
            for i = 1, table.getn(sizes) do
                if anchors[i] and not anchors[i].Dead then
                    CreateLightParticle(anchors[i], -1, brainA:GetArmyIndex(), sizes[i], 150, 'glow_03', 'ramp_flare_02')
                end
            end
            WaitSeconds(14)
        end
        return
    end
    if AB_SCENE == 'water' then
        -- hover tanks and a few structures on and around the lake at (AB_TX, AB_TZ): the mirrored pass draws what stands on the water
        WaitUntil(4)
        local ids = { 'uel0203', 'url0203', 'ual0203', 'xsl0203', 'uel0203', 'url0203', 'ual0203', 'xsl0203' }
        for i = 1, 8 do
            local a = i * math.pi / 4
            local r = 6 + 4 * math.mod(i, 2)
            local ux, uz = AB_TX + r * math.cos(a), AB_TZ + r * math.sin(a)
            if __blueprints[ids[i]] then
                CreateUnitHPR(ids[i], brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, a, 0)
            end
        end
        for i = 1, 6 do
            local ux, uz = AB_TX - 30 + i * 10, AB_TZ + 24
            local id = ({ 'ueb2101', 'uab2101', 'urb2101', 'xsb2101', 'ueb1101', 'uab1101' })[i]
            if __blueprints[id] then
                CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
            end
        end
        Say('water scene created')
        return
    end
    if AB_SCENE == 'smoke' then
        -- hover tanks and structures on and around the lake at (AB_TX, AB_TZ), then a strategic missile onto the shore
        WaitUntil(4)
        local ids = { 'uel0203', 'url0203', 'ual0203', 'xsl0203', 'uel0203', 'url0203', 'ual0203', 'xsl0203' }
        for i = 1, 8 do
            local a = i * math.pi / 4
            local r = 6 + 4 * math.mod(i, 2)
            local ux, uz = AB_TX + r * math.cos(a), AB_TZ + r * math.sin(a)
            if __blueprints[ids[i]] then
                CreateUnitHPR(ids[i], brainA.Name, ux, GetSurfaceHeight(ux, uz), uz, 0, a, 0)
            end
        end
        for i = 1, 6 do
            local ux, uz = AB_TX - 30 + i * 10, AB_TZ + 24
            local id = ({ 'ueb2101', 'uab2101', 'urb2101', 'xsb2101', 'ueb1101', 'uab1101' })[i]
            if __blueprints[id] then
                CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
            end
        end
        Say('smoke scene created')
        WaitUntil(12)
        local launcher = CreateUnitHPR('xsb2305', brainB.Name, x0 + 60, GetTerrainHeight(x0 + 60, z0), z0, 0, 0, 0)
        if launcher then
            launcher:GiveNukeSiloAmmo(1)
            local nx, nz = AB_TX + 10, AB_TZ + 50
            IssueNuke({ launcher }, { nx, GetSurfaceHeight(nx, nz), nz })
            Say(string.format('nuke launched at %.1f %.1f', nx, nz))
        end
        return
    end
    if AB_SCENE == 'nuke' then
        WaitUntil(10)
        local launcher = CreateUnitHPR('xsb2305', brainB.Name, x0 + 60, GetTerrainHeight(x0 + 60, z0), z0, 0, 0, 0)
        if launcher then
            launcher:GiveNukeSiloAmmo(1)
            IssueNuke({ launcher }, { AB_TX, GetSurfaceHeight(AB_TX, AB_TZ), AB_TZ })
            Say(string.format('nuke launched at %.1f %.1f', AB_TX, AB_TZ))
        end
    end
end)
