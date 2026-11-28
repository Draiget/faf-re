-- Census scene for structures, build effects, shields and a nuke (docs/DYNAMIC_LIGHTS.md, "Census"). Not part of the engine: copy this file as
-- <exe folder>/fafengine/lua/test/dynlights_test.lua and dynlights_camera.lua next to it, start a skirmish with
-- /con "ren_DynLights=4;ren_DynLightsCensus=900;ren_DynLightsLog=60".
--
--   t = 10 s   structures of the four factions in a grid in front of the camera (factories, power, mass, radar, shields, defences, artillery)
--   t = 25 s   engineers of each faction build a few more structures (build beams, build effects)
--   t = 70 s   the mass fabricators, shields and artillery are shot at by a few units (impacts, shield hits, sparks)
--   t = 110 s  a strategic missile launcher fires at the middle of the grid (the nuke's own light)
--   t = 160 s  done

local function Say(text)
    LOG(string.format('DYNLIGHT-TEST: [%.1f s] %s', GetGameTimeSeconds(), text))
end

local function WaitUntil(seconds)
    while GetGameTimeSeconds() < seconds do
        WaitTicks(5)
    end
end

local FACTIONS = {
    { prefix = 'ue', name = 'UEF' },
    { prefix = 'ua', name = 'Aeon' },
    { prefix = 'ur', name = 'Cybran' },
    { prefix = 'xs', name = 'Seraphim' },
}

-- the third and fourth letter of a structure id are 'b0'..'b4'; the rest is the number of the building
local STRUCTURES = {
    '0101', '0102', '1101', '1102', '1103', '1104', '1201', '1301', '3101', '3201', '4202', '4301', '2101', '2104', '2301', '2302', '2305',
}

ForkThread(function()
    local brainA, brainB = ArmyBrains[1], ArmyBrains[2]
    local x0, z0 = brainA:GetArmyStartPos()
    SetAlliance(1, 2, 'Enemy')
    SetAlliance(2, 1, 'Enemy')
    Say(string.format('start position (%.1f, %.1f)', x0, z0))

    WaitUntil(10)
    local created, failed = 0, 0
    local all = {}
    for fi, faction in FACTIONS do
        for si, number in STRUCTURES do
            local id = faction.prefix .. 'b' .. number
            local ux = x0 - 40 + (si - 1) * 5
            local uz = z0 - 30 + (fi - 1) * 12
            local unit = nil
            if __blueprints[id] then
                unit = CreateUnitHPR(id, brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
            end
            if unit then
                created = created + 1
                table.insert(all, unit)
            else
                failed = failed + 1
                Say('no unit ' .. id)
            end
        end
    end
    Say(string.format('%d structures created, %d failed', created, failed))
    brainA:GiveResource('Energy', 100000)
    brainA:GiveResource('Mass', 100000)

    WaitUntil(25)
    local engineers = {}
    for fi, faction in FACTIONS do
        local ux, uz = x0 - 40 + (fi - 1) * 8, z0 + 10
        local engineer = nil
        if __blueprints[faction.prefix .. 'l0105'] then
            engineer = CreateUnitHPR(faction.prefix .. 'l0105', brainA.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0)
        end
        if engineer then
            local bx, bz = ux, uz + 12
            IssueBuildMobile({ engineer }, { bx, GetTerrainHeight(bx, bz), bz }, faction.prefix .. 'b1103', {})
            IssueBuildMobile({ engineer }, { bx + 6, GetTerrainHeight(bx + 6, bz), bz }, faction.prefix .. 'b2101', {})
            table.insert(engineers, engineer)
        end
    end
    Say(string.format('%d engineers building', table.getn(engineers)))

    WaitUntil(70)
    local attackers = {}
    for fi, faction in FACTIONS do
        local ux, uz = x0 + 30, z0 - 25 + (fi - 1) * 12
        local unit = nil
        if __blueprints[faction.prefix .. 'l0202'] then
            unit = CreateUnitHPR(faction.prefix .. 'l0202', brainB.Name, ux, GetTerrainHeight(ux, uz), uz, 0, -math.pi * 0.5, 0)
        end
        if unit then
            table.insert(attackers, unit)
            IssueAggressiveMove({ unit }, { x0 - 20, GetTerrainHeight(x0 - 20, uz), uz })
        end
    end
    Say(string.format('%d attackers sent', table.getn(attackers)))

    WaitUntil(110)
    local launcher = nil
    if __blueprints['xsb2305'] then
        launcher = CreateUnitHPR('xsb2305', brainB.Name, x0 + 60, GetTerrainHeight(x0 + 60, z0), z0, 0, 0, 0)
    end
    if launcher then
        launcher:GiveNukeSiloAmmo(1)
        IssueNuke({ launcher }, { x0 - 10, GetTerrainHeight(x0 - 10, z0 - 5), z0 - 5 })
        Say('nuke launched')
    end

    WaitUntil(160)
    Say('done')
end)
