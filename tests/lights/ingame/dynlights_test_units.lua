-- In-game test of the lights that belong to entities (docs/DYNAMIC_LIGHTS.md, "In-game tests"): unit emission read from the unit textures, a
-- Lua light on a bone of the commander, and a headlight on a vehicle. Copy this file as
-- <exe folder>/fafengine/lua/test/dynlights_test.lua (the name the sim hook looks for) instead of dynlights_test.lua to run it.
--
--   t = 18 s   units appear in two rows around the commander: Aeon Harbinger, Aeon T3 power, UEF T3 power, Seraphim T3 power, Cybran PD
--   t = 20 s   a UEF tank with a headlight, the commander with a blue bone light
--   t = 46 s   everything is destroyed: the quiet frames after it are the control
--   t = 60 s   done

local Light = import('/fafengine/lua/dynlights/light.lua')

-- the commander's blue bone light is a separate test: with it on, its glow covers the area the headlight lights
local WITH_COMMANDER_LIGHT = false

local function Say(text)
    LOG(string.format('DYNLIGHT-TEST: [%.1f s] %s', GetGameTimeSeconds(), text))
end

local function WaitUntil(seconds)
    while GetGameTimeSeconds() < seconds do
        WaitTicks(2)
    end
end

ForkThread(function()
    local brain = ArmyBrains[1]
    local x0, z0 = brain:GetArmyStartPos()
    Say(string.format('start position (%.2f, %.2f)', x0, z0))

    WaitUntil(18)
    local spawned = {}
    local function Spawn(bp, dx, dz, yaw)
        local x, z = x0 + dx, z0 + dz
        local y = GetTerrainHeight(x, z)
        local unit = CreateUnitHPR(bp, brain.Name, x, y, z, 0, yaw or 0, 0)  -- the engine order is pitch, yaw, roll
        if unit then
            table.insert(spawned, unit)
            Say(string.format('unit %s at (%.2f, %.2f, %.2f)', bp, x, y, z))
        else
            Say('could not create ' .. bp)
        end
        return unit
    end
    Spawn('ual0303', -14, -12)
    Spawn('uab1301', -2, -12)
    Spawn('ueb1301', 10, -12)
    Spawn('xsb1301', -14, 10)
    Spawn('urb2301', 14, 10)

    WaitUntil(20)
    local tank = Spawn("uel0201", -12, 4, math.pi * 0.5)
    local head
    if tank then
        head = Light.Headlight(tank)
        Say(string.format('headlight on the tank (default: rgb 1.0 0.93 0.75, radius 40, intensity 1.2, cone 32), tank has %d bones', tank:GetBoneCount()))
    end

    local acu = brain:GetListOfUnits(categories.COMMAND, false)[1]
    local lamp
    if acu and WITH_COMMANDER_LIGHT then
        lamp = Light.Create(acu, -1, 0.3, 0.6, 1.0, 14, 1.0)
        lamp:SetOffset(0, 4, 0)
        Say('commander bone light: rgb (0.3 0.6 1.0) radius 14 intensity 1.0 offset (0 4 0)')
    end

    WaitUntil(46)
    if lamp then
        Say('destroy the commander light -> ' .. tostring(lamp:Destroy()))
    end
    if head then
        Say('destroy the headlight -> ' .. tostring(head:Destroy()))
    end
    for _, unit in spawned do
        unit:Destroy()
    end
    Say('units destroyed')

    WaitUntil(60)
    Say('done')
end)
