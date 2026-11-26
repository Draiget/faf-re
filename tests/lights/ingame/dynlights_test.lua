-- In-game test of the dynamic lights (docs/DYNAMIC_LIGHTS.md, "In-game tests"). Not part of the engine: copy this file to
-- <exe folder>/fafengine/lua/test/dynlights_test.lua; the hook tests/lights/ingame/hooks/simInit.lua (appended to <exe folder>/fafengine/lua/simInit.lua) runs it in the sim after the session began.
--
-- A fixed scene around the first army's commander. Every phase is bracketed by quiet time (no light of the script) so a frame of the phase can
-- be compared with a frame of the quiet time before or after it (analyze.py): the camera stands still after the commander has landed.
-- Every step writes a line starting with DYNLIGHT-TEST to the log with the game time, the world position and the colour / strength given.
-- Positions are relative to the start position (x0, z0): the camera starts centred there, about 45 units wide.
--
--   t = 22 s   A  static point lights: red / green / blue, white at intensity 0.25 / 0.5 / 1.0, orange / cyan / magenta
--   t = 34 s      all of them destroyed (light:Destroy())
--   t = 42 s   C  light particles (CreateLightParticle) with five ramps, every 3 s, until t = 54 s
--   t = 60 s   D  two beams between dummy entities, until t = 72 s
--   t = 78 s   E  a bone light and a headlight on the commander, until t = 90 s
--   t = 96 s   F  forty static lights on a grid (the old limit was 16 on units / 28 on terrain), until t = 108 s
--   t = 112 s     done

local Light = import('/fafengine/lua/dynlights/light.lua')
local Entity = import('/lua/sim/entity.lua').Entity

local function Say(text)
    LOG(string.format('DYNLIGHT-TEST: [%.1f s] %s', GetGameTimeSeconds(), text))
end

local function Dummy(x, y, z)
    local e = Entity({ Owner = nil })
    e:SetPosition(Vector(x, y, z), true)
    return e
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

    local function Static(dx, dz, r, g, b, radius, intensity, name, height)
        local x, z = x0 + dx, z0 + dz
        local y = GetTerrainHeight(x, z) + (height or 4)
        local light = Light.Create(nil, nil, r, g, b, radius, intensity)
        light:SetPosition(x, y, z)
        Say(string.format('static %s at (%.2f, %.2f, %.2f) rgb (%.2f %.2f %.2f) radius %.1f intensity %.2f', name, x, y, z, r, g, b, radius, intensity))
        return light
    end

    -- ---- A: static point lights
    WaitUntil(22)
    local statics = {}
    statics[1] = Static(-10, -8, 1, 0, 0, 7, 1.0, 'red')
    statics[2] = Static(0, -8, 0, 1, 0, 7, 1.0, 'green')
    statics[3] = Static(10, -8, 0, 0, 1, 7, 1.0, 'blue')
    statics[4] = Static(-10, 8, 1, 1, 1, 7, 0.25, 'white 0.25')
    statics[5] = Static(0, 8, 1, 1, 1, 7, 0.5, 'white 0.5')
    statics[6] = Static(10, 8, 1, 1, 1, 7, 1.0, 'white 1.0')
    statics[7] = Static(-10, 16, 1.0, 0.6, 0.2, 9, 0.8, 'orange')
    statics[8] = Static(0, 16, 0.2, 0.8, 1.0, 9, 0.8, 'cyan')
    statics[9] = Static(10, 16, 1.0, 0.2, 0.8, 9, 0.8, 'magenta')

    WaitUntil(34)
    for i, light in statics do
        Say('destroy static ' .. i .. ' -> ' .. tostring(light:Destroy()))
    end

    -- ---- C: light particles with five ramps
    WaitUntil(42)
    local flashes = {
        { dx = -16, dz = -4, ramp = 'ramp_blue_01' },
        { dx = -8, dz = -4, ramp = 'ramp_aeon_01' },
        { dx = 0, dz = -4, ramp = 'ramp_antimatter_02' },
        { dx = 8, dz = -4, ramp = 'ramp_flare_01' },
        { dx = 16, dz = -4, ramp = 'ramp_disintegrator_01' },
    }
    local anchors = {}
    for i, f in flashes do
        local x, z = x0 + f.dx, z0 + f.dz
        anchors[i] = Dummy(x, GetTerrainHeight(x, z) + 3, z)
    end
    while GetGameTimeSeconds() < 54 do
        for i, f in flashes do
            CreateLightParticle(anchors[i], -1, 1, 6, 30, 'glow_03', f.ramp)
        end
        Say('light particles: glow_03 with ramps blue_01 aeon_01 antimatter_02 flare_01 disintegrator_01, size 6, lifetime 30, row z0-4, x0-16..x0+16 step 8')
        WaitSeconds(3)
    end

    -- ---- D: beams
    WaitUntil(60)
    local beams = {}
    local function Beam(dx0, dz0, dx1, dz1, bp)
        local ax, az = x0 + dx0, z0 + dz0
        local bx, bz = x0 + dx1, z0 + dz1
        local a = Dummy(ax, GetTerrainHeight(ax, az) + 2, az)
        local b = Dummy(bx, GetTerrainHeight(bx, bz) + 2, bz)
        local beam = AttachBeamEntityToEntity(a, -1, b, -1, 1, bp)
        Say(string.format('beam %s from (%.2f, %.2f) to (%.2f, %.2f)', bp, ax, az, bx, bz))
        return beam
    end
    beams[1] = Beam(-18, 6, -4, 6, '/effects/emitters/laserturret_munition_beam_01_emit.bp')
    beams[2] = Beam(4, 6, 18, 6, '/effects/emitters/microwave_laser_beam_02_emit.bp')
    WaitUntil(72)
    for i, beam in beams do
        beam:Destroy()
        Say('beam ' .. i .. ' destroyed')
    end

    -- ---- E: the commander: a bone light and a headlight
    WaitUntil(78)
    local acu = brain:GetListOfUnits(categories.COMMAND, false)[1]
    local lamp, head
    if acu then
        Say(string.format('commander %s with %d bones', acu.UnitId, acu:GetBoneCount()))
        lamp = Light.Create(acu, -1, 0.3, 0.6, 1.0, 14, 1.0)
        lamp:SetOffset(0, 4, 0)
        Say('commander bone light: rgb (0.3 0.6 1.0) radius 14 intensity 1.0 offset (0 4 0)')
        head = Light.Headlight(acu)
        Say('commander headlight (default: rgb 1.0 0.93 0.75, radius 40, intensity 1.2, cone 32)')
    else
        Say('no commander found')
    end
    WaitUntil(90)
    if lamp then
        Say('destroy commander lights -> ' .. tostring(lamp:Destroy()) .. ' ' .. tostring(head:Destroy()))
    end

    -- ---- F: forty lights at once
    WaitUntil(96)
    local many = {}
    local n = 0
    for gx = -4, 3 do
        for gz = -2, 2 do
            n = n + 1
            local dx, dz = gx * 5 + 2.5, gz * 5
            local x, z = x0 + dx, z0 + dz
            local light = Light.Create(nil, nil, 0.3 + 0.7 * math.mod(n, 3) / 2, 0.3 + 0.7 * math.mod(n + 1, 3) / 2, 0.3 + 0.7 * math.mod(n + 2, 3) / 2, 4, 0.8)
            light:SetPosition(x, GetTerrainHeight(x, z) + 2, z)
            many[n] = light
        end
    end
    Say(string.format('%d static lights (radius 4, intensity 0.8) on a 5-unit grid around the start position', n))
    WaitUntil(108)
    for _, light in many do
        light:Destroy()
    end
    Say('many lights destroyed')

    WaitUntil(112)
    Say('done')
end)
