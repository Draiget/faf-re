-- Shadow filter test scene (private copy, not part of the repository): a row of units, structures, a wall and air units around the start
-- position, flat-ish ground, in front of the camera. The UI script (dynlights_camera.lua) pauses the game and cycles ren_ShadowQuality.
local function Say(text)
    LOG(string.format('SHADOW-TEST: [%.1f s] %s', GetGameTimeSeconds(), text))
end

local function WaitUntil(seconds)
    while GetGameTimeSeconds() < seconds do
        WaitTicks(5)
    end
end

ForkThread(function()
    local brainA = ArmyBrains[1]
    local x0, z0 = brainA:GetArmyStartPos()
    Say(string.format('start position (%.1f, %.1f)', x0, z0))
    WaitUntil(2)
    local function make(id, x, z, heading, air)
        if not __blueprints[id] then Say('no unit ' .. id) return nil end
        local y = GetTerrainHeight(x, z)
        if air then y = y + air end
        return CreateUnitHPR(id, brainA.Name, x, y, z, 0, heading or 0, 0)
    end
    -- the commander's start position is crowded: put the scene to the east of it
    -- close-up: the commander in the middle, units and a wall around it (the shadows fall to the upper left)
    make('url0303', x0 - 4.5, z0 + 4.5, math.pi * 0.25)
    make('xsl0303', x0 + 4.5, z0 + 4.5, math.pi * 0.75)
    make('uel0201', x0 - 1.0, z0 + 4.8, 0)
    make('ual0201', x0 + 1.0, z0 + 4.8, 0)
    make('ueb2301', x0 + 7, z0 + 1, 0)
    make('xsb2301', x0 - 7, z0 + 1.5, 0)
    for i = 0, 3 do
        make('ueb5101', x0 - 1.5 + i * 1.0, z0 + 2.2, 0)
    end
    make('uea0305', x0 - 1, z0 - 0.5, 0, 5)
    Say('scene built')
end)
