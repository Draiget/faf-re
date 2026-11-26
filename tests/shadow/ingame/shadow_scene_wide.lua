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
    local row1 = { 'uel0201', 'ual0201', 'url0107', 'xsl0201', 'uel0303', 'ual0303', 'url0303', 'xsl0303' }
    for i = 1, table.getn(row1) do
        make(row1[i], x0 - 10 + (i - 1) * 2.5, z0 + 4, math.pi * 0.25)
    end
    local row2 = { 'ueb2101', 'ueb2301', 'uab2301', 'urb2301', 'xsb2301', 'ueb1101', 'uab1101', 'urb1101' }
    for i = 1, table.getn(row2) do
        make(row2[i], x0 - 10 + (i - 1) * 3.4, z0 + 8, 0)
    end
    for i = 0, 11 do
        make('ueb5101', x0 - 12 + i * 1.0, z0 - 5, 0)
    end
    make('uea0305', x0 - 8, z0 - 2, 0, 6)
    make('uea0203', x0 - 3, z0 - 3, 0, 9)
    make('uaa0310', x0 + 12, z0 - 4, 0, 20)
    Say('scene built')
end)
