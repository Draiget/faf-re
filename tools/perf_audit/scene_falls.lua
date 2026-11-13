-- River falls scene (sim side, run by the test hook of simInit.lua): moves the commanders out of view and prints the water surface
-- along river A of the faf_re_waterrivers map (above and below the fall at (130, 76)) so a log shows the sloped levels.
local function Say(text) LOG(string.format('FALLS: [%.1f s] %s', GetGameTimeSeconds(), text)) end
ForkThread(function()
    WaitTicks(5)
    for _, brain in ArmyBrains do
        for _, u in brain:GetListOfUnits(categories.COMMAND, false) do
            local fx, fz = 240, 240
            Warp(u, Vector(fx, GetTerrainHeight(fx, fz), fz))
        end
    end
    local pts = { {100, 60}, {120, 71}, {130, 76}, {140, 79}, {162, 86} }
    for _, p in pts do
        Say(string.format('surface at %d %d: %.2f terrain %.2f', p[1], p[2], GetSurfaceHeight(p[1], p[2]), GetTerrainHeight(p[1], p[2])))
    end
    Say('scene ready')
end)
