-- Camera for the in-game light tests: zooms the world camera out so a battle of 100 units across fits the screen. Not part of the engine: copy
-- to <exe folder>/fafengine/lua/test/dynlights_camera.lua; the hook tests/lights/ingame/hooks/gamemain.lua (appended to <exe folder>/fafengine/lua/ui/game/gamemain.lua) runs it in the user interface after
-- CreateUI (if the file is absent nothing happens).

ForkThread(function()
    WaitSeconds(8)
    local camera = GetCamera('WorldCamera')
    if camera then
        camera:SetZoom(90, 1.0)
        LOG('DYNLIGHT-TEST: camera zoom set to 90')
    end
end)
