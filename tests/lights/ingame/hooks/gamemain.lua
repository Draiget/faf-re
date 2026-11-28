-- Test hook (not part of the engine data; append it to the engine folder's copy of this file, see docs/DYNAMIC_LIGHTS.md, "Tests"): appended to /lua/ui/game/gamemain.lua.
--
-- Runs an optional test script in the user interface after CreateUI: if /fafengine/lua/test/dynlights_camera.lua exists it is executed (it
-- zooms the camera out for the light tests). The file is not part of the engine, so on a normal install nothing happens and the check is one
-- file lookup.

do
    local oldCreateUI = CreateUI

    function CreateUI(isReplay)
        oldCreateUI(isReplay)

        local script = '/fafengine/lua/test/dynlights_camera.lua'
        if DiskGetFileInfo(script) then
            doscript(script)
        end
    end
end
