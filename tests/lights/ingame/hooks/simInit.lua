-- Test hook (not part of the engine data; append it to the engine folder's copy of this file, see docs/DYNAMIC_LIGHTS.md, "Tests"): appended to /lua/simInit.lua.
--
-- Runs an optional test script after the session has begun: if the file /fafengine/lua/test/dynlights_test.lua exists it is executed in
-- the sim (it forks its own threads). The file is not part of the engine (tests/lights/ingame/ in the repository holds it, copy it to
-- <exe folder>/fafengine/lua/test/ to use it), so on a normal install nothing happens and the check is one file lookup.

do
    local oldBeginSession = BeginSession

    function BeginSession()
        oldBeginSession()

        local testScript = '/fafengine/lua/test/dynlights_test.lua'
        if DiskGetFileInfo(testScript) then
            doscript(testScript)
        end
    end
end
