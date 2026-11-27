

-- Test hook (not part of the engine): runs /fafengine/lua/test/ev_sim.lua in the sim after BeginSession when it exists.
do
    local oldBeginSession = BeginSession

    function BeginSession()
        oldBeginSession()

        local script = '/fafengine/lua/test/ev_sim.lua'
        if DiskGetFileInfo(script) then
            doscript(script)
        end
    end
end
