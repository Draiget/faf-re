-- Engine hook on /lua/simInit.lua (appended to FAF's file).
--
-- The launcher's changelog preview starts a sandbox skirmish with the game option FafrePreview (the unit and its
-- changed values); the scene is built once the session has begun. Any other game is untouched.

do
    local beginSession = BeginSession
    function BeginSession()
        beginSession()
        local options = ScenarioInfo.Options or {}
        if type(options.FafrePreview) == 'table' then
            ForkThread(import('/fafengine/modules/lua/sim/unitpreview.lua').Run, options.FafrePreview)
        end
    end
end
