-- Engine hook on /lua/SimCallbacks.lua (appended to FAF's file).
--
-- The changelog preview's Restart: the scene built again, only in a preview session.

Callbacks.FafrePreviewRestart = function(data, units)
    local options = ScenarioInfo.Options or {}
    if type(options.FafrePreview) == 'table' then
        import('/fafengine/modules/lua/sim/unitpreview.lua').Restart()
    end
end
