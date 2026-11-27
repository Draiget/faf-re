-- Engine hook on /lua/UserSync.lua (appended to FAF's file).
--
-- The changelog preview's scene (Sync.FafrePreviewScene: the two copies' entity ids and ranges) reaches its overlay,
-- which draws their range rings. Only a preview session's sim sends it.

do
    local previewOnSync = OnSync
    function OnSync()
        previewOnSync()
        if Sync.FafrePreviewScene then
            local ok, why = pcall(function()
                import('/fafengine/modules/lua/ui/game/unitpreview.lua').OnScene(Sync.FafrePreviewScene)
            end)
            if not ok then
                WARN('UNIT PREVIEW: ' .. tostring(why))
            end
        end
    end
end
