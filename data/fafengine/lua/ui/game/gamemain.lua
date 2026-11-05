-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered
-- as a hook directory): appended to /lua/ui/game/gamemain.lua.
--
-- A replay gets the timeline bar. A file that isn't a hook lies under the mount,
-- so it is imported by that path.

do
    local OldCreateUI = CreateUI
    function CreateUI(isReplay)
        OldCreateUI(isReplay)
        if isReplay then
            import('/fafengine/lua/ui/game/replay_timeline.lua').Create()
        end
    end
end
