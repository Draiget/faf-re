-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered
-- as a hook directory): appended to /lua/ui/game/gamemain.lua.
--
-- A replay gets the timeline bar. The engine's own modules lie under /fafengine/modules, a
-- path no FAF file has, so they are never taken as hooks of FAF's files. FAF's Lua may
-- carry the timeline itself (issue #327, /lua/ui/game/replay_timeline.lua); its own
-- CreateUI then makes the bar, so this doesn't.

if not DiskGetFileInfo('/lua/ui/game/replay_timeline.lua') then
    local OldCreateUI = CreateUI
    function CreateUI(isReplay)
        OldCreateUI(isReplay)
        if isReplay then
            import('/fafengine/modules/lua/ui/game/replay_timeline.lua').Create()
        end
    end
end
