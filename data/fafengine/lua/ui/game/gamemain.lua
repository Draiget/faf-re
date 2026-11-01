--*****************************************************************************
--* File: data/fafengine/lua/ui/game/gamemain.lua
--* Summary: Engine hook for in-game replay timeline bar and scrubbing overlay
--*
--* Engine hook (data/fafengine, mounted by the engine at /fafengine and
--* registered as a hook directory): appended to /lua/ui/game/gamemain.lua.
--*****************************************************************************

do
    local function InitReplayTimeline()
        local isReplaySession = false
        if rawget(_G, 'SessionIsReplay') then
            isReplaySession = SessionIsReplay()
        elseif rawget(_G, 'isReplay') then
            isReplaySession = isReplay
        end

        if not isReplaySession then
            return
        end

        local ok, timeline = pcall(import, '/fafengine/lua/ui/game/replay_timeline.lua')
        if not ok or not timeline or not timeline.CreateReplayTimeline then
            ok, timeline = pcall(import, '/lua/ui/game/replay_timeline.lua')
        end

        if ok and timeline and timeline.CreateReplayTimeline then
            if not timeline.GetTimelineControl() then
                local parent = (controls and controls.gameParent) or GetFrame(0)
                timeline.CreateReplayTimeline(parent)
            end
        end
    end

    local OldCreateUI = CreateUI
    function CreateUI(isReplayParam)
        OldCreateUI(isReplayParam)
        InitReplayTimeline()
    end

    local OldOnFirstUpdate = OnFirstUpdate
    function OnFirstUpdate()
        OldOnFirstUpdate()
        InitReplayTimeline()
    end
end
