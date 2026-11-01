--*****************************************************************************
--* File: data/fafengine/lua/ui/game/gamemain.lua
--* Summary: Engine hook for in-game replay timeline bar and scrubbing overlay
--*
--* Hook: appended to /lua/ui/game/gamemain.lua.
--*****************************************************************************

do
    local function is_callable(fn)
        local t = type(fn)
        return t == 'function' or t == 'cfunction'
    end

    local function InitReplayTimeline(isReplayParam)
        local isReplaySession = false
        if isReplayParam != nil then
            isReplaySession = isReplayParam
        elseif is_callable(SessionIsReplay) then
            local ok, val = pcall(SessionIsReplay)
            if ok and val then
                isReplaySession = true
            end
        elseif is_callable(GetReplayState) then
            local ok, val = pcall(GetReplayState)
            if ok and val then
                isReplaySession = true
            end
        end

        LOG("FAFENGINE: InitReplayTimeline check: isReplaySession=" .. tostring(isReplaySession))

        if not isReplaySession then
            return
        end

        local ok, timeline = pcall(import, '/mods/fafengine/lua/ui/game/replay_timeline.lua')
        if not ok or not timeline or not timeline.CreateReplayTimeline then
            ok, timeline = pcall(import, '/lua/ui/game/replay_timeline.lua')
        end
        if not ok or not timeline or not timeline.CreateReplayTimeline then
            ok, timeline = pcall(import, '/mods/FAFEngine/modules/replay_timeline.lua')
        end

        if ok and timeline and timeline.CreateReplayTimeline then
            if not timeline.GetTimelineControl() then
                LOG("FAFENGINE: Calling CreateReplayTimeline")
                timeline.CreateReplayTimeline(GetFrame(0))
            end
        else
            LOG("FAFENGINE: Failed to load replay_timeline.lua: ok=" .. tostring(ok) .. ", timeline=" .. tostring(timeline))
        end
    end

    local OldCreateUI = CreateUI
    function CreateUI(isReplayParam)
        OldCreateUI(isReplayParam)
        InitReplayTimeline(isReplayParam)
    end

    local OldOnFirstUpdate = OnFirstUpdate
    function OnFirstUpdate()
        OldOnFirstUpdate()
        InitReplayTimeline()
    end
end
