-- ev_camera.lua body. The runner prepends a header: EV_PAUSE_AT (game seconds), EV_SPEED, EV_HIDE_UI, EV_SCENES = { { name, {x,y,z}, {heading, pitch}, zoom, { console commands }, hold }, ... }
-- Each scene: snap the camera, run its commands, log "EV: scene <name>", hold. The runner maps the log lines to the frame dumps.
ForkThread(function()
    WaitSeconds(6)
    if EV_TICK then
        ReplaySeek(EV_TICK)
        WaitSeconds(2)
        local n = 0
        while ReplaySeekProgress() and n < 600 do WaitSeconds(0.5) n = n + 1 end
        LOG('EV: seek done at game second ' .. GetGameTimeSeconds())
    elseif EV_SPEED and EV_SPEED > 1 then
        SetGameSpeed(EV_SPEED)
        while GetGameTimeSeconds() < EV_PAUSE_AT do WaitSeconds(0.1) end
    end
    SessionRequestPause()
    SetGameSpeed(1)
    WaitSeconds(1)
    LOG('EV: paused at game second ' .. GetGameTimeSeconds())
    if EV_HIDE_UI then import('/lua/ui/game/gamemain.lua').HideGameUI('hide') end
    WaitSeconds(rawget(_G, 'EV_SETTLE') or 3)
    local camera = GetCamera('WorldCamera')
    for i, s in EV_SCENES do
        local pos = s[2]
        if pos == 'center' then
            local sz = SessionGetScenarioInfo().size
            pos = { sz[1] / 2, 0, sz[2] / 2 }
        end
        if camera and pos then
            camera:SnapTo(pos, { s[3][1], s[3][2], 0 }, s[4])
        end
        WaitSeconds(2)
        for _, cmd in (s[5] or {}) do ConExecute(cmd) end
        LOG('EV: scene ' .. i .. ' ' .. s[1])
        WaitSeconds(s[6] or 5)
    end
    LOG('EV: done')
end)



