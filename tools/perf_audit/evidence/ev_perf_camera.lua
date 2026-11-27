-- measurement run: seek, snap the camera, run EV_MEASURE seconds with the game running (the render profile windows of the runner follow)
ForkThread(function()
    WaitSeconds(6)
    ReplaySeek(EV_TICK)
    WaitSeconds(2)
    local n = 0
    while ReplaySeekProgress() and n < 600 do WaitSeconds(0.5) n = n + 1 end
    LOG('EV: seek done at game second ' .. GetGameTimeSeconds())
    import('/lua/ui/game/gamemain.lua').HideGameUI('hide')
    local camera = GetCamera('WorldCamera')
    local s = EV_SCENES[1]
    camera:SnapTo(s[2], { s[3][1], s[3][2], 0 }, s[4])
    WaitSeconds(3)
    for _, cmd in EV_CMDS do ConExecute(cmd) end
    WaitSeconds(3)
    LOG('PERF: step 1 measure')
    WaitSeconds(EV_MEASURE)
    LOG('EV: done')
end)
