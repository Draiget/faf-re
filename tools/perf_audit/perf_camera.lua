-- Perf audit camera (UI). Header defines AB_START (game seconds before the first step), AB_HOLD (default seconds per step), AB_TX/AB_TY/AB_TZ,
-- AB_PAUSE_AT (0 = never), AB_STEPS ({ label, { console commands }, preset, hold, 'info' }) and AB_PRESETS (name -> { zoom, pitch, heading, dx, dz, dy }).
-- Every step logs "PERF: step <i> <label>"; the analysis joins the render profile windows that follow it.
ForkThread(function()
    WaitSeconds(8)
    while GetGameTimeSeconds() < AB_START do WaitSeconds(0.2) end
    LOG('PERF: ready at game second ' .. GetGameTimeSeconds())
    if AB_PAUSE_AT > 0 then
        while GetGameTimeSeconds() < AB_PAUSE_AT do WaitSeconds(0.1) end
        SessionRequestPause()
        LOG('PERF: paused at ' .. GetGameTimeSeconds())
        WaitSeconds(3)
    end
    local camera = GetCamera('WorldCamera')
    local last = nil
    for i, step in AB_STEPS do
        local p = AB_PRESETS[step[3]]
        if camera and p and step[3] ~= last then
            camera:SnapTo({ AB_TX + p[4], AB_TY + (p[6] or 0), AB_TZ + p[5] }, { p[3], p[2], 0 }, p[1])
            last = step[3]
            WaitSeconds(3)
        end
        for _, cmd in step[2] do ConExecute(cmd) end
        LOG('PERF: step ' .. i .. ' ' .. step[1])
        if step[5] == 'info' then WaitSeconds(2) ConExecute('ren_Info') end
        WaitSeconds(step[4] or AB_HOLD)
    end
    LOG('PERF: done')
end)
