-- Private AO test camera: zoom, pause, then cycle ren_AmbientOcclusion through AB_MODES while paused (AB_HOLD seconds each).
ForkThread(function()
    WaitSeconds(8)
    local camera = GetCamera('WorldCamera')
    if camera then
        camera:SetZoom(AB_ZOOM or 40, 1.0)
        LOG('AO-TEST: camera zoom set to ' .. tostring(AB_ZOOM or 40))
    end
    if AB_PAUSE_AT > 0 then
        while GetGameTimeSeconds() < AB_PAUSE_AT do WaitSeconds(0.1) end
        SessionRequestPause()
        LOG('AO-TEST: paused at ' .. GetGameTimeSeconds())
        WaitSeconds(5)
        for i, mode in AB_MODES do
            ConExecute('ren_AmbientOcclusion ' .. mode)
            LOG('AO-TEST: mode ' .. mode .. ' wall ' .. GetSystemTimeSeconds())
            WaitSeconds(AB_HOLD)
        end
        LOG('AO-TEST: ab done')
    end
end)

if AB_RESIZE then
    ForkThread(function()
        WaitSeconds(14)
        for i, cmd in { 'SC_PrimaryAdapter 1280,720,60', 'SC_PrimaryAdapter 1920,1080,60', 'windowed', 'SC_PrimaryAdapter 1280,720,60', 'windowed' } do
            ConExecute(cmd)
            LOG('AO-TEST: ran ' .. cmd)
            WaitSeconds(5)
        end
        LOG('AO-TEST: resize done')
    end)
end
