-- Camera and A/B control for the shadow filter tests (private copy). Globals set by the launcher through /con are not available here, so
-- the schedule is read from SHADOW_* constants below. After the scene is built the game is paused and ren_ShadowFilter is cycled.
local ZOOM = 6
local HOLD = 5
local MODES = { "ren_ShadowFilter 0", "ren_ShadowFilter 3", "ren_ShadowFilterBias 1;ren_ShadowFilter 3", "ren_ShadowFilterBias 0.25;ren_ShadowFilter 3", "ren_ShadowFilterBias 0.5;ren_ShadowFilterSlope 0;ren_ShadowFilter 3", "ren_ShadowFilterBias 0.5;ren_ShadowFilterSlope 1;ren_ShadowFilter 0" }

local label = nil
local function ShowMode(mode)
    local UIUtil = import('/lua/ui/uiutil.lua')
    local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
    if not label then
        label = UIUtil.CreateText(GetFrame(0), '', 30, UIUtil.bodyFont)
        LayoutHelpers.AtLeftTopIn(label, GetFrame(0), 380, 150)
        label.Depth:Set(10000)
    end
    label:SetText('SHADOW MODE ' .. mode)
end

ForkThread(function()
    WaitSeconds(6)
    local camera = GetCamera('WorldCamera')
    if camera then
        camera:SetZoom(ZOOM, 1.0)
        LOG('SHADOW-TEST: camera zoom ' .. ZOOM)
    end
    while GetGameTimeSeconds() < 8 do WaitSeconds(0.1) end
    SessionRequestPause()
    LOG('SHADOW-TEST: paused at ' .. GetGameTimeSeconds())
    WaitSeconds(4)
    for i, mode in MODES do
        for cmd in string.gfind(mode, '[^;]+') do ConExecute(cmd) end
        ShowMode(i)
        LOG('SHADOW-TEST: mode ' .. i .. ' wall ' .. GetSystemTimeSeconds())
        WaitSeconds(HOLD)
    end
    LOG('SHADOW-TEST: ab done')
end)
