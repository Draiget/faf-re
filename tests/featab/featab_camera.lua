-- Feature on/off capture camera. Header defines AB_START (game seconds before the first step), AB_HOLD (seconds per step), AB_TX/AB_TY/AB_TZ
-- (camera target), AB_PAUSE_AT (0 = never pause, else pause at that game time and run the steps paused), AB_STEPS (list of
-- { label, { console commands }, preset }) and AB_PRESETS (name -> { zoom, pitch, heading, dx, dz }).
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local marker = nil
-- an 8x8 square in the top-left corner of every frame: red = 33 * ((n - 1) mod 8), blue = 33 * ((n - 1) div 8), green 255; black = view change in progress.
-- (the frames are 5/6/5-bit: 33 is four levels apart, so the number survives the quantisation)
local function Mark(n)
    if not marker then
        local frame = GetFrame(0)
        marker = Bitmap(frame)
        LayoutHelpers.AtLeftTopIn(marker, frame, 0, 0)
        LayoutHelpers.SetDimensions(marker, 8, 8)
        LayoutHelpers.DepthOverParent(marker, frame, 100000)
    end
    if n == 0 then
        marker:SetSolidColor('ff000000')
    else
        marker:SetSolidColor(string.format('ff%02x%02x%02x', 33 * math.mod(n - 1, 8), 255, 33 * math.floor((n - 1) / 8)))
    end
end

ForkThread(function()
    WaitSeconds(8)
    while GetGameTimeSeconds() < AB_START do WaitSeconds(0.2) end
    if AB_PAUSE_AT > 0 then
        while GetGameTimeSeconds() < AB_PAUSE_AT do WaitSeconds(0.1) end
        SessionRequestPause()
        LOG('FEATAB: paused at ' .. GetGameTimeSeconds())
        WaitSeconds(3)
    end
    local camera = GetCamera('WorldCamera')
    if AB_FOCUS and AB_FOCUS > 0 then SetFocusArmy(AB_FOCUS) end
    if AB_SELECT then
        WaitSeconds(1)
        UISelectionByCategory('ALLUNITS', false, false, false, false)
    end
    local last = nil
    for i, step in AB_STEPS do
        local p = AB_PRESETS[step[3]]
        if camera and p and step[3] ~= last then
            Mark(0)
            camera:SnapTo({ AB_TX + p[4], AB_TY, AB_TZ + p[5] }, { p[3], p[2], 0 }, p[1])
            last = step[3]
            WaitSeconds(4)
        end
        for _, cmd in step[2] do ConExecute(cmd) end
        Mark(i)
        LOG('FEATAB: step ' .. i .. ' ' .. step[1])
        WaitSeconds(AB_HOLD)
    end
    LOG('FEATAB: ab done')
end)
