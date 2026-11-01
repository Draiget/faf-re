--*****************************************************************************
--* File: data/fafengine/lua/ui/game/replay_timeline.lua
--* Summary: Replay timeline bar and fast-forward scrubbing overlay
--*****************************************************************************

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local IntegerSlider = import('/lua/maui/slider.lua').IntegerSlider
local EscapeHandler = import('/lua/ui/dialogs/eschandler.lua')

-- Format total simulation seconds into HH:MM:SS or MM:SS (Lua 5.0 compatible)
local function FormatSeconds(totalSeconds)
    if not totalSeconds or totalSeconds < 0 then
        totalSeconds = 0
    end
    local s = math.floor(totalSeconds)
    local hours = math.floor(s / 3600)
    local remainder = s - (hours * 3600)
    local minutes = math.floor(remainder / 60)
    local seconds = remainder - (minutes * 60)
    if hours > 0 then
        return string.format("%02d:%02d:%02d", hours, minutes, seconds)
    else
        return string.format("%02d:%02d", minutes, seconds)
    end
end

-- Convert simulation ticks (10 ticks = 1 second) to formatted timestamp
local function FormatTicks(ticks)
    if not ticks or ticks < 0 then
        ticks = 0
    end
    return FormatSeconds(ticks * 0.1)
end

-- Safe global accessors for engine bindings
local function GetTotalTicks()
    if type(GetReplayTotalTicks) == 'function' then
        local ok, val = pcall(GetReplayTotalTicks)
        if ok and val then
            return val
        end
    end
    return 0
end

local function GetCurrentTick()
    local fn = (type(GetGameTick) == 'function' and GetGameTick)
        or (type(GameTick) == 'function' and GameTick)
    if fn then
        local ok, val = pcall(fn)
        if ok and val then
            return val
        end
    end
    return 0
end

local function IsScrubbing()
    if type(IsReplayScrubbing) == 'function' then
        local ok, val = pcall(IsReplayScrubbing)
        if ok then
            return val
        end
    end
    return false
end

local function DoScrub(targetTick)
    if type(ScrubReplay) == 'function' then
        pcall(ScrubReplay, targetTick)
    end
end

local function DoCancelScrub()
    if type(CancelReplayScrub) == 'function' then
        pcall(CancelReplayScrub)
    end
end

local function GetScrubProgress()
    if type(GetReplayScrubProgress) == 'function' then
        local ok, val = pcall(GetReplayScrubProgress)
        if ok then
            return val
        end
    end
    return nil
end

--- Scrubbing modal dialog overlay
--- Displays centered progress box and screen dim while fast-forwarding
local ScrubbingOverlay = ClassUI(Group) {
    __init = function(self, parent)
        Group.__init(self, parent, "ScrubbingModalOverlay")
        LayoutHelpers.FillParent(self, parent)
        self.Depth:Set(1500)

        self._escPushed = false

        -- Semi-transparent dim background covering full screen
        self.dimBg = Bitmap(self)
        LayoutHelpers.FillParent(self.dimBg, self)
        self.dimBg:SetSolidColor('b0000000') -- 70% black dim
        self.dimBg.Depth:Set(function() return self.Depth() end)
        self.dimBg.HandleEvent = function(control, event)
            -- Intercept all mouse clicks while scrubbing
            return true
        end

        -- Centered modal dialog box
        self.dialog = Group(self, "ScrubbingDialog")
        LayoutHelpers.SetDimensions(self.dialog, LayoutHelpers.ScaleNumber(420), LayoutHelpers.ScaleNumber(170))
        LayoutHelpers.AtCenterIn(self.dialog, self)
        self.dialog.Depth:Set(function() return self.Depth() + 5 end)

        -- Dialog background panel
        self.dialogBg = Bitmap(self.dialog)
        LayoutHelpers.FillParent(self.dialogBg, self.dialog)
        self.dialogBg:SetSolidColor('f8101520')
        self.dialogBg.Depth:Set(function() return self.dialog.Depth() end)

        -- 1px border around dialog
        local borderCol = 'ff3c5270'
        self.borderTop = Bitmap(self.dialog)
        LayoutHelpers.AtTopIn(self.borderTop, self.dialog)
        LayoutHelpers.SetHeight(self.borderTop, 1)
        self.borderTop.Left:Set(self.dialog.Left)
        self.borderTop.Right:Set(self.dialog.Right)
        self.borderTop:SetSolidColor(borderCol)
        self.borderTop.Depth:Set(function() return self.dialog.Depth() + 1 end)

        self.borderBottom = Bitmap(self.dialog)
        LayoutHelpers.AtBottomIn(self.borderBottom, self.dialog)
        LayoutHelpers.SetHeight(self.borderBottom, 1)
        self.borderBottom.Left:Set(self.dialog.Left)
        self.borderBottom.Right:Set(self.dialog.Right)
        self.borderBottom:SetSolidColor(borderCol)
        self.borderBottom.Depth:Set(function() return self.dialog.Depth() + 1 end)

        self.borderLeft = Bitmap(self.dialog)
        LayoutHelpers.AtLeftIn(self.borderLeft, self.dialog)
        LayoutHelpers.SetWidth(self.borderLeft, 1)
        self.borderLeft.Top:Set(self.dialog.Top)
        self.borderLeft.Bottom:Set(self.dialog.Bottom)
        self.borderLeft:SetSolidColor(borderCol)
        self.borderLeft.Depth:Set(function() return self.dialog.Depth() + 1 end)

        self.borderRight = Bitmap(self.dialog)
        LayoutHelpers.AtRightIn(self.borderRight, self.dialog)
        LayoutHelpers.SetWidth(self.borderRight, 1)
        self.borderRight.Top:Set(self.dialog.Top)
        self.borderRight.Bottom:Set(self.dialog.Bottom)
        self.borderRight:SetSolidColor(borderCol)
        self.borderRight.Depth:Set(function() return self.dialog.Depth() + 1 end)

        -- Title text
        self.titleText = UIUtil.CreateText(self.dialog, "Fast-forwarding Replay", 16, UIUtil.titleFont)
        LayoutHelpers.AtTopIn(self.titleText, self.dialog, LayoutHelpers.ScaleNumber(16))
        LayoutHelpers.AtHorizontalCenterIn(self.titleText, self.dialog)
        self.titleText:SetColor('ffffffff')
        self.titleText.Depth:Set(function() return self.dialog.Depth() + 2 end)

        -- Detail text: "Fast-forwarding to MM:SS"
        self.targetText = UIUtil.CreateText(self.dialog, "Fast-forwarding to --:--", 13, UIUtil.bodyFont)
        LayoutHelpers.Below(self.targetText, self.titleText, LayoutHelpers.ScaleNumber(8))
        LayoutHelpers.AtHorizontalCenterIn(self.targetText, self.dialog)
        self.targetText:SetColor('ff99ccff')
        self.targetText.Depth:Set(function() return self.dialog.Depth() + 2 end)

        -- Progress bar track
        local trackWidth = LayoutHelpers.ScaleNumber(340)
        local trackHeight = LayoutHelpers.ScaleNumber(16)
        self.barTrack = Bitmap(self.dialog)
        LayoutHelpers.SetDimensions(self.barTrack, trackWidth, trackHeight)
        LayoutHelpers.Below(self.barTrack, self.targetText, LayoutHelpers.ScaleNumber(12))
        LayoutHelpers.AtHorizontalCenterIn(self.barTrack, self.dialog)
        self.barTrack:SetSolidColor('ff080c12')
        self.barTrack.Depth:Set(function() return self.dialog.Depth() + 2 end)

        -- Progress bar track border
        self.barTrackBorder = Bitmap(self.barTrack)
        self.barTrackBorder.Left:Set(function() return self.barTrack.Left() - 1 end)
        self.barTrackBorder.Right:Set(function() return self.barTrack.Right() + 1 end)
        self.barTrackBorder.Top:Set(function() return self.barTrack.Top() - 1 end)
        self.barTrackBorder.Bottom:Set(function() return self.barTrack.Bottom() + 1 end)
        self.barTrackBorder:SetSolidColor('ff1a2636')
        self.barTrackBorder.Depth:Set(function() return self.barTrack.Depth() - 1 end)

        -- Progress bar fill
        self.barFill = Bitmap(self.barTrack)
        self.barFill.Left:Set(self.barTrack.Left)
        self.barFill.Top:Set(self.barTrack.Top)
        self.barFill.Bottom:Set(self.barTrack.Bottom)
        self.barFill.Width:Set(0)
        self.barFill:SetSolidColor('ff00b4d8') -- bright cyan fill
        self.barFill.Depth:Set(function() return self.barTrack.Depth() + 1 end)

        -- Percentage text
        self.percentText = UIUtil.CreateText(self.barTrack, "0%", 10, UIUtil.bodyFont)
        LayoutHelpers.AtCenterIn(self.percentText, self.barTrack)
        self.percentText:SetColor('ffffffff')
        self.percentText.Depth:Set(function() return self.barFill.Depth() + 2 end)

        -- Cancel button
        self.cancelButton = UIUtil.CreateButtonWithDropshadow(self.dialog, '/BUTTON/medium/', "<LOC _Cancel>Cancel")
        LayoutHelpers.Below(self.cancelButton, self.barTrack, LayoutHelpers.ScaleNumber(14))
        LayoutHelpers.AtHorizontalCenterIn(self.cancelButton, self.dialog)
        self.cancelButton.Depth:Set(function() return self.dialog.Depth() + 2 end)
        self.cancelButton.OnClick = function(btn)
            DoCancelScrub()
            self:HideOverlay()
        end

        -- Key and mouse event intercept
        self.HandleEvent = function(control, event)
            if event.Type == 'KeyDown' and event.KeyCode == 27 then -- ESC
                DoCancelScrub()
                self:HideOverlay()
                return true
            end
            return true
        end

        self:Hide()
    end,

    ShowOverlay = function(self, targetTick)
        if not self:IsHidden() then
            return
        end
        if targetTick then
            self.targetText:SetText(string.format("Fast-forwarding to %s", FormatTicks(targetTick)))
        end
        self.barFill.Width:Set(0)
        self.percentText:SetText("0%")

        -- Intercept ESC key via EscapeHandler stack
        if not self._escPushed then
            self._escPushed = true
            EscapeHandler.PushEscapeHandler(function()
                if self._escPushed then
                    self._escPushed = false
                    EscapeHandler.PopEscapeHandler()
                end
                DoCancelScrub()
                self:HideOverlay()
            end)
        end

        self:Show()
    end,

    HideOverlay = function(self)
        if self:IsHidden() then
            return
        end
        if self._escPushed then
            self._escPushed = false
            EscapeHandler.PopEscapeHandler()
        end
        self:Hide()
    end,

    UpdateProgress = function(self, prog)
        if not prog then
            return
        end
        if prog.targetTick then
            self.targetText:SetText(string.format("Fast-forwarding to %s", FormatTicks(prog.targetTick)))
        end
        local pct = prog.progress
        if not pct or pct < 0 then
            pct = 0
        elseif pct > 1 then
            pct = 1
        end
        local totalTrackWidth = self.barTrack.Width()
        self.barFill.Width:Set(math.floor(totalTrackWidth * pct))
        self.percentText:SetText(string.format("%d%% (%s)", math.floor(pct * 100), FormatTicks(prog.currentTick)))
    end,
}

local controls = {
    timeline = false,
    overlay = false,
}

--- Build bottom-centered replay timeline bar
---@param parent Control
---@return Group
function CreateReplayTimeline(parent)
    if controls.timeline then
        return controls.timeline
    end

    local rootFrame = GetFrame(0)
    parent = rootFrame

    -- Create scrubbing overlay on root frame
    controls.overlay = ScrubbingOverlay(rootFrame)

    -- Bottom-centered timeline bar directly on root frame
    local bar = Group(rootFrame, "ReplayTimelineBar")
    bar.Width:Set(LayoutHelpers.ScaleNumber(540))
    bar.Height:Set(LayoutHelpers.ScaleNumber(36))
    bar.Bottom:Set(function() return math.floor(rootFrame.Bottom() - LayoutHelpers.ScaleNumber(14)) end)
    bar.Top:Set(function() return math.floor(bar.Bottom() - bar.Height()) end)
    bar.Left:Set(function() return math.floor(rootFrame.Left() + (rootFrame.Width() - bar.Width()) * 0.5) end)
    bar.Right:Set(function() return math.floor(bar.Left() + bar.Width()) end)
    bar.Depth:Set(1000)
    bar:Show()

    -- Semi-transparent dark background
    local bg = Bitmap(bar)
    bg.Left:Set(bar.Left)
    bg.Right:Set(bar.Right)
    bg.Top:Set(bar.Top)
    bg.Bottom:Set(bar.Bottom)
    bg:SetSolidColor('e60d1117') -- semi-transparent dark charcoal
    bg.Depth:Set(function() return bar.Depth() end)

    -- Top accent line
    local topBorder = Bitmap(bar)
    topBorder.Left:Set(bar.Left)
    topBorder.Right:Set(bar.Right)
    topBorder.Top:Set(bar.Top)
    LayoutHelpers.SetHeight(topBorder, 1)
    topBorder:SetSolidColor('ff2b3d54')
    topBorder.Depth:Set(function() return bar.Depth() + 1 end)

    -- Subtle perimeter borders
    local borderCol = 'ff141c26'
    local botBorder = Bitmap(bar)
    botBorder.Left:Set(bar.Left)
    botBorder.Right:Set(bar.Right)
    botBorder.Bottom:Set(bar.Bottom)
    LayoutHelpers.SetHeight(botBorder, 1)
    botBorder:SetSolidColor(borderCol)
    botBorder.Depth:Set(function() return bar.Depth() + 1 end)

    local leftBorder = Bitmap(bar)
    leftBorder.Left:Set(bar.Left)
    LayoutHelpers.SetWidth(leftBorder, 1)
    leftBorder.Top:Set(bar.Top)
    leftBorder.Bottom:Set(bar.Bottom)
    leftBorder:SetSolidColor(borderCol)
    leftBorder.Depth:Set(function() return bar.Depth() + 1 end)

    local rightBorder = Bitmap(bar)
    rightBorder.Right:Set(bar.Right)
    LayoutHelpers.SetWidth(rightBorder, 1)
    rightBorder.Top:Set(bar.Top)
    rightBorder.Bottom:Set(bar.Bottom)
    rightBorder:SetSolidColor(borderCol)
    rightBorder.Depth:Set(function() return bar.Depth() + 1 end)

    -- Current time label
    local curTimeLabel = UIUtil.CreateText(bar, "00:00", 12, UIUtil.bodyFont)
    curTimeLabel.Left:Set(function() return math.floor(bar.Left() + LayoutHelpers.ScaleNumber(14)) end)
    curTimeLabel.Width:Set(LayoutHelpers.ScaleNumber(55))
    LayoutHelpers.AtVerticalCenterIn(curTimeLabel, bar)
    curTimeLabel:SetColor('ffffffff')
    curTimeLabel.Depth:Set(function() return bar.Depth() + 2 end)

    -- Total duration label
    local totalTimeLabel = UIUtil.CreateText(bar, "00:00", 12, UIUtil.bodyFont)
    totalTimeLabel.Right:Set(function() return math.floor(bar.Right() - LayoutHelpers.ScaleNumber(14)) end)
    totalTimeLabel.Width:Set(LayoutHelpers.ScaleNumber(55))
    LayoutHelpers.AtVerticalCenterIn(totalTimeLabel, bar)
    totalTimeLabel:SetColor('ff9cb0c6')
    totalTimeLabel.Depth:Set(function() return bar.Depth() + 2 end)

    -- Interactive slider
    local function GetSkinFile(path)
        if UIUtil and UIUtil.SkinnableFile then
            return UIUtil.SkinnableFile(path)
        end
        return path
    end

    local initialTotal = GetTotalTicks()
    local maxTicks = math.max(10, initialTotal)
    local slider = IntegerSlider(
        bar,
        false,
        0,
        maxTicks,
        1,
        GetSkinFile('/slider02/slider_btn_up.dds'),
        GetSkinFile('/slider02/slider_btn_over.dds'),
        GetSkinFile('/slider02/slider_btn_down.dds'),
        GetSkinFile('/dialogs/options/slider-back_bmp.dds')
    )
    slider.Left:Set(function() return math.floor(curTimeLabel.Left() + curTimeLabel.Width() + LayoutHelpers.ScaleNumber(10)) end)
    slider.Right:Set(function() return math.floor(totalTimeLabel.Right() - totalTimeLabel.Width() - LayoutHelpers.ScaleNumber(10)) end)
    slider.Height:Set(LayoutHelpers.ScaleNumber(16))
    LayoutHelpers.AtVerticalCenterIn(slider, bar)

    slider._background.Left:Set(slider.Left)
    slider._background.Right:Set(slider.Right)
    slider._background.Top:Set(slider.Top)
    slider._background.Bottom:Set(slider.Bottom)
    slider._thumb.Depth:Set(function() return bar.Depth() + 6 end)
    slider._background.Depth:Set(function() return bar.Depth() + 2 end)

    -- Floating preview label above slider thumb while dragging
    local thumbPreview = UIUtil.CreateText(bar, "", 11, UIUtil.bodyFont)
    LayoutHelpers.Above(thumbPreview, slider._thumb, LayoutHelpers.ScaleNumber(2))
    LayoutHelpers.AtHorizontalCenterIn(thumbPreview, slider._thumb)
    thumbPreview:SetColor('ff00d0ff')
    thumbPreview.Depth:Set(function() return slider._thumb.Depth() + 1 end)
    thumbPreview:Hide()

    local isDragging = false

    slider.OnBeginChange = function(self)
        isDragging = true
        thumbPreview:Show()
    end

    slider.OnScrub = function(self, val)
        val = math.floor(val)
        curTimeLabel:SetText(FormatTicks(val))
        thumbPreview:SetText(FormatTicks(val))
    end

    slider.OnValueChanged = function(self, val)
        if isDragging then
            val = math.floor(val)
            curTimeLabel:SetText(FormatTicks(val))
            thumbPreview:SetText(FormatTicks(val))
        end
    end

    slider.OnEndChange = function(self)
        isDragging = false
        thumbPreview:Hide()
    end

    slider.OnValueSet = function(self, newValue)
        isDragging = false
        thumbPreview:Hide()
        local targetTick = math.floor(newValue)
        DoScrub(targetTick)
        if controls.overlay then
            controls.overlay:ShowOverlay(targetTick)
        end
    end

    bar:SetNeedsFrameUpdate(true)
    bar.OnFrame = function(self, deltaTime)
        local total = GetTotalTicks()
        if total > 0 and slider._endValue ~= total then
            slider:SetEndValue(total)
            totalTimeLabel:SetText(FormatTicks(total))
        end

        local scrubbing = IsScrubbing()
        if scrubbing then
            local prog = GetScrubProgress()
            if controls.overlay then
                if controls.overlay:IsHidden() then
                    local target = (prog and prog.targetTick) or slider:GetValue()
                    controls.overlay:ShowOverlay(target)
                end
                if prog then
                    controls.overlay:UpdateProgress(prog)
                end
            end
        else
            if controls.overlay and not controls.overlay:IsHidden() then
                controls.overlay:HideOverlay()
            end

            if not isDragging then
                local curTick = GetCurrentTick()
                slider:SetValue(curTick)
                curTimeLabel:SetText(FormatTicks(curTick))
            end
        end
    end

    bar.OnDestroy = function(self)
        if controls.overlay then
            controls.overlay:HideOverlay()
            controls.overlay:Destroy()
            controls.overlay = false
        end
        controls.timeline = false
    end

    controls.timeline = bar
    LOG("FAFENGINE: Replay timeline bar created successfully")
    return bar
end

function GetTimelineControl()
    return controls.timeline
end

function GetScrubOverlay()
    return controls.overlay
end
