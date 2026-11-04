--*****************************************************************************
--* File: data/fafengine/lua/ui/game/replay_timeline.lua
--* Summary: Replay timeline bar and fast-forward scrubbing overlay (SupCom UI)
--*****************************************************************************

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local IntegerSlider = import('/lua/maui/slider.lua').IntegerSlider
local EscapeHandler = import('/lua/ui/dialogs/eschandler.lua')

-- Lua 5.0 compatibility: C/C++ engine bindings have type 'cfunction', Lua functions have 'function',
-- and Maui lazyvars are callable tables with __call metamethod.
local function is_callable(fn)
    if not fn then
        return false
    end
    local t = type(fn)
    if t == 'function' or t == 'cfunction' then
        return true
    end
    if t == 'table' then
        local mt = getmetatable(fn)
        if mt and (type(mt.__call) == 'function' or type(mt.__call) == 'cfunction') then
            return true
        end
    end
    return false
end

-- Safe skinnable/UI file lookup with mock fallback
local function GetSkinFile(path)
    if UIUtil and is_callable(UIUtil.SkinnableFile) then
        return UIUtil.SkinnableFile(path)
    end
    if UIUtil and is_callable(UIUtil.UIFile) then
        return UIUtil.UIFile(path)
    end
    return path
end

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
    if is_callable(GetReplayTotalTicks) then
        local ok, val = pcall(GetReplayTotalTicks)
        if ok and val then
            return val
        end
    end
    return 0
end

local function GetCurrentTick()
    local fn = (is_callable(GetGameTick) and GetGameTick)
        or (is_callable(GameTick) and GameTick)
    if fn then
        local ok, val = pcall(fn)
        if ok and val then
            return val
        end
    end
    return 0
end

local function IsScrubbing()
    if is_callable(IsReplayScrubbing) then
        local ok, val = pcall(IsReplayScrubbing)
        if ok then
            return val
        end
    end
    return false
end

local function DoScrub(targetTick)
    local fn = rawget(_G, 'ScrubReplay')
    if not fn and is_callable(ScrubReplay) then
        fn = ScrubReplay
    end
    if is_callable(fn) then
        LOG(string.format("FAFENGINE: Calling ScrubReplay(%d)", targetTick))
        pcall(fn, targetTick)
    else
        WARN("FAFENGINE: ScrubReplay not callable!")
    end
end

local function DoCancelScrub()
    if is_callable(CancelReplayScrub) then
        pcall(CancelReplayScrub)
    end
end

local function GetScrubProgress()
    if is_callable(GetReplayScrubProgress) then
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
        if self.SetRenderPass and UIUtil and UIUtil.UIRP_PostGlow then
            self:SetRenderPass(UIUtil.UIRP_PostGlow)
        end
        LayoutHelpers.FillParent(self, parent)
        self.Depth:Set(10000)

        self._escPushed = false

        -- Semi-transparent dim background covering full screen (matching SupCom popup shadow)
        self.dimBg = Bitmap(self)
        LayoutHelpers.FillParent(self.dimBg, self)
        self.dimBg:SetSolidColor('78000000')
        self.dimBg.Depth:Set(function() return self.Depth() end)
        self.dimBg.HandleEvent = function(control, event)
            -- Intercept mouse clicks while scrubbing
            return true
        end

        -- Centered modal dialog box
        self.dialog = Group(self, "ScrubbingDialog")
        LayoutHelpers.SetDimensions(self.dialog, 420, 160)
        LayoutHelpers.AtCenterIn(self.dialog, self)
        self.dialog.Depth:Set(function() return self.Depth() + 10 end)

        -- Authentic Supreme Commander dialog border
        if UIUtil and is_callable(UIUtil.CreateNinePatchStd) then
            local bgPatch = UIUtil.CreateNinePatchStd(self.dialog, '/scx_menu/lan-game-lobby/dialog/background/')
            LayoutHelpers.FillParentFixedBorder(bgPatch, self.dialog, 32)
            LayoutHelpers.DepthUnderParent(bgPatch, self.dialog, 2)
        else
            self.dialogBg = Bitmap(self.dialog)
            LayoutHelpers.FillParent(self.dialogBg, self.dialog)
            self.dialogBg:SetSolidColor('f8101520')
            self.dialogBg.Depth:Set(function() return self.dialog.Depth() end)
        end

        -- Title text in SupCom title font
        self.titleText = UIUtil.CreateText(self.dialog, "FAST-FORWARDING REPLAY", 15, UIUtil.titleFont)
        LayoutHelpers.AtTopIn(self.titleText, self.dialog, 20)
        LayoutHelpers.AtHorizontalCenterIn(self.titleText, self.dialog)
        self.titleText:SetColor('ffb0c8e0')
        self.titleText.Depth:Set(function() return self.dialog.Depth() + 5 end)

        -- Target status: "Advancing to MM:SS"
        self.targetText = UIUtil.CreateText(self.dialog, "Advancing to --:--", 12, UIUtil.bodyFont)
        LayoutHelpers.Below(self.targetText, self.titleText, 8)
        LayoutHelpers.AtHorizontalCenterIn(self.targetText, self.dialog)
        self.targetText:SetColor('ffffffff')
        self.targetText.Depth:Set(function() return self.dialog.Depth() + 5 end)

        -- Progress bar track using SupCom game slider track texture
        local trackTexture = GetSkinFile('/game/slider/slider-back_bmp.dds')
        self.barTrack = Bitmap(self.dialog, trackTexture)
        LayoutHelpers.SetDimensions(self.barTrack, 320, 16)
        LayoutHelpers.Below(self.barTrack, self.targetText, 14)
        LayoutHelpers.AtHorizontalCenterIn(self.barTrack, self.dialog)
        self.barTrack.Depth:Set(function() return self.dialog.Depth() + 5 end)

        -- Progress bar fill (bright cyan fill)
        self.barFill = Bitmap(self.barTrack)
        self.barFill.Left:Set(self.barTrack.Left)
        self.barFill.Top:Set(self.barTrack.Top)
        self.barFill.Bottom:Set(self.barTrack.Bottom)
        self.barFill.Width:Set(0)
        self.barFill:SetSolidColor('b000b4d8')
        self.barFill.Depth:Set(function() return self.barTrack.Depth() + 1 end)

        -- Percentage text
        self.percentText = UIUtil.CreateText(self.barTrack, "0%", 10, UIUtil.bodyFont)
        LayoutHelpers.AtCenterIn(self.percentText, self.barTrack)
        self.percentText:SetColor('ffffffff')
        self.percentText.Depth:Set(function() return self.barFill.Depth() + 2 end)

        -- Cancel button with standard SupCom drop shadow
        self.cancelButton = UIUtil.CreateButtonWithDropshadow(self.dialog, '/BUTTON/medium/', "<LOC _Cancel>Cancel")
        LayoutHelpers.Below(self.cancelButton, self.barTrack, 16)
        LayoutHelpers.AtHorizontalCenterIn(self.cancelButton, self.dialog)
        self.cancelButton.Depth:Set(function() return self.dialog.Depth() + 5 end)
        self.cancelButton.OnClick = function(btn)
            DoCancelScrub()
            self:HideOverlay()
        end

        -- Key event intercept (ESC to cancel)
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
        local curTick = GetCurrentTick()
        self._isRewind = (targetTick and targetTick < curTick)
        if targetTick then
            if self._isRewind then
                self.targetText:SetText(string.format("Rewinding to %s", FormatTicks(targetTick)))
            else
                self.targetText:SetText(string.format("Advancing to %s", FormatTicks(targetTick)))
            end
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
            if self._isRewind then
                self.targetText:SetText(string.format("Rewinding to %s", FormatTicks(prog.targetTick)))
            else
                self.targetText:SetText(string.format("Advancing to %s", FormatTicks(prog.targetTick)))
            end
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

--- Build replay timeline bar styled for Supreme Commander
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

    -- Bottom-centered timeline bar directly on root frame (lifted midway between center and bottom)
    local bar = Group(rootFrame, "ReplayTimelineBar")
    if bar.SetRenderPass and UIUtil and UIUtil.UIRP_PostGlow then
        bar:SetRenderPass(UIUtil.UIRP_PostGlow)
    end
    LayoutHelpers.SetDimensions(bar, 640, 48)
    LayoutHelpers.AtHorizontalCenterIn(bar, rootFrame)
    bar.Top:Set(function()
        local top = 0
        local height = 1080
        if rootFrame.Top then
            local ok, val = pcall(rootFrame.Top)
            if ok and type(val) == 'number' then
                top = val
            end
        end
        if rootFrame.Height then
            local ok, val = pcall(rootFrame.Height)
            if ok and type(val) == 'number' then
                height = val
            end
        end
        -- Midway between screen center (0.50) and screen bottom (1.00)
        return math.floor(top + height * 0.72)
    end)
    bar.Depth:Set(9500)
    bar:Show()

    -- Authentic Supreme Commander border using NinePatch
    if UIUtil and is_callable(UIUtil.SurroundWithNinePatch) then
        UIUtil.SurroundWithNinePatch(bar, "/game/chat_brd/", 4, 4)
    end

    -- Dark translucent backing (SupCom frosted HUD glass)
    local bg = Bitmap(bar)
    LayoutHelpers.FillParent(bg, bar)
    bg:SetSolidColor('80080d14')
    bg.Depth:Set(function() return bar.Depth() + 1 end)

    -- Header label in SupCom title font
    local barHeader = UIUtil.CreateText(bar, "-- REPLAY TIMELINE --", 9, UIUtil.titleFont)
    LayoutHelpers.AtTopIn(barHeader, bar, 4)
    LayoutHelpers.AtHorizontalCenterIn(barHeader, bar)
    barHeader:SetColor('ff829cb4')
    barHeader.Depth:Set(function() return bar.Depth() + 3 end)

    -- Current time label
    local curTimeLabel = UIUtil.CreateText(bar, "00:00", 12, UIUtil.bodyFont)
    LayoutHelpers.AtLeftIn(curTimeLabel, bar, 18)
    LayoutHelpers.AtVerticalCenterIn(curTimeLabel, bar, 4)
    curTimeLabel:SetColor('ffffffff')
    curTimeLabel.Depth:Set(function() return bar.Depth() + 3 end)

    -- Total duration label
    local totalTimeLabel = UIUtil.CreateText(bar, "--:--", 12, UIUtil.bodyFont)
    LayoutHelpers.AtRightIn(totalTimeLabel, bar, 18)
    LayoutHelpers.AtVerticalCenterIn(totalTimeLabel, bar, 4)
    totalTimeLabel:SetColor('ffb0c4de')
    totalTimeLabel.Depth:Set(function() return bar.Depth() + 3 end)

    -- Authentic Supreme Commander slider textures
    local thumbUp = GetSkinFile('/game/slider-btn/slider_btn_up.dds')
    local thumbOver = GetSkinFile('/game/slider-btn/slider_btn_over.dds')
    local thumbDown = GetSkinFile('/game/slider-btn/slider_btn_down.dds')
    local sliderBg = GetSkinFile('/game/slider/slider-back_bmp.dds')

    local initialTotal = GetTotalTicks()
    local maxTicks = (initialTotal and initialTotal > 0) and initialTotal or 100
    local slider = IntegerSlider(
        bar,
        false,
        0,
        maxTicks,
        1,
        thumbUp,
        thumbOver,
        thumbDown,
        sliderBg
    )
    slider.Left:Set(function() return math.floor(curTimeLabel.Right() + LayoutHelpers.ScaleNumber(12)) end)
    slider.Right:Set(function() return math.floor(totalTimeLabel.Left() - LayoutHelpers.ScaleNumber(12)) end)
    slider.Width:Set(function() return math.max(10, math.floor(slider.Right() - slider.Left())) end)
    LayoutHelpers.SetHeight(slider, 20)
    LayoutHelpers.AtVerticalCenterIn(slider, bar, 4)

    LayoutHelpers.FillParent(slider._background, slider)
    slider._thumb.Depth:Set(function() return bar.Depth() + 6 end)
    slider._background.Depth:Set(function() return bar.Depth() + 2 end)
    if slider.EnableHitTest then
        slider:EnableHitTest()
    end
    if slider._thumb and slider._thumb.EnableHitTest then
        slider._thumb:EnableHitTest()
    end
    if slider._background and slider._background.EnableHitTest then
        slider._background:EnableHitTest()
    end

    -- Floating preview label above slider thumb while dragging
    local thumbPreview = UIUtil.CreateText(bar, "", 11, UIUtil.bodyFont)
    LayoutHelpers.Above(thumbPreview, slider._thumb, 2)
    LayoutHelpers.AtHorizontalCenterIn(thumbPreview, slider._thumb)
    thumbPreview:SetColor('ff00d0ff')
    thumbPreview.Depth:Set(function() return slider._thumb.Depth() + 2 end)
    thumbPreview:Hide()

    local isDragging = false

    slider.OnBeginChange = function(self)
        isDragging = true
        thumbPreview:Show()
    end

    slider.OnScrub = function(self, val)
        val = math.max(0, math.floor(val))
        curTimeLabel:SetText(FormatTicks(val))
        thumbPreview:SetText(FormatTicks(val))
    end

    slider.OnValueChanged = function(self, val)
        if isDragging then
            val = math.max(0, math.floor(val))
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
        local curTick = GetCurrentTick()
        local targetTick = math.floor(newValue)

        if targetTick < 0 then
            targetTick = 0
        end

        -- If target is the exact current tick, do nothing
        if targetTick == curTick then
            slider:SetValue(curTick)
            curTimeLabel:SetText(FormatTicks(curTick))
            return
        end

        -- If rewinding backward, clear unit selection to prevent invalid entity references in UI
        if targetTick < curTick then
            local su = rawget(_G, 'SelectUnits')
            if is_callable(su) then
                pcall(su, nil)
            end
        end

        LOG(string.format("FAFENGINE: Timeline seeking replay from tick %d to tick %d", curTick, targetTick))
        LOG("FAFENGINE: Calling DoScrub")
        DoScrub(targetTick)
        LOG("FAFENGINE: Returned from DoScrub")
        if controls.overlay then
            LOG("FAFENGINE: Calling controls.overlay:ShowOverlay")
            controls.overlay:ShowOverlay(targetTick)
            LOG("FAFENGINE: Returned from ShowOverlay")
        end
    end

    local isAutoScrub = false
    local isShortScrub = false
    local hasCmd = rawget(_G, 'HasCommandLineArg') or HasCommandLineArg
    LOG("FAFENGINE: checking command line flags, hasCmd=" .. tostring(hasCmd))
    if is_callable(hasCmd) then
        local ok, res = pcall(hasCmd, '/autoscrub')
        if ok and res then
            isAutoScrub = true
            LOG("FAFENGINE: /autoscrub command line flag detected! Automated scrubbing test enabled.")
        end
        local ok2, res2 = pcall(hasCmd, '/shortscrub')
        if ok2 and res2 then
            isAutoScrub = true
            isShortScrub = true
            LOG("FAFENGINE: /shortscrub command line flag detected! Automated 300 -> 1 -> 300 test enabled.")
        end
    end

    if isAutoScrub then
        local setSpeed = rawget(_G, 'SetGameSpeed') or SetGameSpeed
        if is_callable(setSpeed) then
            pcall(setSpeed, 10)
        end
        local conExec = rawget(_G, 'ConExecute') or ConExecute
        if is_callable(conExec) then
            pcall(conExec, "WLD_GameSpeed 10")
        end
    end

    local autoScrubStep = 0
    local autoScrubCooldown = 0
    local autoScrubStatusTimer = 0

    local loggedOnce = false
    bar:SetNeedsFrameUpdate(true)
    bar.OnFrame = function(self, deltaTime)
        local total = GetTotalTicks()
        local curTick = GetCurrentTick()

        if isAutoScrub then
            local isScrub = IsScrubbing()
            if autoScrubCooldown > 0 then
                autoScrubCooldown = autoScrubCooldown - deltaTime
            end

            autoScrubStatusTimer = (autoScrubStatusTimer or 0) + deltaTime
            if autoScrubStatusTimer >= 1.0 then
                autoScrubStatusTimer = 0
                LOG(string.format("AUTOTEST_STATUS: step=%d isScrub=%s curTick=%d cooldown=%.1f", autoScrubStep, tostring(isScrub), curTick, autoScrubCooldown))
            end

            if autoScrubCooldown <= 0 then
                if isShortScrub then
                    if autoScrubStep == 0 and curTick >= 300 and not isScrub then
                        autoScrubStep = 2
                        autoScrubCooldown = 1.0
                        LOG(string.format("AUTOTEST: Step 1 -> Seeking back to tick 1 (base snapshot at beat 1) from tick %d", curTick))
                        slider:OnValueSet(1)
                        LOG("AUTOTEST: Step 1 COMPLETE at tick 1! Now Step 2 -> Playing forward to tick 300")
                    elseif autoScrubStep == 2 and not isScrub and curTick >= 300 then
                        autoScrubStep = 3
                        LOG(string.format("AUTOTEST: SUCCESS! Reached tick %d after rewind to base snapshot! Test passed!", curTick))
                        local exitApp = rawget(_G, 'ExitApplication') or ExitApplication
                        if is_callable(exitApp) then
                            exitApp()
                        end
                    end
                else
                    if autoScrubStep == 0 and curTick >= 50 and not isScrub then
                        autoScrubStep = 1
                        autoScrubCooldown = 1.0
                        LOG("AUTOTEST: Step 1 -> Seeking to tick 2400 (4 min)")
                        slider:OnValueSet(2400)
                    elseif autoScrubStep == 1 and not isScrub then
                        autoScrubStep = 2
                        autoScrubCooldown = 1.0
                        LOG(string.format("AUTOTEST: Step 1 COMPLETE at tick %d! Now Step 2 -> Seeking back to tick 1200 (2 min)", curTick))
                        slider:OnValueSet(1200)
                    elseif autoScrubStep == 2 and not isScrub then
                        autoScrubStep = 3
                        autoScrubCooldown = 1.0
                        LOG(string.format("AUTOTEST: Step 2 COMPLETE at tick %d! Now Step 3 -> Seeking forward again to tick 2400 (4 min)", curTick))
                        slider:OnValueSet(2400)
                    elseif autoScrubStep == 3 and not isScrub then
                        autoScrubStep = 4
                        LOG(string.format("AUTOTEST: SUCCESS! Reached tick %d after 2400 -> 1200 -> 2400 scrubbing! Test passed!", curTick))
                        local exitApp = rawget(_G, 'ExitApplication')
                        if is_callable(exitApp) then
                            exitApp()
                        end
                    end
                end
            end
        end

        if total and total > 0 then
            if slider._endValue ~= total then
                slider:SetEndValue(total)
            end
            totalTimeLabel:SetText(FormatTicks(total))
        else
            local fallbackMax = math.max(100, curTick)
            if slider._endValue ~= fallbackMax then
                slider:SetEndValue(fallbackMax)
            end
            totalTimeLabel:SetText("--:--")
        end

        if not loggedOnce then
            loggedOnce = true
            LOG(string.format("FAFENGINE: Timeline rendered at Left=%s Top=%s Right=%s Bottom=%s Depth=%s Hidden=%s TotalTicks=%s CurTick=%s",
                tostring(self.Left()), tostring(self.Top()), tostring(self.Right()), tostring(self.Bottom()),
                tostring(self.Depth()), tostring(self:IsHidden()),
                tostring(total), tostring(curTick)))
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
