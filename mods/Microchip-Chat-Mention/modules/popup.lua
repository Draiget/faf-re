local UI = import('/lua/ui/uiutil.lua')
local L = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Wrap = import('/lua/maui/text.lua').WrapText
local current, queue = nil, {}
local openingTime, closingTime = 0.36, 0.22

local function Clamp(value) return math.max(0, math.min(1, value)) end

local function OpenEase(value)
    -- A small, soft overshoot settles the card into place without a hard stop.
    local t = Clamp(value) - 1
    return 1 + 2.1 * t * t * t + 1.1 * t * t
end

local function Box(parent, x, y, width, height, color)
    local control = Bitmap(parent)
    control:SetSolidColor(color)
    control.Width:Set(L.ScaleNumber(width)); control.Height:Set(L.ScaleNumber(height))
    L.AtLeftTopIn(control, parent, x, y)
    return control
end

local function Text(parent, value, size, x, y, color)
    local control = UI.CreateText(parent, value, size, UI.bodyFont)
    control:SetColor(color or 'fff1f6ff')
    L.AtLeftTopIn(control, parent, x, y)
    control:DisableHitTest()
    return control
end

function Clear()
    queue = {}
    if current and not IsDestroyed(current) then current:Destroy() end
    current = nil
end

local ShowNext
ShowNext = function()
    if current or not queue[1] then return end
    local message = table.remove(queue, 1)
    local fontSize = message.fontSize or 17
    local lineHeight = fontSize + 7
    local frame = GetFrame(0)
    local width = math.min(640, frame.Width() / L.ScaleNumber(1) - 40)
    local panel = Group(frame)
    current = panel
    panel.Width:Set(L.ScaleNumber(width))
    panel.Depth:Set(frame:GetTopmostDepth() + 20)
    L.AtHorizontalCenterIn(panel, frame)

    local measure = Text(panel, '', fontSize, 24, 66)
    local lines = Wrap(message.text, L.ScaleNumber(width - 48), function(text) return measure:GetStringAdvance(text) end)
    measure:Destroy()
    local height = 78 + table.getn(lines) * lineHeight
    panel.Height:Set(L.ScaleNumber(height))
    local background = Box(panel, 0, 0, width, height, 'f20c1520')
    background.Depth:Set(panel.Depth() - 1); background:DisableHitTest()
    Box(panel, 0, 0, 4, height, 'ff59e0cf'):DisableHitTest()
    Text(panel, message.sender, 12, 23, 12, 'ff59e0cf')
    for i, line in ipairs(lines) do Text(panel, line, fontSize, 23, 41 + (i - 1) * lineHeight) end
    local countdown = Text(panel, '', 11, width - 96, height - 26, 'ff9fb1c2')
    local track = Box(panel, 4, height - 3, width - 4, 3, 'ff263645'); track:DisableHitTest()
    local progress = Box(panel, 4, height - 3, width - 4, 3, 'ff59e0cf'); progress:DisableHitTest()
    local close = Box(panel, width - 37, 9, 28, 28, 'ff1d2b3b')
    local cross = Text(close, 'X', 15, 0, 0, 'ffc4d2e0'); L.AtCenterIn(cross, close)
    local born, closing = GetSystemTimeSeconds(), nil
    local offset, alpha, closeOffset, closeAlpha = -28, 0, -28, 0
    local function Close(now)
        if closing then return end
        closing, closeOffset, closeAlpha = now, offset, alpha
    end
    close.HandleEvent = function(self, event)
        if event.Type == 'ButtonPress' then Close(GetSystemTimeSeconds()); return true end
        if event.Type == 'MouseEnter' then self:SetSolidColor('ff3b566d')
        elseif event.Type == 'MouseExit' then self:SetSolidColor('ff1d2b3b') end
        return false
    end
    panel:SetNeedsFrameUpdate(true)
    panel.OnFrame = function(self, delta)
        local now = GetSystemTimeSeconds()
        local remaining = math.max(0, message.seconds - math.max(0, now - born - openingTime))
        countdown:SetText(tostring(math.ceil(remaining)) .. 's left')
        progress.Width:Set(L.ScaleNumber((width - 4) * remaining / message.seconds))
        if remaining == 0 then Close(now) end
        if closing then
            local t = Clamp((now - closing) / closingTime)
            local ease = t * t * (3 - 2 * t)
            offset, alpha = closeOffset - 22 * ease, closeAlpha * (1 - ease)
        else
            local t = Clamp((now - born) / openingTime)
            offset = -28 * (1 - OpenEase(t))
            -- This engine's Lua uses ^ for XOR; spell out the cubic product.
            local inverse = 1 - t
            alpha = 1 - inverse * inverse * inverse
        end
        self.Top:Set(math.max(0, frame.Top()) + L.ScaleNumber(78 + offset))
        self:SetAlpha(alpha, true)
        if closing and now - closing >= closingTime then
            self:SetNeedsFrameUpdate(false)
            self:Destroy(); current = nil; ShowNext()
        end
    end
    -- Keep the animated control on-screen from its first frame. Slide a short
    -- distance down from the HUD instead of starting outside the viewport.
    panel.Top:Set(math.max(0, frame.Top()) + L.ScaleNumber(50))
    panel:SetAlpha(0, true)
    if message.sound then
        -- An unavailable audio cue must not remove an otherwise valid popup.
        local ok, problem = pcall(function() PlaySound(Sound({Bank = 'Interface', Cue = 'UI_Comm_UEF_In'})) end)
        if not ok then WARN('Microchip Chat Mention sound: ' .. tostring(problem)) end
    end
end

function Preview(message)
    -- Tests must show the current draft now, not wait behind earlier previews.
    Clear()
    Push(message)
end

function Push(message)
    if current and IsDestroyed(current) then current = nil end
    -- Preserve the current popup's full lifetime; queue a bounded burst behind it.
    if table.getn(queue) >= 5 then table.remove(queue, 1) end
    table.insert(queue, message)
    local ok, problem = pcall(ShowNext)
    if not ok then Clear(); WARN('Microchip Chat Mention popup: ' .. tostring(problem)) end
end
