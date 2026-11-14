local UI = import('/lua/ui/uiutil.lua')
local L = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Edit = import('/lua/maui/edit.lua').Edit
local Popup = import('/lua/ui/controls/popups/popup.lua').Popup
local Mention = import('/mods/Microchip-Chat-Mention/modules/mentions.lua')
local window

function Open(parent)
    if window and not IsDestroyed(window) then return window end
    parent = parent or GetFrame(0)
    local panel = Group(parent)
    panel.Width:Set(L.ScaleNumber(620)); panel.Height:Set(L.ScaleNumber(514))
    local bg = Bitmap(panel); bg:SetSolidColor('ff0c1520')
    L.FillParent(bg, panel); bg:DisableHitTest()
    local popup = Popup(parent, panel)
    window = popup
    local oldClosed = popup.OnClosed
    popup.OnClosed = function(self) window = nil; oldClosed(self) end
    local function Text(value, size, x, y, color)
        local t = UI.CreateText(panel, value, size, UI.bodyFont)
        t:SetColor(color or 'ffeaf2fa'); L.AtLeftTopIn(t, panel, x, y); t:DisableHitTest()
        return t
    end
    local function Input(value, x, y, width, limit)
        local e = Edit(panel)
        e.Width:Set(L.ScaleNumber(width)); e.Height:Set(L.ScaleNumber(28))
        L.AtLeftTopIn(e, panel, x, y)
        UI.SetupEditStd(e, 'ffeaf2fa', 'ff182635', 'ff000000', 'ff59e0cf', UI.bodyFont, 16, limit)
        e:SetText(value)
        return e
    end
    local function Button(value, x, y, click)
        local b = UI.CreateButtonWithDropshadow(panel, '/BUTTON/medium/', value)
        L.AtLeftTopIn(b, panel, x, y); b.OnClick = click
        return b
    end
    local config = Mention.Settings()
    Text('Microchip Chat Mention', 24, 22, 15, 'ff59e0cf')
    Text('Player name is detected automatically. Nicknames are additional matches.', 13, 22, 53)
    Text('Your player name: ' .. (Mention.PlayerName() ~= '' and Mention.PlayerName() or '(available in game)'), 14, 22, 83)
    Text('Nicknames (separate with commas)', 15, 22, 120)
    local names = Input(config.nicknames, 22, 147, 566, 256)
    Text('Display time in seconds (1-120)', 15, 22, 192)
    local seconds = Input(tostring(config.seconds), 395, 187, 85, 3)
    Text('Message font size (12-32)', 15, 22, 232)
    local fontSize = Input(tostring(config.fontSize), 395, 227, 85, 2)
    local sample = Text('Aa - message text preview', config.fontSize, 22, 266, 'ff59e0cf')
    fontSize.OnTextChanged = function()
        local size = tonumber(fontSize:GetText())
        if size and size == math.floor(size) and size >= 12 and size <= 32 then
            sample:SetFont(UI.bodyFont, size)
        end
    end
    local preview
    local function FontStep(label, x, delta)
        local button = Bitmap(panel); button:SetSolidColor('ff263b4b')
        button.Width:Set(L.ScaleNumber(28)); button.Height:Set(L.ScaleNumber(28))
        L.AtLeftTopIn(button, panel, x, 227)
        local mark = UI.CreateText(button, label, 18, UI.bodyFont)
        mark:SetColor('ff59e0cf'); L.AtCenterIn(mark, button); mark:DisableHitTest()
        button.HandleEvent = function(self, event)
            if event.Type == 'ButtonPress' then
                local size = tonumber(fontSize:GetText()) or config.fontSize
                fontSize:SetText(tostring(math.max(12, math.min(32, math.floor(size) + delta))))
                if preview then preview() end
                return true
            end
            return false
        end
    end
    FontStep('-', 351, -1)
    FontStep('+', 496, 1)
    local function Check(label, y, initial)
        local checked = initial
        local box = Bitmap(panel); box:SetSolidColor('ff263b4b')
        box.Width:Set(L.ScaleNumber(23)); box.Height:Set(L.ScaleNumber(23))
        L.AtLeftTopIn(box, panel, 22, y)
        local mark = UI.CreateText(box, checked and 'X' or '', 17, UI.bodyFont)
        mark:SetColor('ff59e0cf'); L.AtCenterIn(mark, box); mark:DisableHitTest()
        Text(label, 15, 57, y + 1)
        box.HandleEvent = function(self, event)
            if event.Type == 'ButtonPress' then
                checked = not checked; mark:SetText(checked and 'X' or ''); return true
            end
            return false
        end
        return function() return checked end
    end
    local enabled = Check('Enable chat mention popups', 320, config.enabled)
    local simulation = Check('Simulation mode - local test every 10 seconds', 355, config.simulation)
    local sound = Check('Play notification sound when a message pops up', 390, config.sound)
    local status = Text('Test Popup is immediate. Save to keep changes for incoming messages.', 12, 22, 431, 'ff9fb1c2')
    local function Draft()
        local value = tonumber(seconds:GetText())
        if not value or value ~= math.floor(value) or value < 1 or value > 120 then
            status:SetText('Enter a whole number of seconds from 1 to 120.'); return nil
        end
        local size = tonumber(fontSize:GetText())
        if not size or size ~= math.floor(size) or size < 12 or size > 32 then
            status:SetText('Enter a whole font size from 12 to 32.'); return nil
        end
        return {enabled = enabled(), seconds = value, nicknames = names:GetText(),
                fontSize = size, simulation = simulation(), sound = sound()}
    end
    preview = function()
        local draft = Draft()
        if draft then import('/mods/Microchip-Chat-Mention/modules/popup.lua').Preview({
            sender = 'Teammate', channel = 'ALLIES', seconds = draft.seconds,
            fontSize = draft.fontSize, sound = draft.sound,
            text = (Mention.PlayerName() ~= '' and Mention.PlayerName() or 'Microchip') .. ', can you cover the north side?',
        }) end
    end
    Button('Test Popup', 10, 462, preview)
    Button('Save', 204, 462, function()
        local draft = Draft()
        if draft then Mention.Save(draft); popup:Close() end
    end)
    Button('Close', 398, 462, function() popup:Close() end)
    return popup
end
