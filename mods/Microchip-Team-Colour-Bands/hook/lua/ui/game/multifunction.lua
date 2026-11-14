-- Microchip Team Colour Bands: an extra overlay button right after FAF's team colour button.
local Bands = import('/mods/Microchip-Team-Colour-Bands/modules/bands.lua')

local function BandsScoreboard(map)
    -- Reuse FAF's helper (local to this file) so Supreme Score Board is covered too.
    local ok = pcall(changeScoreboardColors, map)
    if not ok then WARN('Microchip Team Colour Bands: scoreboard colours not applied') end
end

function BandsEnable(on)
    local btn = GetButton('microchip_bands')
    if on then
        local faf = GetButton('teamcolor')
        if faf and faf._checkState == 'checked' then
            TeamColorMode(false); BandsScoreboard(); faf:SetCheck(false, true)
        end
        local map = Bands.Calculate()
        TeamColorMode(Bands.ModeString(map))
        TeamColorMode(true)
        BandsScoreboard(map)
        Bands.SetActive(true, map)
    else
        TeamColorMode(false)
        BandsScoreboard()
        Bands.SetActive(false)
    end
    if btn then btn:SetCheck(on and true or false, true) end
end

local bandsMenu
local function CloseBandsMenu()
    if bandsMenu then bandsMenu:Destroy(); bandsMenu = nil end
end

local function OpenBandsMenu(btn)
    CloseBandsMenu()
    local s = Bands.Settings()
    bandsMenu = Bitmap(GetFrame(0))
    bandsMenu:SetSolidColor('ee111518')
    bandsMenu.Width:Set(LayoutHelpers.ScaleNumber(230)); bandsMenu.Height:Set(LayoutHelpers.ScaleNumber(100))
    bandsMenu.Depth:Set(GetFrame(0):GetTopmostDepth() + 5)
    LayoutHelpers.Below(bandsMenu, btn, 4)
    local options = {
        {key = 'autoEnable', text = function() return (s.autoEnable and '[x] ' or '[ ] ') .. 'Turn on at game start' end},
        {key = 'keepBlue', text = function() return (s.keepBlue and '[x] ' or '[ ] ') .. 'Keep me blue' end},
        {key = 'order', text = function() return 'Order: ' .. (s.order == 'name' and 'by name' or 'by slot') end},
        {key = 'close', text = function() return 'Close' end},
    }
    for i, option in options do
        local item = UIUtil.CreateText(bandsMenu, option.text(), 13, UIUtil.bodyFont)
        LayoutHelpers.AtLeftTopIn(item, bandsMenu, 8, 6 + (i - 1) * 22)
        item.option = option
        item.HandleEvent = function(self, event)
            if event.Type == 'MouseEnter' then self:SetColor('ff9fe1cb')
            elseif event.Type == 'MouseExit' then self:SetColor('ffffffff')
            elseif event.Type == 'ButtonPress' then
                local key = self.option.key
                if key == 'close' then CloseBandsMenu(); return true end
                if key == 'order' then s.order = s.order == 'name' and 'slot' or 'name'
                else s[key] = not s[key] end
                Bands.SaveSettings(s)
                self:SetText(self.option.text())
                if Bands.IsActive() then BandsEnable(true) end
            end
            return true
        end
    end
end

-- Insert right after 'teamcolor' so the layout places it next to that button.
do
    local position = table.getn(buttons.overlays) + 1
    for i, data in buttons.overlays do
        if data.id == 'teamcolor' then position = i + 1; break end
    end
    table.insert(buttons.overlays, position, {
        tooltip = {text = 'Team colour bands',
            body = 'Every ally a different green, every enemy a different red. Right-click for settings.'},
        bitmap = 'team-color',
        id = 'microchip_bands',
        disableInReplay = true,
        OnClick = function(self, modifiers)
            if modifiers.Right then
                if bandsMenu then CloseBandsMenu() else OpenBandsMenu(self) end
                return
            end
            BandsEnable(not Bands.IsActive())
        end,
    })
end

-- Green/red stripes over the borrowed icon so it is distinguishable from FAF's button.
local bandsOriginalCreate = Create
function Create(parent)
    bandsOriginalCreate(parent)
    local btn = GetButton('microchip_bands')
    if not btn then return end
    local stripes = {'ffccffb3', 'ff66d94a', 'ff1f8020', 'ffff7a6b', 'ffe01010', 'ff800808'}
    for i, colour in stripes do
        local stripe = Bitmap(btn)
        stripe:SetSolidColor(colour)
        stripe:DisableHitTest()
        stripe.Width:Set(LayoutHelpers.ScaleNumber(3)); stripe.Height:Set(LayoutHelpers.ScaleNumber(4))
        LayoutHelpers.AtLeftIn(stripe, btn, 9 + (i - 1) * 3)
        LayoutHelpers.AtBottomIn(stripe, btn, 7)
        stripe.Depth:Set(function() return btn.Depth() + 2 end)
    end
end

-- Turning FAF's own team colour mode on switches bands off.
local bandsOriginalTeamColorHandler = TeamColorHandler
function TeamColorHandler(self, modifiers)
    if not modifiers.Right and Bands.IsActive() then
        Bands.SetActive(false)
        local btn = GetButton('microchip_bands'); if btn then btn:SetCheck(false, true) end
    end
    return bandsOriginalTeamColorHandler(self, modifiers)
end

ForkThread(function()
    WaitSeconds(1)
    if Bands.Settings().autoEnable and not SessionIsReplay() and GetFocusArmy() > 0 then BandsEnable(true) end
end)
