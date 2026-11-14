-- UI-only replacement of the Connectivity contents; no commands or packets sent.
local LagLinks = import('/mods/Microchip-F11-Lag-Connectivity-Screen/modules/analysis.lua')
local UIUtil = import('/lua/ui/uiutil.lua')
local Layout = import('/lua/maui/layouthelpers.lua')
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local SessionClients = import('/lua/ui/override/sessionclients.lua')
local group, worker, rows, localRow, notice
local tracker = LagLinks.New()
local getClients = GetSessionClients
-- Optional: player names follow Microchip Team Colour Bands when that mod is enabled.
local Bands = rawget(_G, 'exists') and exists('/mods/Microchip-Team-Colour-Bands/modules/bands.lua')
    and import('/mods/Microchip-Team-Colour-Bands/modules/bands.lua') or nil
local function Text(parent, value, size, x, y)
    local text = UIUtil.CreateText(parent, value, size, UIUtil.bodyFont)
    Layout.AtLeftTopIn(text, parent, x, y)
    return text
end
local function WaitColor(value)
    if value < 100 then return 'ff66ff66' end
    if value < 250 then return 'ffffff66' end
    if value < 500 then return 'ffffaa33' end
    return 'ffff5555'
end
function PingUpdate()
    local clients = getClients() or {}
    local labels = tracker:Update(clients, GetSystemTimeSeconds())
    local ranked = LagLinks.Ranked(clients)
    local observed = 0
    for _, client in pairs(clients) do
        if client['local'] then
            localRow:SetText(tostring(client.name or 'You') .. ' (You) - Local player')
            local data = client.fafReNetwork or {}
            observed = data.waitObservedSeconds or 0
        end
    end
    for index, slot in ipairs(rows) do
        local item = ranked[index]
        if item then
            slot.bg:Show()
            local client = item.client
            slot.name:SetText(tostring(index) .. '  ' .. string.sub(tostring(client.name or 'Player'), 1, 25))
            slot.note:SetText(labels[item.id] or '')
            slot.note:SetColor('ffffaa66')
            local band = Bands and Bands.ColourForName(client.name)
            slot.name:SetColor(client.connected and (band or 'ffffffff') or 'ffff5555')
            slot.percent:SetText(item.measured and string.format('%.1f%%', item.percent) or '--')
            slot.longest:SetText(item.measured and string.format('%.0f ms', item.longest) or '--')
            slot.percent:SetColor(item.measured and (item.percent < 1 and 'ff66ff66' or item.percent < 5 and 'ffffff66' or item.percent < 15 and 'ffffaa33' or 'ffff5555') or 'ffaaaaaa')
            slot.longest:SetColor(item.measured and WaitColor(item.longest) or 'ffaaaaaa')
            local g = item.gamePercent
            slot.game:SetText(g and string.format('%.1f%%', g) or '--')
            slot.game:SetColor(g and (g < 1 and 'ff66ff66' or g < 5 and 'ffffff66' or g < 15 and 'ffffaa33' or 'ffff5555') or 'ffaaaaaa')
            slot.average:SetText(item.averageWaitMs and string.format('%.0f ms', item.averageWaitMs) or '--')
            slot.average:SetColor(item.averageWaitMs and 'ffffffff' or 'ffaaaaaa')
            slot.total:SetText(LagLinks.FormatWaitDuration(item.totalWaitSeconds))
            slot.total:SetColor(item.totalWaitSeconds and 'ffffffff' or 'ffaaaaaa')
            local ping = client.ping
            local hasPing = client.connected and type(ping) == 'number' and ping == ping and ping >= 0 and ping < 1000000
            slot.ping:SetText(hasPing and string.format('%.0f ms', ping) or '--')
            slot.ping:SetColor(hasPing and (ping < 200 and 'ff66ff66' or ping < 400 and 'ffffff66' or 'ffff5555') or 'ffaaaaaa')
        else slot.bg:Hide() end
    end
    if observed <= 0 then notice:SetText('Wait timing unavailable: requires the updated faf-re engine.')
    elseif observed < 29.9 then notice:SetText(string.format('Collecting wait history: %.0f / 30 seconds. Shared waits can overlap.', observed))
    else notice:SetText('Worst wait first. Shared waits overlap; network or CPU delays can cause waits.') end
end
function CloseWindow()
    if worker then KillThread(worker); worker = nil end
    if group then
        RemoveInputCapture(group)
        group:Destroy(); group = nil
        SessionClients.ResetInterval()
        ConExecute('ren_shownetworkstats false')
    end
    tracker = LagLinks.New()
end
function CreateUI()
    if group then CloseWindow(); return end
    if not SessionIsMultiplayer() then return end
    local _, connected = UIUtil.GetNetworkBool()
    if not connected then return end
    local clients = getClients() or {}
    local count = table.getn(LagLinks.Ranked(clients))
    local visible = math.max(1, count)
    local rowHeight = math.min(52, math.max(30, math.floor((GetFrame(0).Height() - 340) / visible)))
    local height = 165 + visible * rowHeight
    SessionClients.FastInterval()
    ConExecute('ren_shownetworkstats true')
    group = Bitmap(GetFrame(0), UIUtil.UIFile('/scx_menu/panel-brd/panel_brd_m.dds'))
    group.Width:Set(930); group.Height:Set(height)
    group.Depth:Set(GetFrame(0):GetTopmostDepth() + 10)
    group.wc = UIUtil.CreateWorldCover(group)
    group.border = UIUtil.CreateSCXMenuPanelBorder(group)
    group.brackets = UIUtil.CreateDialogBrackets(group, 106, 110, 110, 108, true)
    local title = UIUtil.CreateText(group.border.tm, '<LOC _Connectivity>', 20)
    Layout.AtTopIn(title, group.border.tm, 12); Layout.AtHorizontalCenterIn(title, group)
    Text(group, 'Waiting for player commands', 14, 10, 4)
    Text(group, 'Player', 15, 10, 30)
    Text(group, 'Wait 30s', 15, 250, 30)
    Text(group, 'Wait game', 15, 345, 30)
    Text(group, 'Total wait', 15, 445, 30)
    Text(group, 'Avg wait', 15, 555, 30)
    Text(group, 'Longest 30s', 15, 665, 30)
    Text(group, 'Ping', 15, 810, 30)
    rows = {}
    for i = 1, count do
        local bg = Bitmap(group, UIUtil.UIFile('/scx_menu/panel-brd/conn-bg.dds'))
        bg.Width:Set(930); bg.Height:Set(rowHeight)
        Layout.AtLeftTopIn(bg, group, 0, 55 + (i - 1) * rowHeight)
        rows[i] = {bg = bg, name = Text(bg, '', 17, 10, 2), note = Text(bg, '', 12, 10, 24),
            percent = Text(bg, '', 17, 250, 2), game = Text(bg, '', 17, 345, 2),
            total = Text(bg, '', 17, 445, 2), average = Text(bg, '', 17, 555, 2), longest = Text(bg, '', 17, 665, 2), ping = Text(bg, '', 17, 810, 2)}
    end
    if count == 0 then Text(group, 'No remote players connected.', 16, 10, 60) end
    localRow = Text(group, 'You - Local player', 15, 10, 60 + visible * rowHeight)
    notice = Text(group, '', 13, 10, 86 + visible * rowHeight)
    local close = UIUtil.CreateButtonStd(group, '/scx_menu/small-btn/small', '<LOC _Close>', 16, 2)
    Layout.AtTopIn(close, group.border.bm, -20); Layout.AtHorizontalCenterIn(close, group)
    close.OnClick = CloseWindow
    AddInputCapture(group)
    group.HandleEvent = function(self, event)
        if event.Type == 'KeyDown' and (event.KeyCode == UIUtil.VK_ESCAPE or event.KeyCode == UIUtil.VK_ENTER or event.KeyCode == 352) then CloseWindow() end
    end
    Layout.AtCenterIn(group, GetFrame(0))
    worker = ForkThread(function() while group do PingUpdate(); WaitSeconds(.5) end end)
end
