-- faf-re's lobby screen, in the in-game launcher's style (launcher/theme.lua): the players and their slots, the map
-- with its start positions, the game options, observers, chat, ready and launch.
--
-- It is a view over FAF's lobby, never a second lobby: FAF's lobby.lua keeps the game state, the network and the
-- host's authority, and its own screen stays built underneath. Every change made here goes through what FAF's own
-- controls run (their OnClick and OnCheck handlers, DoSlotBehavior, SetGameOption, the map dialog's steps), and every
-- permission is read from FAF's own controls (enabled or not), so both screens always agree. The hook appended to
-- FAF's lobby.lua (/fafengine/lua/ui/lobby/lobby.lua) hands over FafReLobbyApi and creates this after CreateUI; if
-- building it fails, FAF's screen is what shows. "Classic view" switches to FAF's screen and back.

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')
local MapUtil = import('/lua/ui/maputil.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors

-- The player's FAF friends (FafOnline_Social), read again at most every 2 s (each slot asks on each paint).
local socialCache = nil
local socialAt = 0
local function Social()
    if not rawget(_G, 'FafOnline_Social') then
        return { friends = {}, foes = {} }
    end
    if not socialCache or GetSystemTimeSeconds() - socialAt > 2 then
        socialCache = FafOnline_Social()
        socialAt = GetSystemTimeSeconds()
    end
    return socialCache
end

local function IsFriend(id)
    return id ~= nil and Social().friends[tostring(id)] == true
end

--- Whether the menu of a player's slot can add them to the friends or remove them (a FAF id, signed in).
local function CanFriend(api, player)
    return player and player.Human and player.OwnerID ~= api.LocalPlayerID() and
        rawget(_G, 'FafOnline_SetFriend') ~= nil and string.find(tostring(player.OwnerID), '^%d+$') ~= nil
end

--- A player's own name colour (aarrggbb), when the engine has proven one for them in this lobby.
local function NameStyle(id)
    local style = id ~= nil and rawget(_G, 'FafNet_PeerStyle') and FafNet_PeerStyle(tostring(id)) or nil
    return style and ('ff' .. style) or nil
end
local Scale = Theme.Scale

local kRefreshSeconds = 0.3
-- How often the FAF game behind the lobby is looked up again (FafOnline_Games builds the whole list).
local kMatchGameSeconds = 3

-- FAF's featured mods by their names in FAF's lists.
local kFeaturedModNames = { faf = 'FAF', fafbeta = 'FAF Beta', fafdevelop = 'FAF Develop', nomads = 'Nomads',
    ladder1v1 = 'Ladder', coop = 'Co-op' }

local loggedMatchMiss = false

--- The FAF game this lobby is, while the launcher's match runs it: FafOnline_Games' entry for the status's
--- matchGame (the lobby only has a title its host typed in FAF's title dialog), or nil.
local function MatchGame()
    local status = rawget(_G, 'FafOnline_Status')
    local games = rawget(_G, 'FafOnline_Games')
    -- The engine's functions are of type cfunction in this Lua, not function.
    if not status or not games then
        if not loggedMatchMiss then
            loggedMatchMiss = true
            LOG('faf-re lobby: no online functions here (FafOnline_Status ' .. type(status) .. ', FafOnline_Games ' ..
                type(games) .. ')')
        end
        return nil
    end
    local ok, state = pcall(status)
    if not ok or type(state) ~= 'table' or state.match ~= 'running' or not state.matchGame or state.matchGame == '' then
        if not loggedMatchMiss then
            loggedMatchMiss = true
            LOG('faf-re lobby: no FAF game behind this lobby (match ' .. tostring(ok and type(state) == 'table' and
                state.match) .. ', game ' .. tostring(ok and type(state) == 'table' and state.matchGame) .. ')')
        end
        return nil
    end
    local okGames, list = pcall(games)
    if not okGames or type(list) ~= 'table' then
        return nil
    end
    for _, game in list do
        if tostring(game.uid) == state.matchGame then
            return game
        end
    end
    if not loggedMatchMiss then
        loggedMatchMiss = true
        LOG('faf-re lobby: FAF game ' .. state.matchGame .. ' is not in the list of ' .. table.getn(list) .. ' games')
    end
    return nil
end

--- Whether our lobby screen shows: on, unless the player turned it off (options key fafre_lobby = false). An
--- organiser's read-only lobby on a game server keeps FAF's locked screen.
function Wanted()
    if rawget(_G, 'ServerLobbyControl') == 'organiser' then
        return false
    end
    return Prefs.GetOption('fafre_lobby') ~= false
end

local current = false

--- The lobby screen on screen now, or false.
function Current()
    return current
end

local function PlayerColor(index)
    local colors = import('/lua/gamecolors.lua').GameColors.PlayerColors
    return colors[index] or C.subtle
end

--- A faction's picture, sharp at the rows' 24 units on a big screen: FAF's 64 px ones (its autolobby's
--- faction_icon-lg/<key>_med.dds), else the 60 px LargeIcon; FAF's small ones are 18 px and blur when stretched.
--- Random is drawn (a question mark), as no large picture of it exists.
local function FactionIcon(key)
    local fallback = UIUtil.UIFile('/faction_icon-sm/random_ico.dds')
    if key == 'random' then
        return Theme.IconTexture('circleHelp', 24, C.muted, 2) or fallback
    end
    for _, faction in import('/lua/factions.lua').Factions do
        if faction.Key == key then
            local medium = '/textures/ui/common/faction_icon-lg/' .. key .. '_med.dds'
            if DiskGetFileInfo(medium) then
                return medium
            end
            return UIUtil.UIFile(faction.LargeIcon or faction.SmallIcon)
        end
    end
    return fallback
end

local function FactionName(key)
    if key == 'random' then
        return 'Random'
    end
    for _, faction in import('/lua/factions.lua').Factions do
        if faction.Key == key then
            return LOC(faction.DisplayName)
        end
    end
    return key or ''
end

local function Enabled(control)
    return control ~= nil and not control:IsHidden() and not control:IsDisabled()
end

local function Strip(text)
    return LOC(text or '')
end

--- An option value's key: its `key` field (which may be false, as Allow Observers' No), else the value itself.
local function ValueKey(value)
    if type(value) == 'table' and value.key ~= nil then
        return value.key
    end
    return value
end

--- An option value's text as FAF's lobby shows it: some are a format with the value's key in it ("%s").
local function ValueText(text, key)
    text = LOC(text or '')
    if string.find(text, '%%s') then
        return string.format(text, tostring(key))
    end
    return text
end

-- ---------------------------------------------------------------------------------------------------------------
-- The players: one row a slot.

-- The player table's columns, from a row's right edge in layout units: where each one's right side is and its width.
-- Three sets by the width the table has: "wide" has everything, "narrow" leaves out the CPU score and makes the boxes
-- smaller, "compact" also leaves out the link and shows the faction by its picture only.
local kLayouts = {
    wide = {
        menu = { right = 6, width = 28 },
        ready = { right = 38, width = 40 },
        ping = { right = 82, width = 54 },
        link = { right = 140, width = 58 },
        cpu = { right = 204, width = 74 },
        color = { right = 284, width = 36 },
        faction = { right = 326, width = 136 },
        team = { right = 468, width = 90 },
    },
    narrow = {
        menu = { right = 6, width = 28 },
        ready = { right = 38, width = 36 },
        ping = { right = 78, width = 48 },
        link = { right = 130, width = 48 },
        color = { right = 190, width = 44 },
        faction = { right = 240, width = 104 },
        team = { right = 350, width = 76 },
    },
    compact = {
        menu = { right = 6, width = 28 },
        ready = { right = 36, width = 34 },
        ping = { right = 74, width = 44 },
        color = { right = 122, width = 28 },
        faction = { right = 154, width = 46 },
        team = { right = 204, width = 64 },
    },
}
-- Where a name starts: after the slot number and the flag's place.
local kNameLeft = 68

--- The layout for a table this many units wide.
local function LayoutFor(units)
    if units >= 780 then
        return 'wide'
    elseif units >= 640 then
        return 'narrow'
    end
    return 'compact'
end

local function Column(layout, name)
    return kLayouts[layout][name]
end

local function ColumnRight(row, name, layout)
    local column = Column(layout, name)
    return function() return row.Right() - Scale(column.right) end
end

local function ColumnLeft(row, name, layout)
    local column = Column(layout, name)
    return function() return row.Right() - Scale(column.right + column.width) end
end

--- A control centred on a column.
local function CenterOnColumn(control, row, name, layout)
    local column = Column(layout, name)
    control.Left:Set(function()
        return row.Right() - Scale(column.right + math.floor(column.width / 2)) - math.floor(control.Width() / 2)
    end)
end

--- A player's flag as FAF's lobby shows it (its country code as the file name), or nil when FAF knows no country
--- (FAF's world picture, a question mark, says no more than an empty place).
local function CountryFlag(country)
    if country and country ~= '' and country ~= 'world' then
        return UIUtil.UIFile('/countries/' .. string.lower(country) .. '.dds') -- FAF ships them lower case
    end
    return nil
end

--- A CPU benchmark's colour: FAF's score, lower is faster.
local function CpuColor(score)
    if score <= 150 then
        return C.good
    elseif score <= 250 then
        return C.warn
    end
    return C.bad
end

local function PingColor(ping)
    if ping < 120 then
        return C.text
    elseif ping < 250 then
        return C.warn
    end
    return C.bad
end

--- A box in a row that opens a picker (team, faction): a field with a chevron while the player may change it, plain
--- text when not. :Paint(text, can, over), and .icon for a picture before the text.
local function SelectBox(row, name, layout, withIcon)
    local box = Theme.Panel(row, C.field, C.line)
    box.Left:Set(ColumnLeft(row, name, layout))
    box.Right:Set(ColumnRight(row, name, layout))
    box.Width:Set(function() return box.Right() - box.Left() end)
    LayoutHelpers.SetHeight(box, 24)
    LayoutHelpers.AtVerticalCenterIn(box, row)
    local textLeft = 10
    if withIcon then
        box.icon = Bitmap(box)
        box.icon:DisableHitTest()
        LayoutHelpers.SetDimensions(box.icon, 18, 18)
        LayoutHelpers.AtLeftIn(box.icon, box, 7)
        LayoutHelpers.AtVerticalCenterIn(box.icon, box)
        textLeft = 31
    end
    box.chevron = Theme.Icon(box, 'chevronDown', 14, C.muted, 2)
    LayoutHelpers.AtRightIn(box.chevron, box, 7)
    LayoutHelpers.AtVerticalCenterIn(box.chevron, box)
    box.label = Theme.Cell(box, 13, C.text)
    box.label.Left:Set(function() return box.Left() + Scale(textLeft) end)
    box.label.Right:Set(function() return box.chevron.Left() - Scale(4) end)
    LayoutHelpers.AtVerticalCenterIn(box.label, box)
    box.Paint = function(self, text, can, over)
        Theme.SetText(self.label, text)
        Theme.SetColor(self.label, can and C.text or C.muted)
        Theme.SetVisible(self.chevron, can and true or false)
        if can then
            self:SetColors(C.field, over and C.accent or C.line)
        else
            self:SetColors(C.clear, C.clear)
        end
    end
    return box
end

local function MakeSlotRow(view, parent, slot, layout)
    local row = Theme.Panel(parent, C.panel, C.line)
    row.slot = slot
    row.layout = layout
    local number = Theme.Text(row, tostring(slot), 13, C.subtle)
    LayoutHelpers.AtLeftIn(number, row, 12)
    LayoutHelpers.AtVerticalCenterIn(number, row)
    local flag = Bitmap(row)
    flag:DisableHitTest()
    LayoutHelpers.SetDimensions(flag, 20, 14)
    LayoutHelpers.AtLeftIn(flag, row, 40)
    LayoutHelpers.AtVerticalCenterIn(flag, row)

    -- Name, then the rating in grey and a tag (host, AI) right after it, all left of the team box.
    local team = SelectBox(row, 'team', layout, false)
    local name = Theme.Cell(row, 14, C.text, true)
    name.Left:Set(function() return row.Left() + Scale(kNameLeft) end)
    name.Right:Set(function() return team.Left() - Scale(12) end)
    LayoutHelpers.AtVerticalCenterIn(name, row)
    local rating = Theme.Text(row, '', 12, C.subtle)
    LayoutHelpers.AtVerticalCenterIn(rating, row, 1)
    local badge = Theme.Tag(row, 'Host', C.gold)
    badge.Left:Set(function() return rating.Right() + Scale(8) end)
    LayoutHelpers.AtVerticalCenterIn(badge, row)
    -- A friend: this mark where the name starts (the name moves right by it), and the name in green.
    local friend = Theme.Icon(row, 'userCheck', 16, C.good)
    LayoutHelpers.AtLeftIn(friend, row, kNameLeft)
    LayoutHelpers.AtVerticalCenterIn(friend, row)

    local faction = SelectBox(row, 'faction', layout, true)
    local swatch = Theme.Panel(row, C.subtle, C.lineStrong)
    LayoutHelpers.SetDimensions(swatch, 18, 18)
    CenterOnColumn(swatch, row, 'color', layout)
    LayoutHelpers.AtVerticalCenterIn(swatch, row)

    local parts = { number = number, flag = flag, name = name, rating = rating, badge = badge, team = team,
        faction = faction, swatch = swatch, friend = friend }

    -- CPU: a bar of FAF's benchmark score (fuller is slower, full at FAF's 450) and the score after it.
    if Column(layout, 'cpu') then
        local cpu = Group(row)
        cpu:DisableHitTest()
        cpu.Left:Set(ColumnLeft(row, 'cpu', layout))
        cpu.Right:Set(ColumnRight(row, 'cpu', layout))
        cpu.Top:Set(row.Top)
        cpu.Bottom:Set(row.Bottom)
        cpu.Width:Set(function() return cpu.Right() - cpu.Left() end)
        cpu.Height:Set(function() return cpu.Bottom() - cpu.Top() end)
        local cpuText = Theme.Text(cpu, '', 12, C.text, true)
        cpuText.Right:Set(cpu.Right)
        LayoutHelpers.AtVerticalCenterIn(cpuText, cpu)
        local cpuTrack = Theme.Rect(cpu, C.line)
        cpuTrack.Left:Set(cpu.Left)
        cpuTrack.Right:Set(function() return cpu.Right() - Scale(32) end)
        cpuTrack.Height:Set(Scale(5))
        cpuTrack.Width:Set(function() return cpuTrack.Right() - cpuTrack.Left() end)
        LayoutHelpers.AtVerticalCenterIn(cpuTrack, cpu)
        local cpuFill = Theme.Rect(cpu, C.good)
        cpuFill.Left:Set(cpu.Left)
        cpuFill.Top:Set(cpuTrack.Top)
        cpuFill.Height:Set(Scale(5))
        cpuFill.Depth:Set(function() return cpuTrack.Depth() + 1 end)
        parts.cpu, parts.cpuText, parts.cpuTrack, parts.cpuFill = cpu, cpuText, cpuTrack, cpuFill
    end
    if Column(layout, 'link') then
        parts.link = Theme.Text(row, '', 13, C.muted)
        parts.link.Left:Set(ColumnLeft(row, 'link', layout))
        LayoutHelpers.AtVerticalCenterIn(parts.link, row)
    end
    parts.ping = Theme.Text(row, '', 13, C.text)
    parts.ping.Right:Set(ColumnRight(row, 'ping', layout))
    LayoutHelpers.AtVerticalCenterIn(parts.ping, row)

    -- Ready: a box, ticked when the player is ready; the player's own box changes it, as FAF's does.
    local ready = Theme.Panel(row, C.clear, C.lineStrong)
    LayoutHelpers.SetDimensions(ready, 20, 20)
    CenterOnColumn(ready, row, 'ready', layout)
    LayoutHelpers.AtVerticalCenterIn(ready, row)
    ready.check = Theme.Icon(ready, 'check', 14, C.good, 2.6)
    LayoutHelpers.AtCenterIn(ready.check, ready)
    parts.ready = ready

    local menu = Theme.Button(row, '', function()
        view:OpenSlotMenu(slot, row)
    end, 'ghost', { icon = 'chevronDown', width = 28, height = 28 })
    menu.Right:Set(ColumnRight(row, 'menu', layout))
    LayoutHelpers.AtVerticalCenterIn(menu, row)
    parts.menu = menu

    local mark = Theme.Rect(row, C.accent)
    mark.Left:Set(row.Left)
    mark.Top:Set(row.Top)
    mark.Bottom:Set(row.Bottom)
    mark.Width:Set(Scale(3))
    mark.Height:Set(function() return mark.Bottom() - mark.Top() end)
    parts.mark = mark

    -- Clicks: the team, faction and colour pickers and the ready box where FAF's control for them is enabled; a
    -- right click anywhere, or a left click on an empty slot, opens the slot's menu.
    local function Clickable(control, key, onPress)
        Theme.HitArea(control, function(self, event)
            if event.Type == 'MouseEnter' then
                row.overPart = key
                view:PaintSlot(row)
            elseif event.Type == 'MouseExit' then
                row.overPart = nil
                view:PaintSlot(row)
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left and row.can and row.can[key] then
                Theme.ClickSound()
                onPress()
                return true
            elseif event.Type == 'ButtonPress' and event.Modifiers.Right then
                view:OpenSlotMenu(slot, row)
                return true
            end
            return false
        end).Depth:Set(function() return row.Depth() + 20 end)
    end
    Clickable(team, 'team', function() view:OpenPicker('team', slot, team) end)
    Clickable(faction, 'faction', function() view:OpenPicker('faction', slot, faction) end)
    Clickable(swatch, 'color', function() view:OpenPicker('color', slot, swatch) end)
    Clickable(ready, 'ready', function() view.api.ToggleReady() end)
    Theme.HitArea(row, function(self, event)
        if event.Type == 'MouseEnter' then
            row.over = true
            view:PaintSlot(row)
        elseif event.Type == 'MouseExit' then
            row.over = false
            view:PaintSlot(row)
        elseif event.Type == 'ButtonPress' and (event.Modifiers.Right or (event.Modifiers.Left and not row.player)) then
            Theme.ClickSound()
            view:OpenSlotMenu(slot, row)
            return true
        end
        return false
    end).Depth:Set(function() return row.Depth() + 2 end)
    menu.Depth:Set(function() return row.Depth() + 25 end)

    row.parts = parts
    return row
end

local function TeamLabel(team)
    if not team or team <= 1 then
        return 'None'
    end
    return 'Team ' .. (team - 1)
end

local LobbyView = {}
LobbyView.__index = LobbyView

--- A player's link as the game's own links (FafNet_Links) or the lobby (FAF's peer status) know it: text, colour.
function LobbyView:LinkOf(player)
    local links = self.links
    if links and links.peers then
        for _, link in links.peers do
            if link.id == tostring(player.OwnerID) or (link.login ~= '' and link.login == player.PlayerName) then
                if link.connected then
                    if link.localType == 'relay' or link.remoteType == 'relay' then
                        return 'relay', C.warn, link
                    end
                    return 'direct', C.good, link
                end
                local state = string.lower(link.state or '')
                if state == 'failed' or state == 'closed' then
                    return 'failed', C.bad, link
                end
                return 'linking', C.muted, link
            end
        end
    end
    local peer = self.api.Peer and self.api.Peer(player.OwnerID)
    if peer and peer.status == 'Established' then
        return 'linked', C.muted, nil
    end
    return 'linking', C.muted, nil
end

function LobbyView:PaintSlot(row)
    local api = self.api
    local info = api.GameInfo()
    local slot = row.slot
    local player = info.PlayerOptions[slot]
    local fafSlot = api.GUI().slots and api.GUI().slots[slot]
    local p = row.parts
    local closed = info.ClosedSlots[slot]
    local human = player and player.Human
    -- The host owns its AIs too: only a human slot is "mine".
    local mine = human and player.OwnerID == api.LocalPlayerID()
    local withOthers = not api.IsSinglePlayer()
    local flag = human and CountryFlag(player.Country) or nil
    row.player = player
    row.can = {
        color = player and fafSlot and Enabled(fafSlot.color),
        faction = player and fafSlot and Enabled(fafSlot.faction),
        team = player and fafSlot and Enabled(fafSlot.team),
        ready = mine and withOthers and fafSlot and Enabled(fafSlot.ready),
    }
    Theme.SetVisible(p.mark, mine and true or false)
    Theme.SetVisible(p.flag, flag ~= nil)
    Theme.SetVisible(p.team, player ~= nil)
    Theme.SetVisible(p.faction, player ~= nil)
    Theme.SetVisible(p.swatch, player ~= nil)
    local keys = api.SlotMenu(slot)
    Theme.SetVisible(p.menu, (keys ~= nil and table.getn(keys) > 0) or CanFriend(api, player) and true or false)
    -- A friend's name moves right for the mark before it; any other row's name sits at its place.
    local isFriend = human and not mine and IsFriend(player.OwnerID)
    local shift = isFriend and 22 or 0
    if row.nameShift ~= shift then
        row.nameShift = shift
        p.name.Left:Set(function() return row.Left() + Scale(kNameLeft + shift) end)
    end
    Theme.SetVisible(p.friend, isFriend and true or false)

    -- Rating, link, ping and ready count for a game with other players only.
    local rated = human and withOthers
    Theme.SetVisible(p.rating, rated and true or false)
    Theme.SetVisible(p.ping, (human and withOthers) and true or false)
    if p.link then
        Theme.SetVisible(p.link, (human and withOthers) and true or false)
    end
    Theme.SetVisible(p.ready, (human and withOthers) and true or false)
    Theme.SetVisible(p.ready.check, (human and withOthers and player.Ready) and true or false)
    p.ready:SetColors(C.clear, (human and player.Ready) and C.good or
        ((row.can.ready and row.overPart == 'ready') and C.accent or C.lineStrong))

    if p.cpu then
        local score = human and api.Cpu(player.PlayerName) or nil
        Theme.SetVisible(p.cpu, score ~= nil)
        Theme.SetVisible(p.cpuText, score ~= nil)
        Theme.SetVisible(p.cpuTrack, score ~= nil)
        Theme.SetVisible(p.cpuFill, score ~= nil)
        if score then
            score = math.floor(score)
            Theme.SetText(p.cpuText, tostring(score))
            Theme.SetColor(p.cpuText, CpuColor(score))
            p.cpuFill:SetSolidColor(CpuColor(score))
            local share = math.min(1, math.max(0.04, score / 450))
            if row.cpuShare ~= share then
                row.cpuShare = share
                p.cpuFill.Width:Set(function() return math.floor(p.cpuTrack.Width() * share) end)
            end
        end
    end

    local label
    if player then
        p.swatch:SetColors(PlayerColor(player.PlayerColor),
            (row.can.color and row.overPart == 'color') and C.text or (row.can.color and C.lineStrong or C.clear))
        local factions = fafSlot and fafSlot.AvailableFactions or {}
        local key = factions[player.Faction] or 'random'
        if row.factionKey ~= key then
            row.factionKey = key
            p.faction.icon:SetTexture(FactionIcon(key))
            LayoutHelpers.SetDimensions(p.faction.icon, 18, 18)
        end
        p.faction:Paint(row.layout == 'compact' and '' or FactionName(key), row.can.faction, row.overPart == 'faction')
        p.team:Paint(TeamLabel(player.Team), row.can.team, row.overPart == 'team')
        if flag and row.flagFile ~= flag then
            row.flagFile = flag
            p.flag:SetTexture(flag)
            LayoutHelpers.SetDimensions(p.flag, 20, 14)
        end
        label = player.PlayerName or ''
        if player.PlayerClan and player.PlayerClan ~= '' then
            label = '[' .. player.PlayerClan .. '] ' .. label
        end
        -- The player's own proven colour first, then the local player's accent, then a friend's green.
        local friend = human and not mine and IsFriend(player.OwnerID)
        Theme.SetColor(p.name, (human and NameStyle(player.OwnerID)) or (mine and C.accent) or
            (friend and C.good) or C.text)
        Theme.SetText(p.rating, rated and tostring(math.floor(player.PL or 0)) or '')
        if not human then
            Theme.SetVisible(p.badge, true)
            p.badge:SetTag('AI', C.violet)
        elseif withOthers and player.OwnerID == api.HostID() then
            Theme.SetVisible(p.badge, true)
            p.badge:SetTag('Host', C.gold)
        else
            Theme.SetVisible(p.badge, false)
        end
        if human and withOthers then
            if mine then
                Theme.SetText(p.ping, '-')
                Theme.SetColor(p.ping, C.subtle)
                if p.link then
                    Theme.SetText(p.link, 'you')
                    Theme.SetColor(p.link, C.subtle)
                end
            else
                local text, color, link = self:LinkOf(player)
                if p.link then
                    Theme.SetText(p.link, text)
                    Theme.SetColor(p.link, color)
                end
                local ping = api.Ping(player.OwnerID)
                if (not ping or ping <= 0) and link and link.rttMs and link.rttMs >= 0 then
                    ping = math.floor(link.rttMs + 0.5)
                end
                Theme.SetText(p.ping, ping and (ping .. ' ms') or '...')
                Theme.SetColor(p.ping, ping and PingColor(ping) or C.subtle)
            end
        end
    else
        label = closed and (info.SpawnMex and info.SpawnMex[slot] and 'Closed - spawn mex' or 'Closed') or 'Open slot'
        Theme.SetColor(p.name, closed and C.bad or C.subtle)
        Theme.SetText(p.rating, '')
        Theme.SetVisible(p.badge, false)
    end
    -- The rating and the tag follow the name's own width; the name is cut only where they would reach the team box.
    local reserve = 0
    if p.rating.shown and p.rating.shown ~= '' then
        reserve = reserve + Scale(8) + p.rating:GetStringAdvance(p.rating.shown)
    end
    if not p.badge:IsHidden() then
        reserve = reserve + Scale(8) + p.badge.Width()
    end
    if row.label ~= label or row.reserve ~= reserve then
        row.label = label
        row.reserve = reserve
        Theme.SetText(p.name, label)
        local advance = p.name:GetStringAdvance(label)
        local team = p.team
        p.name.Right:Set(function() return team.Left() - Scale(12) - reserve end)
        p.rating.Left:Set(function() return math.min(p.name.Left() + advance, p.name.Right()) + Scale(8) end)
    end
    row:SetColors(row.over and C.raised or (mine and C.selected or C.panel), row.over and C.lineStrong or C.line)
end

--- The slot's menu, as FAF's name control offers it (GetSlotMenuTables), run through DoSlotBehavior.
function LobbyView:OpenSlotMenu(slot, anchor)
    local keys, strings = self.api.SlotMenu(slot)
    local items = {}
    for i, key in keys or {} do
        local text = Strip(strings[i])
        local color = C.text
        if key == 'remove_to_kik' then
            color = C.bad
        end
        table.insert(items, { text, key = key, color = color })
    end
    -- Ours after FAF's: the player into the FAF friends, or out of them.
    local player = self.api.GameInfo().PlayerOptions[slot]
    local friendId = CanFriend(self.api, player) and tostring(player.OwnerID) or nil
    if friendId then
        table.insert(items, { IsFriend(friendId) and 'Remove from friends' or 'Add to friends', key = 'fafre_friend',
            color = C.good })
    end
    if table.getn(items) == 0 then
        return
    end
    local api = self.api
    local view = self
    Widgets.Dropdown(anchor, items, function(item)
        if item.key == 'fafre_friend' then
            local ok, why = FafOnline_SetFriend(friendId, not IsFriend(friendId))
            if not ok then
                view:AddChat(nil, 'Friends: ' .. tostring(why))
            end
            socialCache = nil
            view:Refresh()
            return
        end
        api.SlotAction(slot, item.key, item[1])
    end, { width = 260, maxRows = 16 })
end

--- Colour, faction or team for a slot, through FAF's own control for it.
function LobbyView:OpenPicker(kind, slot, anchor)
    local api = self.api
    local fafSlot = api.GUI().slots[slot]
    local items = {}
    if kind == 'color' then
        local colors = import('/lua/gamecolors.lua').GameColors.PlayerColors
        for index, color in colors do
            local free = api.IsColorFree(index, slot)
            table.insert(items, { free and ('Colour ' .. index) or ('Colour ' .. index .. ' (taken)'), key = index,
                swatch = color, color = free and C.text or C.subtle })
        end
        Widgets.Dropdown(anchor, items, function(item)
            fafSlot.color:SetItem(item.key)
            fafSlot.color.OnClick(fafSlot.color, item.key)
        end, { width = 200, maxRows = 12 })
    elseif kind == 'faction' then
        for index, key in fafSlot.AvailableFactions or {} do
            table.insert(items, { FactionName(key), key = index, icon = FactionIcon(key) })
        end
        Widgets.Dropdown(anchor, items, function(item)
            fafSlot.faction:SetItem(item.key)
            fafSlot.faction.OnClick(fafSlot.faction, item.key)
        end, { width = 200 })
    elseif kind == 'team' then
        table.insert(items, { 'No team', key = 1 })
        for team = 1, 8 do
            table.insert(items, { 'Team ' .. team, key = team + 1 })
        end
        Widgets.Dropdown(anchor, items, function(item)
            fafSlot.team:SetItem(item.key)
            fafSlot.team.OnClick(fafSlot.team, item.key, '')
        end, { width = 160 })
    end
end

-- ---------------------------------------------------------------------------------------------------------------
-- The map: FAF's own map control, so its start positions take clicks as on FAF's screen.

function LobbyView:BuildMap(parent)
    local view = self
    local card = Theme.Panel(parent, C.panel, C.line)
    Theme.Brackets(card, C.accent)
    self.mapCard = card
    local caption = Theme.Caption(card, 'Map', C.accent)
    LayoutHelpers.AtLeftTopIn(caption, card, 16, 14)
    local size = self.mapSize
    -- About how many characters of the description fit on a line beside the picture (11 px text).
    self.descriptionChars = math.max(28, math.floor((LayoutHelpers.InvScaleNumber(parent.Width()) - size - 48) / 6.2))
    local ResourceMapPreview = import('/lua/ui/controls/resmappreview.lua').ResourceMapPreview
    local frame = Theme.Panel(card, C.field, C.line)
    LayoutHelpers.SetDimensions(frame, size + 2, size + 2)
    LayoutHelpers.AtLeftTopIn(frame, card, 16, 36)
    local preview = ResourceMapPreview(frame, size, 3, 5)
    LayoutHelpers.AtLeftTopIn(preview, frame, 1, 1)
    preview.Depth:Set(function() return frame.Depth() + 1 end)
    self.preview = preview
    local left = function() return frame.Right() + Scale(16) end
    local right = function() return card.Right() - Scale(16) end
    local function Line(size, color, bold, below, gap)
        local cell = Theme.Cell(card, size, color, bold)
        cell.Left:Set(left)
        cell.Right:Set(right)
        cell.Top:Set(function() return below.Bottom() + Scale(gap) end)
        return cell
    end
    self.mapName = Theme.Cell(card, 16, C.text, true)
    self.mapName.Left:Set(left)
    self.mapName.Right:Set(right)
    self.mapName.Top:Set(frame.Top)
    self.mapSizeText = Line(12, C.muted, false, self.mapName, 6)
    self.mapPlayers = Line(12, C.muted, false, self.mapSizeText, 2)
    self.mapVersion = Line(12, C.subtle, false, self.mapPlayers, 2)
    self.mapDescription = {}
    local above = self.mapVersion
    for i = 1, 3 do
        local line = Line(11, C.subtle, false, above, i == 1 and 8 or 1)
        self.mapDescription[i] = line
        above = line
    end
    self.changeMap = Theme.Button(card, 'Change map', function()
        view:OpenMapPicker()
    end, 'secondary', { icon = 'maps', width = 150 })
    self.changeMap.Left:Set(left)
    self.changeMap.Bottom:Set(frame.Bottom)
    card.Height:Set(function() return frame.Bottom() - card.Top() + Scale(16) end)
end

--- A description cut into at most `count` lines of about `width` characters.
local function DescriptionLines(text, width, count)
    local lines = {}
    local current = ''
    local more = false
    for word in string.gfind(text or '', '%S+') do
        if table.getn(lines) >= count then
            more = true
            break
        end
        if string.len(current) + string.len(word) + 1 > width and current ~= '' then
            table.insert(lines, current)
            current = word
        else
            current = current == '' and word or (current .. ' ' .. word)
        end
    end
    if table.getn(lines) < count and current ~= '' then
        table.insert(lines, current)
    elseif current ~= '' then
        more = true
    end
    if more then
        lines[count] = lines[count] .. '...'
    end
    return lines
end

function LobbyView:RefreshMap()
    local api = self.api
    local info = api.GameInfo()
    local file = info.GameOptions.ScenarioFile
    if file and file ~= self.scenarioFile then
        self.scenarioFile = file
        local ok, scenario = pcall(MapUtil.LoadScenario, file)
        self.scenario = ok and scenario or false
        if self.scenario then
            self.preview:SetScenario(self.scenario, true)
            pcall(api.ConfigureMapListeners, self.preview, self.scenario)
            Theme.SetText(self.mapName, LOC(self.scenario.name or file))
            local armies = MapUtil.GetArmies(self.scenario) or {}
            local width = self.scenario.size and math.floor(self.scenario.size[1] / 51.2 + 0.5) or 0
            local height = self.scenario.size and math.floor(self.scenario.size[2] / 51.2 + 0.5) or 0
            Theme.SetText(self.mapSizeText, string.format('%d x %d km', width, height))
            Theme.SetText(self.mapPlayers, string.format('%d start positions', table.getn(armies)))
            Theme.SetText(self.mapVersion, self.scenario.map_version and ('Map version ' .. self.scenario.map_version) or '')
            local lines = DescriptionLines(LOC(self.scenario.description or ''), self.descriptionChars, 3)
            for i, cell in self.mapDescription do
                Theme.SetText(cell, lines[i] or '')
            end
        else
            Theme.SetText(self.mapName, 'Map not on this computer')
            Theme.SetText(self.mapSizeText, file)
            Theme.SetText(self.mapPlayers, '')
            Theme.SetText(self.mapVersion, '')
            for _, cell in self.mapDescription do
                Theme.SetText(cell, '')
            end
        end
    end
    if self.scenario then
        pcall(api.ShowMapPositions, self.preview, self.scenario)
    end
    local host = api.IsHost()
    Theme.SetVisible(self.changeMap, host)
    self.changeMap:SetEnabled(host and Enabled(api.GUI().gameoptionsButton))
end

--- Maps on this computer by name; the pick goes through what FAF's map dialog does for the host.
function LobbyView:OpenMapPicker()
    local api = self.api
    local view = self
    local frameWidth, frameHeight = Widgets.FrameUnits()
    local cover = Widgets.Modal(self.root, math.min(760, frameWidth - 24), math.max(420, math.min(560, frameHeight - 24)))
    local panel = cover.panel
    local head = Theme.Title(panel, 'Change map', 18)
    LayoutHelpers.AtLeftTopIn(head, panel, 24, 20)
    local frame = Theme.Panel(panel, C.field, C.line)
    LayoutHelpers.SetDimensions(frame, 180, 180)
    LayoutHelpers.AtLeftTopIn(frame, panel, 24, 64)
    Widgets.MapPicture(frame)
    local title = Theme.Cell(panel, 15, C.text, true)
    title.Left:Set(function() return frame.Left() end)
    title.Right:Set(function() return frame.Right() end)
    title.Top:Set(function() return frame.Bottom() + Scale(10) end)
    local info = Theme.Cell(panel, 12, C.muted)
    info.Left:Set(title.Left)
    info.Right:Set(title.Right)
    info.Top:Set(function() return title.Bottom() + Scale(4) end)
    local search = Theme.TextField(panel, 300, 'Search maps', 'search', 40)
    search.Left:Set(function() return panel.Left() + Scale(228) end)
    search.Right:Set(function() return panel.Right() - Scale(24) end)
    search.Width:Set(function() return search.Right() - search.Left() end)
    LayoutHelpers.AtTopIn(search, panel, 64)
    local names = {}
    local function NameOf(path)
        if names[path] == nil then
            local ok, scenario = pcall(MapUtil.LoadScenario, path)
            names[path] = ok and scenario and scenario.name and LOC(scenario.name) or false
        end
        return names[path] or path
    end
    local function Folder(path)
        local _, _, folder = string.find(path or '', '^/maps/([^/]+)/')
        return folder and string.lower(folder) or path
    end
    local paths = {}
    for _, path in DiskFindFiles('/maps', '*_scenario.lua') do
        table.insert(paths, path)
    end
    table.sort(paths)
    local chosen = false
    local function Show(item)
        chosen = item
        frame:SetMap(Folder(item.path))
        Theme.SetText(title, NameOf(item.path))
        local scenario = Widgets.LocalScenario(Folder(item.path))
        if scenario and scenario.size then
            local armies = MapUtil.GetArmies(scenario) or {}
            Theme.SetText(info, string.format('%d x %d km  -  %d players', math.floor(scenario.size[1] / 51.2 + 0.5),
                math.floor(scenario.size[2] / 51.2 + 0.5), table.getn(armies)))
        else
            Theme.SetText(info, Folder(item.path))
        end
    end
    local list = Widgets.VirtualList(panel, {
        { 'Map', 0.64, function(item) return NameOf(item.path) end },
        { 'Folder', 0.36, function(item) return Folder(item.path) end, C.subtle },
    }, function(item, double)
        Show(item)
        if double then
            api.SetMap(item.path)
            cover:Destroy()
        end
    end)
    list.Left:Set(search.Left)
    list.Right:Set(search.Right)
    list.Top:Set(function() return search.Bottom() + Scale(10) end)
    list.Bottom:Set(function() return panel.Bottom() - Scale(70) end)
    local currentFile = string.lower(api.GameInfo().GameOptions.ScenarioFile or '')
    local function Fill()
        local filter = string.lower(search.edit:GetText())
        local items = {}
        for _, path in paths do
            if filter == '' or string.find(string.lower(path), filter, 1, true) or
                string.find(string.lower(names[path] or ''), filter, 1, true) then
                table.insert(items, { key = string.lower(path), path = path })
            end
        end
        list:SetItems(items)
    end
    search:OnChange(function()
        list.top = 1
        Fill()
    end)
    list.selectedKey = currentFile
    Fill()
    for index, item in list.items do
        if item.key == currentFile then
            list:ScrollSetTop(nil, index - 3)
            Show(item)
        end
    end
    local cancel = Theme.Button(panel, 'Cancel', function() cover:Destroy() end, 'secondary', { width = 120 })
    LayoutHelpers.AtRightIn(cancel, panel, 24)
    LayoutHelpers.AtBottomIn(cancel, panel, 20)
    local pick = Theme.Button(panel, 'Use this map', function()
        local item = list:Selected() or chosen
        if item then
            api.SetMap(item.path)
        end
        cover:Destroy()
    end, 'primary', { width = 170 })
    pick.Right:Set(function() return cancel.Left() - Scale(12) end)
    LayoutHelpers.AtBottomIn(pick, panel, 20)
end

-- ---------------------------------------------------------------------------------------------------------------
-- The game options: FAF's option definitions and the lobby's values; the host changes them with SetGameOption.

function LobbyView:OptionRows()
    local api = self.api
    local info = api.GameInfo()
    local options = import('/lua/ui/lobby/lobbyoptions.lua')
    local rows = {}
    local changed = 0
    local function Add(definitions)
        for _, option in definitions or {} do
            if not (option.mponly and api.IsSinglePlayer()) and option.values and table.getn(option.values) > 1 then
                local currentValue = info.GameOptions[option.key]
                local text = ''
                local isDefault = false
                for index, value in option.values do
                    local key = ValueKey(value)
                    if key == currentValue or tostring(key) == tostring(currentValue) then
                        text = ValueText(value.text or option.value_text, key)
                        isDefault = index == option.default
                    end
                end
                if not isDefault then
                    changed = changed + 1
                end
                if not (self.onlyChanged and isDefault) then
                    table.insert(rows, { key = option.key, label = Strip(option.label), value = text, option = option,
                        color = isDefault and C.muted or C.accent })
                end
            end
        end
    end
    Add(options.globalOpts)
    Add(options.teamOptions)
    Add(options.AIOpts)
    if self.scenario and self.scenario.options then
        Add(self.scenario.options)
    end
    return rows, changed
end

function LobbyView:OpenOption(item, anchor)
    local api = self.api
    if not api.IsHost() then
        return
    end
    local items = {}
    for _, value in item.option.values do
        table.insert(items, { ValueText(value.text or item.option.value_text, ValueKey(value)), key = ValueKey(value) })
    end
    Widgets.Dropdown(anchor, items, function(picked)
        api.SetOption(item.key, picked.key)
    end, { width = 300, maxRows = 12 })
end

-- ---------------------------------------------------------------------------------------------------------------
-- Chat: FAF's chat lines as they arrive (the hook passes AddChatText on), and a field that sends through FAF's.

function LobbyView:AddChat(name, text, color)
    table.insert(self.chat, { name = name, text = text, color = color })
    if table.getn(self.chat) > 200 then
        table.remove(self.chat, 1)
    end
    self:PaintChat()
end

function LobbyView:PaintChat()
    local count = table.getn(self.chat)
    -- The lines above the input field (fewer when a bigger map adds player rows).
    local fit = 0
    for _, row in self.chatRows do
        if row.name.Top() + Scale(18) <= self.chatField.Top() then
            fit = fit + 1
        end
    end
    for i, loopRow in self.chatRows do
        -- Lua 5.0 keeps one loop variable for every pass: the closure below needs its own copy.
        local row = loopRow
        local inside = i <= fit
        Theme.SetVisible(row.text, inside)
        if not inside then
            Theme.SetVisible(row.name, false)
        end
        local line = inside and self.chat[count - fit + i] or nil
        Theme.SetVisible(row.name, line ~= nil and line.name ~= nil)
        if line then
            Theme.SetText(row.name, line.name and (line.name .. ':') or '')
            Theme.SetColor(row.name, line.color or C.accent)
            Theme.SetText(row.text, line.text or '')
            Theme.SetColor(row.text, line.name and C.text or C.muted)
            row.text.Left:Set(function()
                return (line.name and row.name.Right() or row.name.Left()) + Scale(line.name and 8 or 0)
            end)
        else
            Theme.SetText(row.text, '')
        end
    end
end

-- ---------------------------------------------------------------------------------------------------------------
-- Building and refreshing.

function LobbyView:Build()
    local api = self.api
    local view = self
    local fafGui = api.GUI()
    local root = Group(fafGui, 'faf-re lobby')
    LayoutHelpers.FillParent(root, fafGui)
    root.Width:Set(function() return root.Right() - root.Left() end)
    root.Height:Set(function() return root.Bottom() - root.Top() end)
    root.Depth:Set(GetFrame(0):GetTopmostDepth() + 1) -- over everything FAF's screen has; its later popups go over this
    self.root = root
    -- Takes every click over FAF's screen underneath.
    local back = Theme.Rect(root, C.page)
    LayoutHelpers.FillParent(back, root)
    Theme.SizeFromEdges(back)
    back.HandleEvent = function(self, event)
        return true
    end

    -- Header: the game's name, what it is, its tags, and the ways out.
    self.title = Theme.Text(root, '', 22, C.text, true)
    LayoutHelpers.AtLeftTopIn(self.title, root, 28, 16)
    self.subtitle = Theme.Text(root, '', 12, C.muted)
    LayoutHelpers.AtLeftTopIn(self.subtitle, root, 28, 46)
    self.headerTags = {}
    for i = 1, 7 do
        local tag = Theme.Tag(root, '', C.muted)
        LayoutHelpers.AtTopIn(tag, root, 22)
        if i == 1 then
            tag.Left:Set(function() return view.title.Right() + Scale(18) end)
        else
            local before = self.headerTags[i - 1]
            tag.Left:Set(function() return before.Right() + Scale(8) end)
        end
        self.headerTags[i] = tag
    end
    local leave = Theme.Button(root, 'Leave', function()
        local exit = api.GUI().exitButton
        if exit then
            exit.OnClick(exit)
        end
    end, 'danger', { icon = 'logout', width = 120 })
    LayoutHelpers.AtRightTopIn(leave, root, 28, 16)
    local classic = Theme.Button(root, 'Classic view', function()
        view:SetClassic(true)
    end, 'ghost', { icon = 'eye', width = 150 })
    classic.Right:Set(function() return leave.Left() - Scale(10) end)
    LayoutHelpers.AtTopIn(classic, root, 16)
    -- FAF's presets (the host's saved lobby set-ups), for a host of a game with other players.
    self.presets = Theme.Button(root, 'Presets', function()
        api.OpenPresets()
    end, 'ghost', { icon = 'list', width = 120 })
    self.presets.Right:Set(function() return classic.Left() - Scale(10) end)
    LayoutHelpers.AtTopIn(self.presets, root, 16)
    -- The host is known when FAF builds its screen (Hosting, or the link to the host made), and never changes.
    local hostsGame = api.IsHost()
    local withPresets = hostsGame and not api.IsSinglePlayer()
    Theme.SetVisible(self.presets, withPresets)
    self.withPresets = withPresets
    self.headerEnd = function()
        return (withPresets and view.presets.Left() or classic.Left()) - Scale(12)
    end

    local line = Theme.Rect(root, C.line)
    line.Left:Set(function() return root.Left() + Scale(28) end)
    line.Right:Set(function() return root.Right() - Scale(28) end)
    line.Top:Set(function() return root.Top() + Scale(70) end)
    line.Height:Set(1)
    line.Width:Set(function() return line.Right() - line.Left() end)
    line:DisableHitTest()

    -- Columns: players and chat on the left, map, mods, options and observers on the right.
    local _, frameHeight = Widgets.FrameUnits()
    local leftCol = Group(root)
    leftCol.Left:Set(function() return root.Left() + Scale(28) end)
    leftCol.Right:Set(function() return root.Left() + math.floor(root.Width() * 0.58) end)
    leftCol.Top:Set(function() return line.Bottom() + Scale(14) end)
    leftCol.Bottom:Set(function() return root.Bottom() - Scale(24) end)
    leftCol.Width:Set(function() return leftCol.Right() - leftCol.Left() end)
    leftCol.Height:Set(function() return leftCol.Bottom() - leftCol.Top() end)
    local rightCol = Group(root)
    rightCol.Left:Set(function() return leftCol.Right() + Scale(20) end)
    rightCol.Right:Set(function() return root.Right() - Scale(28) end)
    rightCol.Top:Set(leftCol.Top)
    rightCol.Bottom:Set(leftCol.Bottom)
    rightCol.Width:Set(function() return rightCol.Right() - rightCol.Left() end)
    rightCol.Height:Set(function() return rightCol.Bottom() - rightCol.Top() end)

    -- Players: a heading with the teams' figures, the column names, then one row a start position.
    local playersCaption = Theme.Caption(leftCol, 'Players', C.accent)
    LayoutHelpers.AtLeftTopIn(playersCaption, leftCol, 0, 0)
    -- On the heading's line: the teams' figures, and at its end the network the game runs on.
    self.networkIcon = Theme.Icon(leftCol, 'activity', 14, C.muted, 2)
    self.networkNote = Theme.Text(leftCol, '', 11, C.muted)
    self.networkNote.Right:Set(leftCol.Right)
    LayoutHelpers.AtTopIn(self.networkNote, leftCol, 0)
    self.networkIcon.Right:Set(function() return view.networkNote.Left() - Scale(6) end)
    self.networkIcon.Top:Set(function() return view.networkNote.Top() - Scale(1) end)
    self.teamsNote = Theme.Cell(leftCol, 11, C.muted)
    self.teamsNote.Left:Set(function() return playersCaption.Right() + Scale(16) end)
    self.teamsNote.Right:Set(function() return view.networkIcon.Left() - Scale(16) end)
    LayoutHelpers.AtTopIn(self.teamsNote, leftCol, 0)
    -- The table's columns by the width it has (kLayouts).
    self.layout = LayoutFor(LayoutHelpers.InvScaleNumber(leftCol.Width()))
    local layout = self.layout
    local heads = Group(leftCol)
    heads:DisableHitTest()
    heads.Left:Set(leftCol.Left)
    heads.Right:Set(leftCol.Right)
    heads.Top:Set(function() return playersCaption.Bottom() + Scale(10) end)
    heads.Height:Set(Scale(14))
    heads.Width:Set(function() return heads.Right() - heads.Left() end)
    local function Head(text, column, align)
        if not Column(layout, column) then
            return
        end
        local caption = Theme.Caption(heads, text)
        LayoutHelpers.AtTopIn(caption, heads, 0)
        if align == 'centre' then
            CenterOnColumn(caption, heads, column, layout)
        elseif align == 'left' then
            caption.Left:Set(ColumnLeft(heads, column, layout))
        else
            caption.Right:Set(ColumnRight(heads, column, layout))
        end
    end
    local numberHead = Theme.Caption(heads, '#')
    LayoutHelpers.AtLeftTopIn(numberHead, heads, 12, 0)
    local playerHead = Theme.Caption(heads, 'Player')
    LayoutHelpers.AtLeftTopIn(playerHead, heads, 40, 0)
    local withOthers = not api.IsSinglePlayer()
    Head('Team', 'team', 'left')
    Head('Faction', 'faction', layout == 'compact' and 'centre' or 'left')
    Head('Colour', 'color', 'centre')
    Head('CPU', 'cpu', 'left')
    if withOthers then
        Head('Link', 'link', 'left')
        Head('Ping', 'ping')
        Head('Ready', 'ready', 'centre')
    end
    self.leftCol = leftCol
    self.rowsTop = heads
    self.frameHeight = frameHeight
    -- The rows' bottom edge as a layout value: BuildRows sets it, and what sits under the rows follows.
    self.rowsEnd = Group(leftCol)
    self.rowsEnd:DisableHitTest()
    self.rowsEnd.Left:Set(leftCol.Left)
    self.rowsEnd.Width:Set(1)
    self.rowsEnd.Height:Set(1)
    self.rows = {}
    self:BuildRows()

    -- Observers, in a line under the players.
    local observersCaption = Theme.Caption(leftCol, 'Observers')
    observersCaption.Left:Set(function() return leftCol.Left() + Scale(2) end)
    observersCaption.Top:Set(function() return view.rowsEnd.Top() + Scale(12) end)
    self.observerText = Theme.Cell(leftCol, 12, C.muted)
    self.observerText.Left:Set(function() return observersCaption.Right() + Scale(12) end)
    self.observerText.Right:Set(leftCol.Right)
    self.observerText.Top:Set(function() return observersCaption.Top() - Scale(2) end)

    -- Chat under them.
    local chat = Theme.Panel(leftCol, C.panel, C.line)
    chat.Left:Set(leftCol.Left)
    chat.Right:Set(leftCol.Right)
    chat.Top:Set(function() return observersCaption.Bottom() + Scale(12) end)
    chat.Bottom:Set(leftCol.Bottom)
    chat.Width:Set(function() return chat.Right() - chat.Left() end)
    chat.Height:Set(function() return chat.Bottom() - chat.Top() end)
    local chatCaption = Theme.Caption(chat, 'Chat')
    LayoutHelpers.AtLeftTopIn(chatCaption, chat, 14, 10)
    local field = Theme.TextField(chat, 300, 'Say something (Enter to send)', nil, 300)
    field.Left:Set(function() return chat.Left() + Scale(10) end)
    field.Right:Set(function() return chat.Right() - Scale(10) end)
    field.Width:Set(function() return field.Right() - field.Left() end)
    field.Top:Set(function() return chat.Bottom() - Scale(44) end)
    field.edit.OnEnterPressed = function(self, text)
        if text ~= '' then
            api.Chat(text)
            self:SetText('')
        end
        return true
    end
    self.chatField = field
    self.chat = {}
    self.chatRows = {}
    local chatTop = 30
    local chatHeight = LayoutHelpers.InvScaleNumber(chat.Height()) - chatTop - 50
    for i = 1, math.max(1, math.floor(chatHeight / 18)) do
        local nameCell = Theme.Text(chat, '', 12, C.accent, true)
        LayoutHelpers.AtLeftTopIn(nameCell, chat, 14, chatTop + (i - 1) * 18)
        local textCell = Theme.Cell(chat, 12, C.text)
        textCell.Left:Set(function() return nameCell.Right() + Scale(8) end)
        textCell.Right:Set(function() return chat.Right() - Scale(14) end)
        textCell.Top:Set(nameCell.Top)
        self.chatRows[i] = { name = nameCell, text = textCell }
    end

    -- Right: map, mods and restrictions, options, observers, then ready and launch.
    self.mapSize = math.max(120, math.min(180, math.floor(LayoutHelpers.InvScaleNumber(rightCol.Width()) * 0.34)))
    self:BuildMap(rightCol)
    self.mapCard.Left:Set(rightCol.Left)
    self.mapCard.Right:Set(rightCol.Right)
    self.mapCard.Top:Set(rightCol.Top)
    self.mapCard.Width:Set(function() return self.mapCard.Right() - self.mapCard.Left() end)

    -- Mods and unit restrictions: what the game runs with, each with its button in the card's header.
    local mods = Theme.Panel(rightCol, C.panel, C.line)
    mods.Left:Set(rightCol.Left)
    mods.Right:Set(rightCol.Right)
    mods.Top:Set(function() return view.mapCard.Bottom() + Scale(12) end)
    mods.Height:Set(Scale(64))
    mods.Width:Set(function() return mods.Right() - mods.Left() end)
    local modsCaption = Theme.Caption(mods, 'Mods', C.accent)
    LayoutHelpers.AtLeftTopIn(modsCaption, mods, 14, 12)
    self.modsButton = Theme.Button(mods, 'Manage', function()
        import('/fafengine/modules/lua/ui/lobby/lobbypages.lua').OpenMods(view)
    end, 'secondary', { icon = 'mods', height = 26, width = 110, size = 12 })
    LayoutHelpers.AtRightTopIn(self.modsButton, mods, 10, 8)
    self.restrictButton = Theme.Button(mods, 'Restrictions', function()
        api.OpenRestrictions()
    end, 'secondary', { icon = 'lock', height = 26, width = 130, size = 12 })
    self.restrictButton.Right:Set(function() return view.modsButton.Left() - Scale(8) end)
    LayoutHelpers.AtTopIn(self.restrictButton, mods, 8)
    -- One line: the sim mods' names, and the restrictions' count at the end.
    self.restrictText = Theme.Text(mods, '', 11, C.muted)
    self.restrictText.Right:Set(function() return mods.Right() - Scale(14) end)
    LayoutHelpers.AtTopIn(self.restrictText, mods, 40)
    self.modsText = Theme.Cell(mods, 12, C.text)
    self.modsText.Left:Set(function() return mods.Left() + Scale(14) end)
    self.modsText.Right:Set(function() return view.restrictText.Left() - Scale(16) end)
    LayoutHelpers.AtTopIn(self.modsText, mods, 38)

    local actions = Group(rightCol)
    actions.Left:Set(rightCol.Left)
    actions.Right:Set(rightCol.Right)
    actions.Bottom:Set(rightCol.Bottom)
    actions.Height:Set(Scale(44))
    actions.Width:Set(function() return actions.Right() - actions.Left() end)
    self.launch = Theme.Button(actions, 'Launch game', function()
        api.Launch()
    end, 'primary', { height = 44, width = 200 })
    LayoutHelpers.AtRightIn(self.launch, actions, 0)
    LayoutHelpers.AtBottomIn(self.launch, actions, 0)
    self.ready = Theme.Button(actions, 'Ready', function()
        api.ToggleReady()
    end, 'secondary', { height = 44, width = 140, icon = 'check' })
    self.ready.Right:Set(function() return view.launch.Left() - Scale(10) end)
    LayoutHelpers.AtBottomIn(self.ready, actions, 0)
    self.observe = Theme.Button(actions, 'Observe', function()
        local button = api.GUI().becomeObserver
        if button then
            button.OnClick(button)
        end
    end, 'ghost', { height = 44, width = 130, icon = 'eye' })
    self.observe.Right:Set(function() return view.ready.Left() - Scale(10) end)
    LayoutHelpers.AtBottomIn(self.observe, actions, 0)
    -- Who the game waits for, over the buttons.
    self.waiting = Theme.Cell(rightCol, 12, C.muted)
    self.waiting.Left:Set(rightCol.Left)
    self.waiting.Right:Set(rightCol.Right)
    self.waiting.Bottom:Set(function() return actions.Top() - Scale(8) end)

    -- Options: a heading with "only changed" (on by default, fafre_lobby_only_changed) and FAF's full dialog.
    local optionsCaption = Theme.Caption(rightCol, 'Game options', C.accent)
    optionsCaption.Left:Set(rightCol.Left)
    optionsCaption.Top:Set(function() return mods.Bottom() + Scale(16) end)
    self.optionsNote = Theme.Text(rightCol, '', 11, C.subtle)
    self.optionsNote.Left:Set(function() return optionsCaption.Right() + Scale(12) end)
    self.optionsNote.Top:Set(optionsCaption.Top)
    -- On a narrow column the count gives its place to the checkbox and the button.
    self.showOptionsNote = LayoutHelpers.InvScaleNumber(rightCol.Width()) >= 440
    -- Every option on a page of its own (lobbypages.lua); the host changes them there, others read them.
    self.advanced = Theme.Button(rightCol, 'All options', function()
        import('/fafengine/modules/lua/ui/lobby/lobbypages.lua').OpenOptions(view)
    end, 'ghost', { icon = 'settings', height = 26, width = 130, size = 12 })
    self.advanced.Right:Set(rightCol.Right)
    self.advanced.Top:Set(function() return optionsCaption.Top() - Scale(7) end)
    -- On unless the player turned it off here (a key of its own: FAF's LobbyHideDefaultOptions is often 'false' from
    -- FAF's own lobby), and written to disk at once, so a game that doesn't end normally keeps the choice too.
    self.onlyChanged = Prefs.GetFromCurrentProfile('fafre_lobby_only_changed') ~= false
    local onlyChanged = Theme.Checkbox(rightCol, 'Only changed', function(box)
        view.onlyChanged = box.on
        Prefs.SetToCurrentProfile('fafre_lobby_only_changed', box.on and true or false)
        if rawget(_G, 'SavePreferences') then
            SavePreferences()
        end
        view.options.top = 1
        view:Refresh()
    end)
    onlyChanged:SetOn(self.onlyChanged)
    self.onlyChangedBox = onlyChanged
    onlyChanged.Left:Set(function()
        return (hostsGame and (view.advanced.Left() - Scale(12)) or rightCol.Right()) - onlyChanged.Width()
    end)
    onlyChanged.Top:Set(function() return optionsCaption.Top() - Scale(11) end)
    self.options = Widgets.VirtualList(rightCol, {
        { 'Option', 0.56, function(item) return item.label end, C.text },
        { 'Value', 0.44, function(item) return item.value end },
    }, function(item, double, row)
        view:OpenOption(item, row or view.options)
    end)
    self.options.Left:Set(rightCol.Left)
    self.options.Right:Set(rightCol.Right)
    self.options.Top:Set(function() return optionsCaption.Bottom() + Scale(8) end)
    self.options.Bottom:Set(function() return view.waiting.Top() - Scale(10) end)

    -- FAF's screen with a way back here, while classic view is on.
    local backButton = Theme.Button(fafGui, 'faf-re lobby', function()
        view:SetClassic(false)
    end, 'primary', { icon = 'arrowLeft', width = 170 })
    LayoutHelpers.AtLeftTopIn(backButton, fafGui, 12, 12)
    backButton.Depth:Set(function() return root.Depth() + 1 end)
    self.backButton = backButton
    Theme.SetVisible(backButton, false)

    local ticker = Group(root)
    ticker:DisableHitTest()
    LayoutHelpers.SetDimensions(ticker, 1, 1)
    LayoutHelpers.AtLeftTopIn(ticker, root, 0, 0)
    ticker.elapsed = kRefreshSeconds
    ticker:SetNeedsFrameUpdate(true)
    ticker.OnFrame = function(self, delta)
        self.elapsed = self.elapsed + delta
        if self.elapsed >= kRefreshSeconds then
            self.elapsed = 0
            view:Refresh()
        end
    end
end

--- One row a start position of the map: made again when a new map has another number of them.
function LobbyView:BuildRows()
    for _, row in self.rows do
        row:Destroy()
    end
    self.rows = {}
    local slots = math.max(2, self.api.NumSlots())
    self.builtSlots = self.api.NumSlots()
    local rowHeight = math.max(30, math.min(44, math.floor(((self.frameHeight - 72 - 80) * 0.6) / slots)))
    local top = self.rowsTop
    local column = self.leftCol
    for loopSlot = 1, slots do
        -- Lua 5.0 keeps one loop variable for every pass: a closure needs its own copy.
        local slot = loopSlot
        local row = MakeSlotRow(self, column, slot, self.layout)
        row.Left:Set(column.Left)
        row.Right:Set(column.Right)
        row.Top:Set(function() return top.Bottom() + Scale(6) + (slot - 1) * Scale(rowHeight + 3) end)
        row.Height:Set(Scale(rowHeight))
        row.Width:Set(function() return row.Right() - row.Left() end)
        self.rows[slot] = row
    end
    local count = slots
    self.rowsEnd.Top:Set(function()
        return top.Bottom() + Scale(6) + count * Scale(rowHeight + 3) - Scale(3)
    end)
end

function LobbyView:SetClassic(classic)
    self.classic = classic
    Prefs.SetToCurrentProfile('fafre_lobby_classic', classic)
    Theme.SetVisible(self.root, not classic)
    Theme.SetVisible(self.backButton, classic)
    if not classic then
        Theme.RepaintAll()
        self:Refresh()
    end
end

--- The network the game runs on, on the players' heading line: this computer for a skirmish; for a game with others
--- P2P with how many links are direct and relayed (the game's own links), or FAF's own count of linked peers when
--- an ICE adapter makes the links. A link that changes to relayed, to linked or to failed is told in the chat.
function LobbyView:RefreshNetwork(info)
    local api = self.api
    if api.IsSinglePlayer() then
        Theme.SetText(self.networkNote, 'This computer')
        Theme.SetColor(self.networkNote, C.muted)
        return
    end
    local direct, relayed, linked, linking, failed = 0, 0, 0, 0, 0
    self.linkStates = self.linkStates or {}
    for _, player in info.PlayerOptions:pairs() do
        if player.Human and player.OwnerID ~= api.LocalPlayerID() then
            local text = self:LinkOf(player)
            if text == 'direct' then
                direct = direct + 1
            elseif text == 'linked' then
                linked = linked + 1 -- an ICE adapter's link: whether it is relayed isn't known here
            elseif text == 'relay' then
                relayed = relayed + 1
            elseif text == 'failed' then
                failed = failed + 1
            else
                linking = linking + 1
            end
            local before = self.linkStates[player.OwnerID]
            if before ~= text then
                self.linkStates[player.OwnerID] = text
                if text == 'relay' then
                    self:AddChat(nil, player.PlayerName .. ' is linked through a relay (no direct path was found)')
                elseif text == 'direct' and before == 'relay' then
                    self:AddChat(nil, player.PlayerName .. ' is linked directly now')
                elseif text == 'failed' then
                    self:AddChat(nil, 'The link to ' .. player.PlayerName .. ' failed')
                end
            end
        end
    end
    local text
    if direct + relayed + linked + linking + failed == 0 then
        text = 'P2P  -  waiting for players'
    else
        local parts = {}
        if direct > 0 then
            table.insert(parts, direct .. ' direct')
        end
        if relayed > 0 then
            table.insert(parts, relayed .. ' relayed')
        end
        if linked > 0 then
            table.insert(parts, linked .. ' linked')
        end
        if linking > 0 then
            table.insert(parts, linking .. ' linking')
        end
        if failed > 0 then
            table.insert(parts, failed .. ' failed')
        end
        text = 'P2P  -  ' .. table.concat(parts, ', ')
    end
    Theme.SetText(self.networkNote, text)
    Theme.SetColor(self.networkNote, failed > 0 and C.bad or (relayed > 0 and C.warn or C.muted))
end

function LobbyView:Refresh()
    if self.classic then
        return
    end
    local ok, err = pcall(function()
        local api = self.api
        local info = api.GameInfo()
        if not info or not info.PlayerOptions or not info.PlayerOptions.pairs then
            return -- launching: FAF flattened the game info
        end
        -- The title: the host's own from FAF's title dialog, else the FAF game's that the launcher hosted or joined
        -- (FAF's lobby has no other; the engine names a FAF-hosted game GPGNetGame), else the lobby's name.
        if not self.matchChecked or GetSystemTimeSeconds() - self.matchChecked >= kMatchGameSeconds then
            self.matchChecked = GetSystemTimeSeconds()
            self.match = MatchGame() or false
        end
        local match = self.match
        local gameName = api.GameName()
        if gameName == 'GPGNetGame' then
            gameName = ''
        end
        Theme.SetText(self.title, info.GameOptions.Title or (match and match.title) or
            (gameName ~= '' and gameName) or 'Game lobby')

        -- Players, readiness and each team's rating.
        local players, humans, readyCount = 0, 0, 0
        local notReady = {}
        local teams = {}
        local teamOrder = {}
        local hostName = ''
        for _, player in info.PlayerOptions:pairs() do
            players = players + 1
            if player.Human then
                humans = humans + 1
                if player.Ready then
                    readyCount = readyCount + 1
                else
                    table.insert(notReady, player.PlayerName)
                end
                if player.OwnerID == api.HostID() then
                    hostName = player.PlayerName
                end
            end
            local team = player.Team or 1
            if team > 1 then
                if not teams[team] then
                    teams[team] = { total = 0, count = 0, rated = 0 }
                    table.insert(teamOrder, team)
                end
                teams[team].count = teams[team].count + 1
                if player.Human and player.PL then
                    teams[team].total = teams[team].total + player.PL
                    teams[team].rated = teams[team].rated + 1
                end
            end
        end
        table.sort(teamOrder)
        local kind = api.IsSinglePlayer() and 'Skirmish' or (api.IsHost() and 'You host this game' or
            ('Hosted by ' .. (hostName ~= '' and hostName or 'the host')))
        Theme.SetText(self.subtitle, kind .. '  -  ' .. players .. ' of ' .. api.NumSlots() .. ' slots taken' ..
            (api.IsSinglePlayer() and '' or ('  -  ' .. readyCount .. ' of ' .. humans .. ' ready')))
        -- Each team's size and, with other players, its players' average rating (AIs have none).
        local parts = {}
        for _, team in teamOrder do
            local figures = teams[team]
            local text = string.format('Team %d: %d %s', team - 1, figures.count, figures.count == 1 and 'player' or 'players')
            if not api.IsSinglePlayer() and figures.rated > 0 then
                text = text .. string.format(', avg %d', math.floor(figures.total / figures.rated + 0.5))
            end
            table.insert(parts, text)
        end
        Theme.SetText(self.teamsNote, table.getn(parts) > 0 and table.concat(parts, '   ') or
            'No teams chosen: everyone for themselves')

        -- Header tags: the game's rules at a glance.
        local tags = {}
        if match and match.featuredMod and match.featuredMod ~= '' then
            table.insert(tags, { kFeaturedModNames[match.featuredMod] or match.featuredMod, C.accent })
        end
        if match and (match.ratingMin or match.ratingMax) then
            table.insert(tags, { 'Rating ' .. (match.ratingMin and math.floor(match.ratingMin) or 'any') .. ' - ' ..
                (match.ratingMax and math.floor(match.ratingMax) or 'any'), C.gold })
        end
        if match and match.password then
            table.insert(tags, { 'Password', C.muted })
        elseif match and match.visibility == 'friends' then
            table.insert(tags, { 'Friends only', C.muted })
        end
        -- Only the host's own choice: whether FAF rates the game is decided by its server afterwards.
        if not api.IsSinglePlayer() and (info.GameOptions.Unranked == 'Yes' or info.GameOptions.Unranked == true) then
            table.insert(tags, { 'Unrated', C.bad })
        end
        local quality = info.GameOptions.Quality
        if quality and quality > 0 and not api.IsSinglePlayer() then
            table.insert(tags, { string.format('Quality %d%%', math.floor(quality + 0.5)),
                quality >= 70 and C.good or (quality >= 50 and C.warn or C.bad) })
        end
        local gameMods = api.GameMods()
        if table.getn(gameMods) > 0 then
            table.insert(tags, { table.getn(gameMods) == 1 and '1 sim mod' or (table.getn(gameMods) .. ' sim mods'), C.warn })
        end
        if info.GameOptions.RestrictedCategories and table.getn(info.GameOptions.RestrictedCategories) > 0 then
            table.insert(tags, { 'Restrictions', C.violet })
        end
        -- As many as fit between the title and the header's buttons.
        local headerEnd = self.headerEnd()
        local fits = true
        for i, tag in self.headerTags do
            if tags[i] and fits then
                tag:SetTag(tags[i][1], tags[i][2])
                fits = tag.Right() <= headerEnd
            end
            Theme.SetVisible(tag, (tags[i] ~= nil and fits) and true or false)
        end
        Theme.SetVisible(self.presets, self.withPresets)

        self.links = rawget(_G, 'FafNet_Links') and FafNet_Links() or nil
        self:RefreshNetwork(info)

        if api.NumSlots() ~= self.builtSlots then
            self:BuildRows()
            Theme.RepaintAll()
        end
        for _, row in self.rows do
            self:PaintSlot(row)
        end
        self:RefreshMap()

        -- Mods and restrictions.
        local names = {}
        for _, mod in gameMods do
            table.insert(names, mod.name or mod.uid or '?')
        end
        Theme.SetText(self.modsText, table.getn(names) > 0 and table.concat(names, ', ') or 'No sim mods')
        Theme.SetColor(self.modsText, table.getn(names) > 0 and C.text or C.muted)
        local restricted = info.GameOptions.RestrictedCategories and table.getn(info.GameOptions.RestrictedCategories) or 0
        Theme.SetText(self.restrictText, restricted > 0 and (restricted == 1 and '1 unit restriction' or
            (restricted .. ' unit restrictions')) or 'No unit restrictions')
        local fafGui = api.GUI()
        -- FAF's options button (the host's map dialog, a client's mod manager) says when these may open; a client's
        -- restrictions follow FAF's read-only Unit Manager button, which skirmish doesn't have.
        local host = api.IsHost()
        self.modsButton:SetEnabled(Enabled(fafGui.gameoptionsButton))
        self.modsButton:SetLabel(host and 'Manage' or 'View')
        self.restrictButton:SetEnabled(host and Enabled(fafGui.gameoptionsButton) or
            (not host and Enabled(fafGui.restrictedUnitsOrPresetsBtn)))
        -- Everyone reads every option there; only the host's page changes them.
        Theme.SetVisible(self.advanced, true)
        self.advanced:SetEnabled(true)

        local rows, changed = self:OptionRows()
        self.options:SetItems(rows)
        Theme.SetText(self.optionsNote, changed .. ' changed' .. (api.IsHost() and '' or ' by the host'))
        Theme.SetVisible(self.optionsNote, self.showOptionsNote)

        local observerNames = {}
        for _, observer in info.Observers:pairs() do
            table.insert(observerNames, observer.PlayerName)
        end
        Theme.SetText(self.observerText, table.getn(observerNames) > 0 and table.concat(observerNames, ', ') or 'Nobody watches')

        local waiting = ''
        if not api.IsSinglePlayer() then
            waiting = readyCount .. ' of ' .. humans .. ' ready'
            if table.getn(notReady) > 0 then
                waiting = waiting .. '  -  waiting for ' .. table.concat(notReady, ', ')
            elseif api.IsHost() then
                waiting = waiting .. '  -  everyone is ready'
            else
                waiting = waiting .. '  -  the host launches'
            end
        end
        Theme.SetText(self.waiting, waiting)

        local launchButton = fafGui.launchGameButton
        Theme.SetVisible(self.launch, api.IsHost())
        self.launch:SetEnabled(Enabled(launchButton))
        local mySlot = api.LocalSlot()
        local mine = mySlot and info.PlayerOptions[mySlot]
        Theme.SetVisible(self.ready, mine ~= nil and not api.IsSinglePlayer())
        if mine then
            self.ready:SetLabel(mine.Ready and 'Not ready' or 'Ready')
        end
        Theme.SetVisible(self.observe, not api.IsSinglePlayer())
        self.observe:SetEnabled(Enabled(fafGui.becomeObserver))
        self.observe:SetLabel(mine and 'Observe' or 'Observing')
    end)
    if not ok and not self.failed then
        self.failed = true
        WARN('faf-re lobby: the screen failed to update, FAF\'s screen shows instead: ' .. tostring(err))
        self:SetClassic(true)
    end
end

--- Builds the screen over FAF's lobby; `api` is the hook's FafReLobbyApi.
function Create(api)
    if current and current.root then
        current.root:Destroy()
    end
    current = false
    local view = setmetatable({ api = api, chat = {} }, LobbyView)
    view:Build()
    current = view
    view:SetClassic(Prefs.GetFromCurrentProfile('fafre_lobby_classic') and true or false)
    view:Refresh()
    LOG('faf-re lobby: shown')
    return view
end

--- FAF's lobby lost its game (text: the host left, the connection failed, a kick): said over this screen in its
--- own look; its button leaves the lobby with `leave` (FAF's ReturnToMenu). False when FAF's screen shows instead.
function OnClosed(text, leave)
    local view = current
    if not view or not view.root or view.classic or view.root:IsHidden() then
        return false
    end
    LOG('faf-re lobby: closed: ' .. tostring(text))
    local cover = Widgets.Modal(view.root, 540, 210)
    local panel = cover.panel
    local head = Theme.Title(panel, 'Lobby closed', 16, C.text)
    LayoutHelpers.AtLeftTopIn(head, panel, 26, 22)
    local body = Theme.Paragraph(panel, 14, C.muted)
    body.Left:Set(function() return panel.Left() + Scale(26) end)
    body.Right:Set(function() return panel.Right() - Scale(26) end)
    body.Top:Set(function() return panel.Top() + Scale(64) end)
    body:SetText(text)
    local function Leave()
        view.closedText = nil
        view.closedLeave = nil
        cover:Destroy()
        leave()
    end
    local back = Theme.Button(panel, 'Back to the launcher', Leave, 'primary', { width = 220, icon = 'arrowLeft' })
    LayoutHelpers.AtRightIn(back, panel, 26)
    LayoutHelpers.AtBottomIn(back, panel, 22)
    view.closedText = text
    view.closedLeave = Leave -- tests press it with this
    return true
end

--- The launcher's screen test (launcher.lua TestWalk, in a skirmish lobby): the calls this screen's clicks make, as
--- steps the walk runs one by one with a pause after each (Lua 5.0 can't wait inside a pcall), each followed by what
--- FAF's lobby state says; the last leaves a slot menu open for the screenshot.
function TestSteps(step)
    local view = current
    if not view then
        return { function() step('lobby: no faf-re lobby screen') end }
    end
    local api = view.api
    local function Info()
        return api.GameInfo()
    end
    return {
        function()
            local keys, strings = api.SlotMenu(2)
            step('lobby: slot 2 menu ' .. table.concat(keys or {}, ','))
            for i, key in keys or {} do
                if key ~= 'close' and key ~= 'occupy' and key ~= 'open' and key ~= 'close_spawn_mex' and
                    not string.find(key, '^move') then
                    api.SlotAction(2, key, LOC(strings[i]))
                    step('lobby: asked for ' .. key .. ' in slot 2')
                    break
                end
            end
        end,
        function()
            local ai = Info().PlayerOptions[2]
            step('lobby: slot 2 now ' .. (ai and (tostring(ai.PlayerName) .. ', human ' .. tostring(ai.Human)) or 'empty'))
            local fafSlot = api.GUI().slots[1]
            fafSlot.faction:SetItem(2)
            fafSlot.faction.OnClick(fafSlot.faction, 2)
            fafSlot.team:SetItem(3)
            fafSlot.team.OnClick(fafSlot.team, 3, '')
        end,
        function()
            local player = Info().PlayerOptions[1]
            step('lobby: slot 1 faction ' .. tostring(player.Faction) .. ', team ' .. tostring(player.Team))
            if Info().PlayerOptions[2] then
                local aiSlot = api.GUI().slots[2]
                aiSlot.color:SetItem(5)
                aiSlot.color.OnClick(aiSlot.color, 5)
            end
        end,
        function()
            local ai = Info().PlayerOptions[2]
            step('lobby: slot 2 colour ' .. tostring(ai and ai.PlayerColor))
            for _, option in import('/lua/ui/lobby/lobbyoptions.lua').globalOpts do
                if option.key == 'UnitCap' and option.values[2] then
                    view.askedUnitCap = option.values[2].key or option.values[2]
                    api.SetOption('UnitCap', view.askedUnitCap)
                end
            end
        end,
        function()
            step('lobby: unit cap ' .. tostring(Info().GameOptions.UnitCap) .. ' (asked ' .. tostring(view.askedUnitCap) .. ')')
            api.SetMap('/maps/scmp_007/scmp_007_scenario.lua')
        end,
        function()
            step('lobby: map ' .. tostring(Info().GameOptions.ScenarioFile))
            local saved = view.onlyChanged
            view.onlyChanged = false
            local all = view:OptionRows()
            view.onlyChanged = true
            local shown, changed = view:OptionRows()
            view.onlyChanged = saved
            step(string.format('lobby: options %d, only changed shows %d (counted %d changed), only changed on: %s',
                table.getn(all), table.getn(shown), changed, tostring(saved)))
            -- Unticked as a click does: saved to the preferences file at once (the run checks the file after).
            local box = view.onlyChangedBox
            box:SetOn(false)
            box.onToggle(box)
            step('lobby: only changed unticked, preference ' .. tostring(Prefs.GetFromCurrentProfile('fafre_lobby_only_changed')))
            step('lobby: slot 1 cpu ' .. tostring(api.Cpu(Info().PlayerOptions[1].PlayerName)) .. ', country ' ..
                tostring(Info().PlayerOptions[1].Country) .. ', columns ' .. tostring(view.layout) .. ', links ' .. tostring(view.links and view.links.mode) ..
                ', mods ' .. table.getn(api.GameMods()))
        end,
        function()
            -- The game options page: every option, then one picked through it (the second fog-of-war value).
            local pages = import('/fafengine/modules/lua/ui/lobby/lobbypages.lua')
            local page = pages.OpenOptions(view)
            local fog = nil
            for _, item in page.items do
                if item.key == 'FogOfWar' then
                    fog = item
                end
            end
            step('lobby: options page ' .. table.getn(page.items) .. ' options, ' .. tostring(page.changed) .. ' changed')
            if fog and fog.option.values[2] then
                view.askedFog = ValueKey(fog.option.values[2])
                api.SetOption('FogOfWar', view.askedFog)
            end
        end,
        function()
            local page = view.optionsPage
            page:Refresh()
            step('lobby: options page fog ' .. tostring(Info().GameOptions.FogOfWar) .. ' (asked ' ..
                tostring(view.askedFog) .. '), changed now ' .. tostring(page.changed))
        end,
        function()
            view.optionsPage:Destroy()
            local mods = import('/fafengine/modules/lua/ui/lobby/lobbypages.lua').OpenMods(view)
            step('lobby: mods page ' .. mods.counts.game .. ' game mods (' .. mods.counts.gameOn .. ' on), ' ..
                mods.counts.ui .. ' interface mods (' .. mods.counts.uiOn .. ' on)')
        end,
        function()
            view.modsPage.kind = 'ui'
            view.modsPage:Refresh()
            step('lobby: mods page interface tab ' .. table.getn(view.modsPage.items) .. ' rows')
        end,
        function()
            -- A game mod turned on and applied through FAF's lobby, then off again.
            local page = view.modsPage
            page.kind = 'game'
            page:Refresh()
            local first = page.items[1]
            view.testMod = first and first.uid
            if first and not first.why then
                page.chosen[first.uid] = true
                page:Apply()
            else
                page:Destroy()
            end
        end,
        function()
            local names = {}
            for _, mod in api.GameMods() do
                table.insert(names, tostring(mod.name))
            end
            step('lobby: game mods after Apply: ' .. table.getn(names) .. ' (' .. table.concat(names, ', ') .. ')')
            local page = import('/fafengine/modules/lua/ui/lobby/lobbypages.lua').OpenMods(view)
            if view.testMod then
                page.chosen[view.testMod] = nil
            end
            page:Apply()
        end,
        function()
            step('lobby: game mods after turning it off: ' .. table.getn(api.GameMods()))
            view:Refresh()
            view:OpenSlotMenu(3, view.rows[3])
            step('lobby: slot 3 menu open')
        end,
    }
end

--- A chat line FAF's lobby added (the hook's AddChatText), for this screen too.
function OnChat(text, name, color)
    if current then
        current:AddChat(name, text, color)
    end
end
