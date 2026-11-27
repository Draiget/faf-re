-- The launcher's LAN page: games hosted on this network (found by the engine's discovery service, as FAF's LAN screen
-- finds them), hosting one, and connecting to a game by its address. Joining and hosting open FAF's own lobby
-- (lobby.lua CreateLobby / JoinGame / HostGame) on a launcher screen; leaving the lobby comes back here.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kDefaultPort = 16010 -- FAF's LAN screens' default
local kRowHeight = 76
local kRows = 10

local function NameOk(name)
    return name and string.find(name, '%S') ~= nil
end

--- A field's caption over it.
local function Labelled(parent, text, field, gap)
    local label = Theme.Text(parent, string.upper(text), 10, C.muted, true)
    label.Left:Set(field.Left)
    label.Bottom:Set(function() return field.Top() - Scale(gap or 6) end)
    return label
end

--- A port typed in a field: the default when empty, nil when it isn't one.
local function PortOf(field)
    local text = field.edit:GetText()
    if text == '' then
        return kDefaultPort
    end
    local port = tonumber(text)
    if not port or math.floor(port) ~= port or port < 1 or port > 65535 then
        return nil
    end
    return port
end

--- A dialog over the launcher: title, its fields (built by fill(panel, dialog)), a line for what went wrong, and the
--- action and Cancel along its bottom.
local function Dialog(launcher, title, height, actionText, actionIcon, fill, onAction)
    local cover = Widgets.Modal(launcher.root, 480, height)
    local panel = cover.panel
    local dialog = { cover = cover, panel = panel }
    local head = Theme.Title(panel, title, 16, C.text)
    LayoutHelpers.AtLeftTopIn(head, panel, 26, 22)
    fill(panel, dialog)
    dialog.problem = Theme.Paragraph(panel, 13, C.warn)
    dialog.problem.Left:Set(function() return panel.Left() + Scale(26) end)
    dialog.problem.Right:Set(function() return panel.Right() - Scale(26) end)
    dialog.problem.Top:Set(function() return panel.Bottom() - Scale(108) end)
    dialog.Say = function(self, text)
        self.problem:SetText(text or '', C.warn)
    end
    dialog.Close = function(self)
        self.cover:Destroy()
    end
    local action = Theme.Button(panel, actionText, function() onAction(dialog) end, 'primary',
        { icon = actionIcon, width = 200 })
    LayoutHelpers.AtRightIn(action, panel, 26)
    LayoutHelpers.AtBottomIn(action, panel, 22)
    local cancel = Theme.Button(panel, 'Cancel', function() dialog:Close() end, 'secondary', { width = 120 })
    cancel.Right:Set(function() return action.Left() - Scale(12) end)
    LayoutHelpers.AtBottomIn(cancel, panel, 22)
    return dialog
end

function Build(launcher, page)
    local view = { games = {}, rows = {} }
    launcher.lanView = view

    local title = Theme.Title(page, 'LAN', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    local subtitle = Theme.Text(page, 'Games on this network, or one at an address you know', 13, C.subtle)
    subtitle.Left:Set(function() return title.Right() + Scale(24) end)
    subtitle.Bottom:Set(function() return title.Bottom() - Scale(3) end)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return title.Bottom() + Scale(14) end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    -- The toolbar: the player's name, Host game, Connect by address.
    view.hostButton = Theme.Button(page, 'Host game', function() view:OpenHost() end, 'primary', { icon = 'plus' })
    LayoutHelpers.AtLeftIn(view.hostButton, page, 0)
    view.hostButton.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.connectButton = Theme.Button(page, 'Connect by address', function() view:OpenConnect() end, 'secondary',
        { icon = 'globe' })
    view.connectButton.Left:Set(function() return view.hostButton.Right() + Scale(12) end)
    view.connectButton.Top:Set(view.hostButton.Top)
    view.name = Theme.TextField(page, 220, 'Your name in the game', 'user', 30)
    view.name.Left:Set(function() return math.max(view.connectButton.Right() + Scale(24), page.Right() - view.name.Width()) end)
    view.name.Top:Set(view.hostButton.Top)
    view.name.edit:SetText(Prefs.GetFromCurrentProfile('NetName') or Prefs.GetFromCurrentProfile('Name') or '')
    view.name:Refresh()
    view.name:OnChange(function(text)
        if NameOk(text) then
            Prefs.SetToCurrentProfile('NetName', text)
        end
    end)

    -- The games found on this network.
    local list = Group(page)
    list.Left:Set(page.Left)
    list.Right:Set(page.Right)
    list.Top:Set(function() return view.hostButton.Bottom() + Scale(22) end)
    list.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(list)
    view.list = list
    local heading = Theme.Text(list, 'GAMES ON THIS NETWORK', 12, C.accent, true)
    LayoutHelpers.AtLeftTopIn(heading, list, 0, 0)
    view.count = Theme.Text(list, '', 12, C.subtle)
    view.count.Left:Set(function() return heading.Right() + Scale(12) end)
    LayoutHelpers.AtVerticalCenterIn(view.count, heading)
    view.searching = Theme.Loader(list)
    view.searching.Left:Set(function() return view.count.Right() + Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(view.searching, heading)
    -- What the last action said (a missing name), right of the heading.
    view.status = Theme.Cell(list, 12, C.warn)
    view.status.Left:Set(function() return view.searching.Right() + Scale(20) end)
    view.status.Right:Set(list.Right)
    LayoutHelpers.AtVerticalCenterIn(view.status, heading)

    local rowsTop = function() return heading.Bottom() + Scale(14) end
    for i = 1, kRows do
        local offset = (i - 1) * (kRowHeight + 8)
        local row = Theme.Panel(list, 'ff08121a', C.line)
        row.Left:Set(list.Left)
        row.Right:Set(list.Right)
        row.Top:Set(function() return rowsTop() + Scale(offset) end)
        LayoutHelpers.SetHeight(row, kRowHeight)
        row.Width:Set(function() return row.Right() - row.Left() end)
        row.frame = Theme.Panel(row, 'ff060d13', C.line)
        LayoutHelpers.SetDimensions(row.frame, 58, 58)
        LayoutHelpers.AtLeftIn(row.frame, row, 10)
        LayoutHelpers.AtVerticalCenterIn(row.frame, row)
        Widgets.MapPicture(row.frame)
        row.watch = Theme.Button(row, 'Watch', function() view:Join(row.game, true) end, 'secondary', { width = 90 })
        LayoutHelpers.AtRightIn(row.watch, row, 12)
        LayoutHelpers.AtVerticalCenterIn(row.watch, row)
        row.join = Theme.Button(row, 'Join', function() view:Join(row.game, false) end, 'primary', { width = 96 })
        LayoutHelpers.AtVerticalCenterIn(row.join, row)
        -- Left of Watch, or where Watch is when nobody may watch (Paint).
        row.join.Right:Set(function() return (row.canWatch and row.watch.Left() or row.Right()) - Scale(12) end)
        row.canWatch = true
        row.players = Theme.Text(row, '', 14, C.text, true)
        row.players.Right:Set(function() return row.join.Left() - Scale(20) end)
        LayoutHelpers.AtVerticalCenterIn(row.players, row)
        row.name = Theme.Cell(row, 15, C.text, true)
        row.name.Left:Set(function() return row.frame.Right() + Scale(16) end)
        row.name.Right:Set(function() return row.players.Left() - Scale(16) end)
        row.name.Top:Set(function() return row.Top() + Scale(12) end)
        row.map = Theme.Cell(row, 13, C.muted)
        row.map.Left:Set(row.name.Left)
        row.map.Right:Set(row.name.Right)
        row.map.Top:Set(function() return row.Top() + Scale(32) end)
        row.where = Theme.Cell(row, 12, C.subtle)
        row.where.Left:Set(row.name.Left)
        row.where.Right:Set(row.name.Right)
        row.where.Top:Set(function() return row.Top() + Scale(52) end)
        view.rows[i] = row
    end
    view.empty = Theme.Paragraph(list, 14, C.subtle)
    view.empty.Left:Set(list.Left)
    view.empty.Right:Set(function() return list.Left() + math.min(list.Width(), Scale(640)) end)
    view.empty.Top:Set(function() return rowsTop() + Scale(8) end)
    view.empty:SetText('Looking for games on this network. A game hosted on another computer here (or on this one) ' ..
        'shows up by itself; one elsewhere joins through Connect by address.', C.subtle)

    ----------------------------------------------------------------------------------------------------------------

    --- Listens for games while the page shows (FAF's LAN screen does the same with the engine's discovery service).
    function view:Start()
        if self.discovery then
            return
        end
        local ok, service = pcall(function() return import('/lua/ui/lobby/lobbycomm.lua').CreateDiscoveryService() end)
        if not ok or not service then
            self:Say('This game can\'t look for LAN games: ' .. tostring(service))
            return
        end
        self.discovery = service
        self.games = {}
        -- The service numbers games from 0.
        service.GameFound = function(_, index, config)
            view.games[index + 1] = config
            LOG('LAUNCHER: LAN game found: ' .. tostring(config.GameName) .. ' at ' .. tostring(config.Address))
            view:Paint()
        end
        service.GameUpdated = function(_, index, config)
            view.games[index + 1] = config
            view:Paint()
        end
        service.RemoveGame = function(_, index)
            view.games[index + 1] = nil
            view:Paint()
        end
    end

    --- Stops listening (before a lobby opens, and when the page goes).
    function view:Stop()
        if self.discovery then
            pcall(self.discovery.Destroy, self.discovery)
            self.discovery = false
        end
        self.games = {}
    end

    function view:Say(text)
        self.statusText = text or ''
        Theme.SetText(self.status, self.statusText)
    end

    function view:PlayerName(dialog)
        local name = self.name.edit:GetText()
        if not NameOk(name) then
            local why = 'Type the name you want to play under first (at the top right).'
            if dialog then
                dialog:Say(why)
            else
                self:Say(why)
            end
            return nil
        end
        Prefs.SetToCurrentProfile('NetName', name)
        return name
    end

    --- FAF's lobby on a launcher screen; leaving it comes back to this page.
    function view:OpenLobby(what, start)
        self:Stop()
        self:Say('')
        launcher:OpenScreen(what, function(host, back)
            local lobby = import('/lua/ui/lobby/lobby.lua')
            start(lobby, host, back)
        end, true)
    end

    function view:Join(game, observe)
        local name = self:PlayerName()
        if not name or not game then
            return
        end
        LOG('LAUNCHER: joining the LAN game ' .. tostring(game.GameName) .. ' at ' .. tostring(game.Address) ..
            (observe and ' to watch' or ''))
        self:OpenLobby('LAN game', function(lobby, host, back)
            lobby.CreateLobby(game.Protocol or 'UDP', 0, name, nil, nil, host, back)
            lobby.JoinGame(game.Address, observe)
        end)
    end

    --- The host dialog: the game's name, a port or any free one.
    function view:OpenHost()
        if self.dialog then
            self.dialog:Close()
        end
        self.dialog = Dialog(launcher, 'Host a LAN game', 330, 'Host game', 'plus', function(panel, dialog)
            dialog.gameName = Theme.TextField(panel, 428, 'A name others see in their list', nil, 40)
            LayoutHelpers.AtLeftTopIn(dialog.gameName, panel, 26, 92)
            Labelled(panel, 'Game name', dialog.gameName)
            dialog.gameName.edit:SetText(Prefs.GetFromCurrentProfile('last_game_name') or '')
            dialog.gameName:Refresh()
            dialog.port = Theme.TextField(panel, 120, tostring(kDefaultPort), nil, 5)
            LayoutHelpers.AtLeftTopIn(dialog.port, panel, 26, 166)
            Labelled(panel, 'Port', dialog.port)
            local lastPort = Prefs.GetFromCurrentProfile('LastPort')
            dialog.port.edit:SetText(lastPort and tostring(lastPort) or '')
            dialog.port:Refresh()
            dialog.anyPort = Theme.Checkbox(panel, 'Any free port', function(self)
                Prefs.SetToCurrentProfile('fafre_lan_any_port', self.on)
            end)
            dialog.anyPort.Left:Set(function() return dialog.port.Right() + Scale(18) end)
            LayoutHelpers.AtVerticalCenterIn(dialog.anyPort, dialog.port)
            dialog.anyPort:SetOn(Prefs.GetFromCurrentProfile('fafre_lan_any_port') ~= false)
        end, function(dialog) view:Host(dialog) end)
        return self.dialog
    end

    function view:Host(dialog)
        dialog = dialog or self.dialog
        local name = self:PlayerName(dialog)
        if not name or not dialog then
            return
        end
        local gameName = dialog.gameName.edit:GetText()
        if not NameOk(gameName) then
            gameName = name .. '\'s game'
        end
        local port = 0 -- the engine picks a free one
        if not dialog.anyPort.on then
            port = PortOf(dialog.port)
            if not port then
                dialog:Say('The port is a number from 1 to 65535.')
                return
            end
            Prefs.SetToCurrentProfile('LastPort', port)
        end
        Prefs.SetToCurrentProfile('last_game_name', gameName)
        local scenario = Prefs.GetFromCurrentProfile('LastScenario') or import('/lua/ui/uiutil.lua').defaultScenario
        LOG('LAUNCHER: hosting the LAN game ' .. gameName .. ' on port ' .. tostring(port))
        dialog:Close()
        self.dialog = false
        self:OpenLobby('LAN game', function(lobby, host, back)
            lobby.CreateLobby('UDP', port, name, nil, nil, host, back)
            lobby.HostGame(gameName, scenario, false)
        end)
    end

    --- The address dialog: an IP address or host name, and its port.
    function view:OpenConnect()
        if self.dialog then
            self.dialog:Close()
        end
        self.dialog = Dialog(launcher, 'Connect by address', 260, 'Connect', 'arrowRight', function(panel, dialog)
            dialog.address = Theme.TextField(panel, 296, 'IP address or host name', 'globe', 60)
            LayoutHelpers.AtLeftTopIn(dialog.address, panel, 26, 92)
            Labelled(panel, 'Address', dialog.address)
            dialog.address.edit:SetText(Prefs.GetFromCurrentProfile('last_dc_ipaddress') or '')
            dialog.address:Refresh()
            dialog.address.edit.OnEnterPressed = function()
                view:Connect(dialog)
                return true
            end
            dialog.port = Theme.TextField(panel, 120, tostring(kDefaultPort), nil, 5)
            dialog.port.Left:Set(function() return dialog.address.Right() + Scale(12) end)
            dialog.port.Top:Set(dialog.address.Top)
            Labelled(panel, 'Port', dialog.port)
            dialog.port.edit:SetText(Prefs.GetFromCurrentProfile('last_dc_port') or '')
            dialog.port:Refresh()
        end, function(dialog) view:Connect(dialog) end)
        return self.dialog
    end

    function view:Connect(dialog)
        dialog = dialog or self.dialog
        local name = self:PlayerName(dialog)
        if not name or not dialog then
            return
        end
        local address = dialog.address.edit:GetText()
        local port = PortOf(dialog.port)
        if not port then
            dialog:Say('The port is a number from 1 to 65535.')
            return
        end
        local valid = address ~= '' and ValidateIPAddress(address .. ':' .. port)
        if not valid then
            dialog:Say('This game can\'t find ' .. (address ~= '' and address or 'an empty address') ..
                '. Check the address, or the host\'s name on your network.')
            return
        end
        Prefs.SetToCurrentProfile('last_dc_ipaddress', address)
        Prefs.SetToCurrentProfile('last_dc_port', tostring(port))
        LOG('LAUNCHER: connecting to ' .. tostring(valid))
        dialog:Close()
        self.dialog = false
        self:OpenLobby('LAN game', function(lobby, host, back)
            lobby.CreateLobby('UDP', 0, name, nil, nil, host, back)
            lobby.JoinGame(valid, false)
        end)
    end

    --- The games this game version can join, by name.
    function view:Shown()
        local shown = {}
        local product = import('/lua/productcode.lua').productCode
        for _, game in self.games do
            if game.ProductCode == nil or game.ProductCode == product then
                table.insert(shown, game)
            end
        end
        table.sort(shown, function(a, b) return tostring(a.GameName) < tostring(b.GameName) end)
        return shown
    end

    function view:Paint()
        local shown = self:Shown()
        local count = table.getn(shown)
        Theme.SetText(self.count, count == 0 and '' or (count == 1 and '1 game' or (count .. ' games')))
        Theme.SetVisible(self.searching, self.discovery and true or false)
        Theme.SetVisible(self.empty, count == 0)
        Theme.SetText(self.status, self.statusText or '')
        local room = math.max(1, math.floor((self.list.Height() - Scale(30)) / Scale(kRowHeight + 8)))
        for i, row in self.rows do
            local game = (i <= room) and shown[i] or nil
            row.game = game
            Theme.SetVisible(row, game ~= nil)
            if game then
                local options = game.Options or {}
                local scenarioFile = options.ScenarioFile and string.lower(options.ScenarioFile) or ''
                local _, _, found = string.find(scenarioFile, '^/maps/([^/]+)/')
                local folder = found or ''
                local scenario = folder ~= '' and Widgets.LocalScenario(folder)
                row.frame:SetMap(scenario and folder or nil)
                local most = 0
                if scenario and scenario.Configurations and scenario.Configurations.standard then
                    most = table.getsize(scenario.Configurations.standard.teams[1].armies)
                end
                Theme.SetText(row.name, tostring(game.GameName or 'A LAN game'))
                Theme.SetText(row.map, scenario and LOC(scenario.name) or
                    (folder ~= '' and folder or 'A map not on this computer'))
                Theme.SetText(row.where, 'Hosted by ' .. tostring(game.Hostname or '?') .. ' at ' ..
                    tostring(game.Address or '?'))
                Theme.SetText(row.players, most > 0 and string.format('%d / %d', game.PlayerCount or 0, most) or
                    tostring(game.PlayerCount or 0))
                local watch = options.AllowObservers and true or false
                Theme.SetVisible(row.watch, watch)
                if row.canWatch ~= watch then
                    local thisRow = row -- Lua 5.0: the loop's own variable is gone by the time the closure runs
                    thisRow.canWatch = watch
                    thisRow.join.Right:Set(function()
                        return (thisRow.canWatch and thisRow.watch.Left() or thisRow.Right()) - Scale(12)
                    end)
                end
            end
        end
    end

    --- On each launcher refresh while the page shows.
    function view:Refresh()
        self:Start()
        self:Paint()
    end

    view:Paint()
    return view
end
