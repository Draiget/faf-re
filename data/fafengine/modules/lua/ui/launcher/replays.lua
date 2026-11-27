-- The launcher's Replays page: replays on this computer (the game's own, FAF's client's, the launcher's downloads)
-- and FAF's replay vault, in the launcher's look. A list, a search, the selected replay's details with its players by
-- team, and Watch (a vault replay downloads first). The engine reads the files and talks to FAF
-- (moho/app/LauncherLibrary.cpp: FafLibrary_*); searches and downloads run on its threads and are asked after on each
-- refresh.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kPageSize = 30

local function Available()
    return rawget(_G, 'FafLibrary_LocalReplays') ~= nil
end

local function LocalTime(when)
    if not when or when == 0 or when == '' or not rawget(_G, 'FafLibrary_LocalTime') then
        return ''
    end
    return FafLibrary_LocalTime(when)
end

local function Length(seconds)
    seconds = math.floor(seconds or 0)
    if seconds <= 0 then
        return ''
    end
    local hours = math.floor(seconds / 3600)
    local minutes = math.floor(math.mod(seconds, 3600) / 60)
    if hours > 0 then
        return string.format('%d:%02d:%02d', hours, minutes, math.mod(seconds, 60))
    end
    return string.format('%d:%02d', minutes, math.mod(seconds, 60))
end

local function Contains(text, filter)
    return text and string.find(string.lower(text), filter, 1, true) ~= nil
end

local kSourceNames = { game = 'This game', faf = 'FAF client', downloads = 'Downloaded' }

--- Players grouped by team, in team order: {team, won, avg, players = {name, rating, rated, change, changed, won}}.
--- Team 1 (or none) is "no team": everyone for themselves.
local function Teams(players)
    local byTeam, order = {}, {}
    for _, player in players or {} do
        local key = player.team or 0
        if not byTeam[key] then
            byTeam[key] = { team = key, won = false, players = {}, total = 0, rated = 0 }
            table.insert(order, key)
        end
        local team = byTeam[key]
        local won = player.result == 'VICTORY'
        team.won = team.won or won
        table.insert(team.players, { name = player.name or '', rating = player.rating or 0, rated = player.rated,
            change = (player.ratingAfter or 0) - (player.rating or 0), changed = player.changed, won = won })
        if player.rated then
            team.total = team.total + player.rating
            team.rated = team.rated + 1
        end
    end
    table.sort(order)
    local teams = {}
    for _, key in order do
        local team = byTeam[key]
        team.avg = team.rated > 0 and math.floor(team.total / team.rated + 0.5) or nil
        table.insert(teams, team)
    end
    return teams
end

--- A head's teams ({["2"] = {logins}}) as players for Teams.
local function HeadPlayers(info)
    local players = {}
    for _, player in info and info.players or {} do
        table.insert(players, { name = player.name, team = player.team })
    end
    return players
end

--- One line for a list: "a, b (won) vs c, d".
local function TeamsText(teams)
    local parts = {}
    for _, team in teams do
        local names = {}
        for _, player in team.players do
            table.insert(names, player.name)
        end
        table.insert(parts, table.concat(names, ', ') .. (team.won and ' (won)' or ''))
    end
    return table.concat(parts, '  vs  ')
end

local function AverageRating(players)
    local total, count = 0, 0
    for _, player in players or {} do
        if player.rated then
            total = total + player.rating
            count = count + 1
        end
    end
    return count > 0 and math.floor(total / count + 0.5) or nil
end

--- The page. Returns its view; view:Refresh() runs while the page shows.
function Build(launcher, page)
    local view = { tab = 'local', infos = {}, vaultItems = {}, vaultPage = 1, vaultPages = 0, vaultTotal = 0,
        status = '', statusColor = C.subtle }
    launcher.replaysView = view

    local title = Theme.Title(page, 'Replays', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, { { 'local', 'On this computer' }, { 'vault', 'FAF vault' } }, function(key)
        view:SetTab(key)
    end)
    view.tabs.Left:Set(function() return title.Right() + Scale(40) end)
    LayoutHelpers.AtTopIn(view.tabs, page, 0)
    view.tabs.Right:Set(page.Right)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return view.tabs.Bottom() end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    -- The toolbar: the search (local: title, map, player or file; vault: map or title), the vault's player field and
    -- rated games only, then Search (vault) or Rescan (local).
    view.search = Theme.TextField(page, 300, 'Search title, map or player', 'search', 60)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search:OnChange(function()
        if view.tab == 'local' then
            view.localList.top = 1
            view:Refresh()
        end
    end)
    view.player = Theme.TextField(page, 220, 'Player', 'user', 40)
    view.player.Left:Set(function() return view.search.Right() + Scale(12) end)
    view.player.Top:Set(view.search.Top)
    view.rated = Theme.Checkbox(page, 'Rated only', function() end)
    view.rated.Left:Set(function() return view.player.Right() + Scale(18) end)
    view.rated.Top:Set(view.search.Top)
    view.searchButton = Theme.Button(page, 'Search', function()
        view:SearchVault(1)
    end, 'secondary', { icon = 'search', width = 120 })
    view.searchButton.Left:Set(function() return view.rated.Right() + Scale(18) end)
    view.searchButton.Top:Set(view.search.Top)
    view.rescan = Theme.Button(page, 'Rescan', function()
        view:ScanLocal()
        view:Refresh()
    end, 'ghost', { icon = 'refresh', width = 120 })
    view.rescan.Left:Set(function() return view.search.Right() + Scale(12) end)
    view.rescan.Top:Set(view.search.Top)
    for _, field in { view.search, view.player } do
        local this = field
        this.edit.OnEnterPressed = function()
            if view.tab == 'vault' then
                view:SearchVault(1)
            end
            return true
        end
    end

    -- The list on the left, the details on the right.
    local details = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(details, C.accent)
    details.Right:Set(page.Right)
    details.Top:Set(function() return view.search.Bottom() + Scale(16) end)
    details.Bottom:Set(page.Bottom)
    details.Width:Set(Scale(400))
    view.details = details
    local listArea = Group(page)
    listArea.Left:Set(page.Left)
    listArea.Right:Set(function() return details.Left() - Scale(20) end)
    listArea.Top:Set(details.Top)
    listArea.Bottom:Set(function() return page.Bottom() - Scale(34) end)
    listArea.Width:Set(function() return listArea.Right() - listArea.Left() end)
    listArea.Height:Set(function() return listArea.Bottom() - listArea.Top() end)

    local function Pick(item, double)
        view.selected = item
        view:ShowDetails()
        if double then
            view:Watch()
        end
    end
    view.localList = Widgets.VirtualList(listArea, {
        { 'Title', 0.24, function(item) return view:Title(item) end },
        { 'Map', 0.19, function(item) return view:MapText(item) end, C.muted },
        { 'Teams', 0.36, function(item) return view:TeamsText(item) end, C.muted },
        { 'Date', 0.21, function(item) return item.when end, C.subtle },
    }, Pick)
    LayoutHelpers.FillParent(view.localList, listArea)
    view.vaultList = Widgets.VirtualList(listArea, {
        { 'Title', 0.18, function(item) return item.title end },
        { 'Map', 0.14, function(item) return item.mapName end, C.muted },
        { 'Teams', 0.30, function(item) return TeamsText(Teams(item.players)) end, C.muted },
        { 'Avg', 0.09, function(item) return tostring(AverageRating(item.players) or '') end, C.gold },
        { 'Length', 0.10, function(item) return Length(item.seconds) end, C.muted },
        { 'Date', 0.19, function(item) return item.when end, C.subtle },
    }, Pick)
    LayoutHelpers.FillParent(view.vaultList, listArea)
    view.empty = Theme.Text(listArea, '', 14, C.subtle)
    LayoutHelpers.AtCenterIn(view.empty, listArea)
    view.loader = Theme.Loader(listArea)
    LayoutHelpers.AtHorizontalCenterIn(view.loader, listArea)
    view.loader.Bottom:Set(function() return view.empty.Top() - Scale(14) end)

    -- Under the list: what is going on, and the vault's pages.
    view.footer = Theme.Cell(page, 12, C.subtle)
    view.footer.Left:Set(page.Left)
    view.footer.Right:Set(function() return listArea.Right() - Scale(240) end)
    view.footer.Bottom:Set(function() return page.Bottom() - Scale(6) end)
    view.next = Theme.Button(page, '', function()
        view:SearchVault(view.vaultPage + 1)
    end, 'ghost', { icon = 'chevronRight', width = 34, height = 26 })
    view.next.Right:Set(listArea.Right)
    view.next.Bottom:Set(page.Bottom)
    view.pageText = Theme.Text(page, '', 12, C.muted)
    view.pageText.Right:Set(function() return view.next.Left() - Scale(8) end)
    LayoutHelpers.AtVerticalCenterIn(view.pageText, view.next)
    view.previous = Theme.Button(page, '', function()
        view:SearchVault(view.vaultPage - 1)
    end, 'ghost', { icon = 'arrowLeft', width = 34, height = 26 })
    view.previous.Right:Set(function() return view.pageText.Left() - Scale(8) end)
    view.previous.Bottom:Set(page.Bottom)

    -- The details: map, title, what kind of game, the players by team, Watch and Download.
    local frame = Theme.Panel(details, C.field, C.line)
    LayoutHelpers.AtLeftTopIn(frame, details, 18, 18)
    frame.Width:Set(Scale(120))
    frame.Height:Set(Scale(120))
    Widgets.MapPicture(frame)
    view.mapFrame = frame
    local textLeft = function() return frame.Right() + Scale(14) end
    local textRight = function() return details.Right() - Scale(18) end
    view.detailTitle = Theme.Paragraph(details, 15, C.text)
    view.detailTitle.Left:Set(textLeft)
    view.detailTitle.Right:Set(textRight)
    view.detailTitle.Top:Set(frame.Top)
    view.detailLines = Theme.Paragraph(details, 12, C.muted)
    view.detailLines.Left:Set(textLeft)
    view.detailLines.Right:Set(textRight)
    view.detailLines.Top:Set(function() return view.detailTitle.Bottom() + Scale(6) end)
    -- The teams: a heading per team (winner, average rating), then each player with the rating before the game and
    -- what the game changed it by. Rows made as needed and kept.
    local teamArea = Group(details)
    teamArea:DisableHitTest()
    teamArea.Left:Set(function() return details.Left() + Scale(18) end)
    teamArea.Right:Set(textRight)
    teamArea.Top:Set(function() return math.max(frame.Bottom(), view.detailLines.Bottom()) + Scale(18) end)
    teamArea.Width:Set(function() return teamArea.Right() - teamArea.Left() end)
    teamArea.Height:Set(Scale(10))
    view.teamRows = {}
    local function TeamRow(index)
        local row = view.teamRows[index]
        if row then
            return row
        end
        row = {}
        local top = function() return teamArea.Top() + Scale((index - 1) * 22) end
        row.name = Theme.Cell(teamArea, 13, C.text)
        row.name.Left:Set(function() return teamArea.Left() + Scale(row.indent or 0) end)
        row.name.Right:Set(function() return teamArea.Right() - Scale(120) end)
        row.name.Top:Set(top)
        -- A player: flag, clan and name; the name opens the player's profile.
        row.player = Widgets.PlayerTag(teamArea, 13, function(login)
            launcher:ShowProfile(login)
        end)
        row.player.Left:Set(function() return teamArea.Left() + Scale(12) end)
        row.player.Top:Set(function() return top() - Scale(3) end)
        row.tag = Theme.Text(teamArea, '', 11, C.gold, true)
        row.tag.Left:Set(function() return teamArea.Left() + Scale(row.tagLeft or 70) end)
        row.tag.Top:Set(function() return top() + Scale(2) end)
        row.value = Theme.Text(teamArea, '', 13, C.gold)
        row.value.Right:Set(function() return teamArea.Right() - Scale(48) end)
        row.value.Top:Set(top)
        row.change = Theme.Text(teamArea, '', 12, C.good)
        row.change.Right:Set(teamArea.Right)
        row.change.Top:Set(function() return top() + Scale(1) end)
        view.teamRows[index] = row
        return row
    end
    function view:ShowTeams(teams, note)
        local index = 0
        local function Line(name, nameColor, tag, value, valueColor, change, changeColor, indent, player)
            index = index + 1
            local row = TeamRow(index)
            row.indent = indent
            row.name.Left:Set(function() return teamArea.Left() + Scale(indent or 0) end)
            Theme.SetText(row.name, player and '' or name)
            Theme.SetColor(row.name, nameColor)
            Theme.SetVisible(row.player, player ~= nil)
            if player then
                row.player:Set({ login = player.name, color = nameColor })
            end
            Theme.SetText(row.tag, tag or '')
            local advance = name ~= '' and row.name:GetStringAdvance(name) or 0
            row.tag.Left:Set(function() return row.name.Left() + math.min(row.name.Width(), advance) + Scale(10) end)
            if player then
                row.tag.Left:Set(function() return row.player.Right() + Scale(10) end)
            end
            Theme.SetText(row.value, value or '')
            Theme.SetColor(row.value, valueColor or C.gold)
            Theme.SetText(row.change, change or '')
            Theme.SetColor(row.change, changeColor or C.good)
        end
        local ffa = table.getn(teams) == 1
        for i, team in teams do
            local heading = (ffa or team.team <= 1) and 'NO TEAM' or ('TEAM ' .. (team.team - 1))
            Line(heading, C.accent, team.won and 'WINNER' or nil, team.avg and ('avg ' .. team.avg) or nil, C.subtle)
            for _, player in team.players do
                local change, color = nil, nil
                if player.changed then
                    change = (player.change >= 0 and '+' or '') .. player.change
                    color = player.change >= 0 and C.good or C.bad
                end
                Line(player.name, C.text, (ffa and player.won) and 'WINNER' or nil,
                    player.rated and tostring(player.rating) or nil, C.gold, change, color, 12, player)
            end
            if i < table.getn(teams) then
                Line('', C.text)
            end
        end
        if note then
            Line(note, C.subtle)
        end
        if index == 0 then
            Line('No players listed.', C.subtle)
        end
        for i = index + 1, table.getn(self.teamRows) do
            local row = self.teamRows[i]
            Theme.SetVisible(row.player, false)
            Theme.SetText(row.name, '')
            Theme.SetText(row.tag, '')
            Theme.SetText(row.value, '')
            Theme.SetText(row.change, '')
        end
    end
    view.watch = Theme.Button(details, 'Watch', function()
        view:Watch()
    end, 'primary', { icon = 'play', height = 38 })
    view.watch.Left:Set(function() return details.Left() + Scale(18) end)
    view.watch.Right:Set(function() return details.Right() - Scale(18) end)
    view.watch.Width:Set(function() return view.watch.Right() - view.watch.Left() end)
    view.watch.Bottom:Set(function() return details.Bottom() - Scale(18) end)
    view.download = Theme.Button(details, 'Download', function()
        view:Download(false)
    end, 'secondary', { icon = 'download', height = 32 })
    view.download.Left:Set(view.watch.Left)
    view.download.Right:Set(view.watch.Right)
    view.download.Width:Set(function() return view.download.Right() - view.download.Left() end)
    view.download.Bottom:Set(function() return view.watch.Top() - Scale(10) end)
    view.detailNote = Theme.Paragraph(details, 12, C.muted)
    view.detailNote.Left:Set(view.watch.Left)
    view.detailNote.Right:Set(view.watch.Right)
    view.detailNote.Top:Set(function() return view.download.Top() - Scale(40) end)

    -- -------------------------------------------------------------------------------------------------------------

    --- What a local replay's head says, read once per file.
    function view:Info(item)
        if self.infos[item.path] == nil then
            local info = FafLibrary_ReplayInfo(item.path)
            self.infos[item.path] = info or false
        end
        return self.infos[item.path]
    end

    function view:Title(item)
        local info = self:Info(item)
        if info and info.title and info.title ~= '' then
            return info.title
        end
        return item.file
    end

    function view:MapText(item)
        local info = self:Info(item)
        return info and Widgets.MapTitle(info.map) or ''
    end

    function view:TeamsText(item)
        local info = self:Info(item)
        if not info then
            return ''
        end
        local found = info.uid and self.lookups and self.lookups[info.uid]
        return TeamsText(Teams(found and found.players or HeadPlayers(info)))
    end

    --- A FAF replay's game in the vault (ratings, results), asked once per game while signed in.
    function view:LookUp(uid)
        self.lookups = self.lookups or {}
        if not uid or uid == '' or self.lookups[uid] ~= nil or self.lookupJob then
            return
        end
        if not (rawget(_G, 'FafOnline_Status') and FafOnline_Status().signIn == 'signedin') then
            return
        end
        self.lookups[uid] = false
        self.lookupJob = FafLibrary_SearchReplays({ id = uid, pageSize = 1 })
        self.lookupFor = uid
    end

    --- A replay file's game time, read once per file (the whole file: only for the selected one).
    function view:GameLength(path)
        self.lengths = self.lengths or {}
        if self.lengths[path] == nil then
            self.lengths[path] = rawget(_G, 'FafLibrary_ReplayLength') and FafLibrary_ReplayLength(path) or false
        end
        return self.lengths[path]
    end

    function view:ScanLocal()
        local items = {}
        if Available() then
            for _, replay in FafLibrary_LocalReplays() do
                replay.key = replay.path
                replay.when = LocalTime(replay.time)
                table.insert(items, replay)
            end
        end
        table.sort(items, function(a, b) return a.time > b.time end)
        self.localItems = items
        LOG('LAUNCHER: ' .. table.getn(items) .. ' replays on this computer')
    end

    function view:SetTab(key)
        self.tab = key
        self.selected = nil
        if key == 'vault' and not self.vaultSearched then
            self:SearchVault(1)
        end
        self:Refresh()
    end

    function view:SearchVault(number)
        if number < 1 or (self.vaultPages > 0 and number > self.vaultPages) or self.searchJob then
            return
        end
        if not Available() then
            return
        end
        self.vaultSearched = true
        self.searchJob = FafLibrary_SearchReplays({
            title = '', map = self.search.edit:GetText(), player = self.player.edit:GetText(),
            rated = self.rated.on and true or false, page = number, pageSize = kPageSize,
        })
        self.searchPage = number
        self.status, self.statusColor = 'Searching FAF\'s replay vault...', C.accent
        self:Refresh()
    end

    --- The selected vault replay into the launcher's replay folder; `andWatch`: watch it once it's there.
    function view:Download(andWatch)
        local item = self.selected
        if not item or self.tab ~= 'vault' or self.downloadJob then
            return
        end
        self.downloadJob = FafLibrary_DownloadReplay(item.id)
        self.downloadFor = item.id
        self.watchAfter = andWatch
        self.status, self.statusColor = 'Downloading the replay of ' .. item.title .. '...', C.accent
        self:Refresh()
    end

    function view:Watch()
        local item = self.selected
        if not item then
            return
        end
        if self.tab == 'vault' then
            local path = self.downloaded and self.downloaded[item.id]
            if not path then
                self:Download(true)
                return
            end
            item = { path = path }
        end
        local ok, why = launcher:WatchReplay(item.path)
        if not ok then
            self.status, self.statusColor = 'Can\'t watch it: ' .. tostring(why), C.bad
            self:Refresh()
        end
    end

    --- The answers of the searches and downloads under way.
    function view:Poll()
        if self.lookupJob then
            local job = FafLibrary_Job(self.lookupJob)
            if not job or job.state ~= 'working' then
                self.lookupJob = nil
                local found = job and job.state == 'done' and job.items and job.items[1]
                self.lookups[self.lookupFor] = found or false
                LOG('LAUNCHER: replay ' .. tostring(self.lookupFor) .. (found and ' found in the vault' or
                    ' not found in the vault'))
            end
        end
        if self.searchJob then
            local job = FafLibrary_Job(self.searchJob)
            if not job or job.state ~= 'working' then
                self.searchJob = nil
                if job and job.state == 'done' then
                    for _, item in job.items do
                        item.key = item.id
                        item.when = LocalTime(item.startTime)
                        item.color = (not item.available) and C.subtle or nil
                    end
                    self.vaultItems = job.items
                    self.vaultPage = self.searchPage
                    self.vaultPages = job.totalPages or 0
                    self.vaultTotal = job.totalRecords or 0
                    self.vaultList.top = 1
                    self.status, self.statusColor = '', C.subtle
                    LOG('LAUNCHER: replay vault page ' .. self.vaultPage .. ' of ' .. self.vaultPages .. ', ' ..
                        table.getn(job.items) .. ' games')
                else
                    self.status = 'The search failed: ' .. tostring(job and job.message or 'no answer')
                    self.statusColor = C.bad
                    WARN('LAUNCHER: ' .. self.status)
                end
            end
        end
        if self.downloadJob then
            local job = FafLibrary_Job(self.downloadJob)
            if job and job.state == 'working' then
                if job.total > 0 then
                    self.status = string.format('Downloading the replay... %d%%', math.floor(job.received * 100 / job.total))
                end
            else
                self.downloadJob = nil
                if job and job.state == 'done' then
                    self.downloaded = self.downloaded or {}
                    self.downloaded[self.downloadFor] = job.path
                    self.localItems = nil -- the local list shows it too
                    self.status, self.statusColor = 'Downloaded: ' .. job.path, C.good
                    LOG('LAUNCHER: replay downloaded to ' .. job.path)
                    if self.watchAfter and self.selected and self.selected.id == self.downloadFor then
                        self:Watch()
                    end
                else
                    self.status = 'The download failed: ' .. tostring(job and job.message or 'no answer')
                    self.statusColor = C.bad
                    WARN('LAUNCHER: ' .. self.status)
                end
            end
        end
    end

    local function TeamName(team)
        if not team or team <= 1 then
            return 'No team'
        end
        return 'Team ' .. (team - 1)
    end

    function view:ShowDetails()
        local item = self.selected
        Theme.SetVisible(self.details, true)
        if not item then
            self.mapFrame:SetMap(nil)
            self.detailTitle:SetText('Pick a replay to see its players.', C.subtle)
            self.detailLines:SetText('')
            self:ShowTeams({}, '')
            self.detailNote:SetText('')
            self.watch:SetEnabled(false)
            Theme.SetVisible(self.download, false)
            return
        end
        local lines = {}
        local players = {}
        local teamNote = nil
        local map, title
        -- Game time (the replay's beats) against the time on the wall clock from start to end; a game that ran slower
        -- than real time (a slow machine, pauses) shows a longer wall time.
        local function Times(game, wall)
            local parts = {}
            if game and game > 0 then
                table.insert(parts, 'Game time ' .. Length(game))
            end
            if wall and wall > 0 then
                table.insert(parts, 'real time ' .. Length(wall))
            end
            if table.getn(parts) > 0 then
                table.insert(lines, table.concat(parts, '  -  '))
            end
        end
        if self.tab == 'local' then
            local info = self:Info(item)
            title = self:Title(item)
            if info then
                map = info.map
                table.insert(lines, Widgets.MapTitle(info.map))
                if info.featuredMod and info.featuredMod ~= '' then
                    table.insert(lines, 'Featured mod: ' .. info.featuredMod)
                end
                table.insert(lines, LocalTime(info.launchedAt ~= 0 and info.launchedAt or item.time))
                local wall = (info.gameEnd and info.launchedAt and info.gameEnd > info.launchedAt) and
                    (info.gameEnd - info.launchedAt) or nil
                Times(self:GameLength(item.path), wall)
                if table.getn(info.mods or {}) > 0 then
                    table.insert(lines, 'Mods: ' .. table.concat(info.mods, ', '))
                end
                players = HeadPlayers(info)
                if info.kind == 'faf' and info.uid and info.uid ~= '' then
                    self:LookUp(info.uid)
                    local found = self.lookups and self.lookups[info.uid]
                    if found then
                        players = found.players
                    elseif self.lookupJob and self.lookupFor == info.uid then
                        teamNote = 'Asking FAF for ratings and results...'
                    elseif found == false then
                        teamNote = 'FAF has no ratings for this game, or you aren\'t signed in.'
                    end
                end
            else
                table.insert(lines, 'Its head can\'t be read.')
            end
            table.insert(lines, (kSourceNames[item.source] or item.source) .. ' - ' .. item.file)
        else
            title = item.title
            map = item.map
            table.insert(lines, item.mapName)
            table.insert(lines, 'Featured mod: ' .. item.featuredMod .. (item.validity == 'VALID' and ', rated' or ''))
            table.insert(lines, item.when)
            Times(item.seconds, item.wallSeconds)
            if item.reviews > 0 then
                table.insert(lines, string.format('Reviews: %.1f of 5 (%d)', item.reviewScore, item.reviews))
            end
            players = item.players
        end
        self.mapFrame:SetMap(map)
        self.detailTitle:SetText(title or '', C.text)
        self.detailLines:SetText(table.concat(lines, '\n'), C.muted)

        self:ShowTeams(Teams(players), teamNote)

        local note = ''
        local canWatch = true
        if self.tab == 'vault' then
            Theme.SetVisible(self.download, true)
            local have = self.downloaded and self.downloaded[item.id]
            self.download:SetEnabled(item.available and not have and not self.downloadJob)
            if not item.available then
                canWatch = false
                note = 'FAF has no replay of this game.'
            elseif have then
                note = 'Downloaded to ' .. have
            end
        else
            Theme.SetVisible(self.download, false)
        end
        self.watch:SetEnabled(canWatch and not self.downloadJob)
        self.detailNote:SetText(note, C.muted)
    end

    function view:Refresh()
        self:Poll()
        local vault = self.tab == 'vault'
        self.tabs:Set(self.tab, { ['local'] = self.localItems and table.getn(self.localItems) or nil,
            vault = vault and self.vaultTotal > 0 and self.vaultTotal or nil })
        Theme.SetVisible(self.player, vault)
        Theme.SetVisible(self.rated, vault)
        Theme.SetVisible(self.searchButton, vault)
        Theme.SetVisible(self.rescan, not vault)
        Theme.SetVisible(self.localList, not vault)
        Theme.SetVisible(self.vaultList, vault)
        Theme.SetVisible(self.previous, vault)
        Theme.SetVisible(self.next, vault)
        Theme.SetVisible(self.pageText, vault)
        self.search:Refresh()
        if vault then
            self.player:Refresh() -- its hint shows again otherwise, over the local tab
        end

        local empty = ''
        local loading = false
        if not Available() then
            empty = 'This build of the game has no replay library.'
        elseif vault then
            if self.searchJob and table.getn(self.vaultItems) == 0 then
                empty, loading = 'Searching FAF\'s replay vault...', true
            elseif table.getn(self.vaultItems) == 0 and self.vaultSearched and not self.searchJob then
                empty = 'No game matches.'
            end
            self.vaultList:SetItems(self.vaultItems)
            Theme.SetText(self.pageText, self.vaultPages > 0 and
                string.format('Page %d of %d', self.vaultPage, self.vaultPages) or '')
            self.previous:SetEnabled(self.vaultPage > 1 and not self.searchJob)
            self.next:SetEnabled(self.vaultPage < self.vaultPages and not self.searchJob)
        else
            if not self.localItems then
                self:ScanLocal()
            end
            local filter = string.lower(self.search.edit:GetText())
            local shown = self.localItems
            if filter ~= '' then
                -- File names always; titles, maps and players once read (rows read theirs as they come on screen).
                shown = {}
                for _, item in self.localItems do
                    local info = self.infos[item.path]
                    local match = Contains(item.file, filter)
                    if not match and info then
                        match = Contains(info.title, filter) or Contains(info.map, filter) or
                            Contains(Widgets.MapTitle(info.map), filter)
                        for _, player in info.players or {} do
                            match = match or Contains(player.name, filter)
                        end
                    end
                    if match then
                        table.insert(shown, item)
                    end
                end
            end
            if table.getn(shown) == 0 then
                empty = filter ~= '' and 'No replay matches the search.' or 'No replays on this computer yet.'
            end
            self.localList:SetItems(shown)
        end
        Theme.SetText(self.empty, empty)
        Theme.SetVisible(self.loader, loading)
        Theme.SetText(self.footer, self.status ~= '' and self.status or (vault and
            'Double-click a game to download and watch its replay.' or
            'Double-click a replay to watch it.'))
        Theme.SetColor(self.footer, self.statusColor)
        self:ShowDetails()
    end

    return view
end
