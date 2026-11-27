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
        { 'Title', 0.38, function(item) return view:Title(item) end },
        { 'Map', 0.24, function(item) return view:MapText(item) end, C.muted },
        { 'Players', 0.14, function(item) return view:PlayerCount(item) end, C.muted },
        { 'Date', 0.24, function(item) return item.when end, C.subtle },
    }, Pick)
    LayoutHelpers.FillParent(view.localList, listArea)
    view.vaultList = Widgets.VirtualList(listArea, {
        { 'Title', 0.34, function(item) return item.title end },
        { 'Map', 0.24, function(item) return item.mapName end, C.muted },
        { 'Players', 0.10, function(item) return tostring(table.getn(item.players)) end, C.muted },
        { 'Length', 0.10, function(item) return Length(item.seconds) end, C.muted },
        { 'Date', 0.22, function(item) return item.when end, C.subtle },
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
    view.teams = Theme.Paragraph(details, 13, C.text)
    view.teams.Left:Set(function() return details.Left() + Scale(18) end)
    view.teams.Right:Set(textRight)
    view.teams.Top:Set(function() return math.max(frame.Bottom(), view.detailLines.Bottom()) + Scale(18) end)
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

    function view:PlayerCount(item)
        local info = self:Info(item)
        return info and tostring(table.getn(info.players or {})) or ''
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
            self.teams:SetText('')
            self.detailNote:SetText('')
            self.watch:SetEnabled(false)
            Theme.SetVisible(self.download, false)
            return
        end
        local lines = {}
        local players = {}
        local map, title
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
                if info.gameEnd and info.launchedAt and info.gameEnd > info.launchedAt then
                    table.insert(lines, 'Length ' .. Length(info.gameEnd - info.launchedAt))
                end
                if table.getn(info.mods or {}) > 0 then
                    table.insert(lines, 'Mods: ' .. table.concat(info.mods, ', '))
                end
                players = info.players or {}
            else
                table.insert(lines, 'Its head can\'t be read.')
            end
            table.insert(lines, (kSourceNames[item.source] or item.source) .. ' - ' .. item.file)
        else
            title = item.title
            map = item.map
            table.insert(lines, item.mapName)
            table.insert(lines, 'Featured mod: ' .. item.featuredMod .. (item.validity == 'VALID' and ', rated' or ''))
            table.insert(lines, item.when .. (item.seconds > 0 and ('  -  ' .. Length(item.seconds)) or ''))
            if item.reviews > 0 then
                table.insert(lines, string.format('Reviews: %.1f of 5 (%d)', item.reviewScore, item.reviews))
            end
            players = item.players
        end
        self.mapFrame:SetMap(map)
        self.detailTitle:SetText(title or '', C.text)
        self.detailLines:SetText(table.concat(lines, '\n'), C.muted)

        -- Players by team, each with the rating they had before the game when known.
        local byTeam = {}
        local order = {}
        for _, player in players do
            local key = player.team or 0
            if not byTeam[key] then
                byTeam[key] = {}
                table.insert(order, key)
            end
            local text = player.name or ''
            if player.rated then
                text = text .. '  (' .. player.rating .. ')'
            end
            if player.result and player.result ~= '' then
                text = text .. '  ' .. string.lower(player.result)
            end
            table.insert(byTeam[key], text)
        end
        table.sort(order)
        local teamLines = {}
        for _, team in order do
            if table.getn(order) > 1 or team > 1 then
                table.insert(teamLines, string.upper(TeamName(team)))
            end
            for _, text in byTeam[team] do
                table.insert(teamLines, '  ' .. text)
            end
        end
        self.teams:SetText(table.getn(teamLines) > 0 and table.concat(teamLines, '\n') or 'No players listed.', C.text)

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
