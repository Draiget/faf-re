-- The launcher's Leaderboards page: FAF's rating ladders (1v1, 2v2, 4v4, 4v4 full share, global) from FAF's API
-- (/data/leaderboardRating with each rating's player), ranked by rating, a page at a time; search by name; by default
-- only players who played in the last 30 days, as FAF's website shows them. On the right: where the signed-in player
-- stands on the chosen ladder (rank, rating, games, win rate, with a jump to their page) and the chosen player's
-- numbers with a link to their FAF profile.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local Kit = import('/fafengine/modules/lua/ui/launcher/kit.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kPageSize = 100
local kActiveDays = 30
local kBoards = {
    { 'ladder_1v1', '1v1' },
    { 'tmm_2v2', '2v2' },
    { 'tmm_4v4_share_until_death', '4v4' },
    { 'tmm_4v4_full_share', '4v4 full share' },
    { 'global', 'Global' },
}

-- FAF's API answers (JSON:API): resources by type and id, relationships followed through `included`.
local function Store(doc)
    local store = {}
    for _, list in { doc and doc.data or {}, doc and doc.included or {} } do
        for _, resource in list do
            if type(resource) == 'table' and resource.type and resource.id then
                store[resource.type .. ':' .. resource.id] = resource
            end
        end
    end
    return store
end

local function Rel(store, resource, name)
    local link = resource and resource.relationships and resource.relationships[name]
    local data = link and link.data
    if type(data) ~= 'table' or not data.type then
        return nil
    end
    return store[data.type .. ':' .. data.id] or { id = data.id, type = data.type }
end

local function Attr(resource, name)
    return resource and resource.attributes and resource.attributes[name]
end

local function WinRate(won, total)
    if not total or total <= 0 then
        return '-'
    end
    return string.format('%.1f%%', (won or 0) * 100 / total)
end

--- A rating row from one leaderboardRating resource.
local function Row(store, rating)
    local player = Rel(store, rating, 'player')
    local games = Attr(rating, 'totalGames') or 0
    local won = Attr(rating, 'wonGames') or 0
    local value = Attr(rating, 'rating') or 0
    return {
        key = rating.id, playerId = player and player.id, login = Attr(player, 'login') or '?',
        rating = math.floor(value + 0.5), ratingExact = value, mean = Attr(rating, 'mean') or 0,
        deviation = Attr(rating, 'deviation') or 0, games = games, won = won, winRate = WinRate(won, games),
        updated = Attr(rating, 'updateTime'),
    }
end

function Build(launcher, page)
    local view = { board = kBoards[1][1], pageNumber = 1, pages = 0, total = nil, rows = nil, jobs = {},
        active = true, mine = {} }
    launcher.leaderboardsView = view

    local title = Theme.Title(page, 'Leaderboards', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    local tabEntries = {}
    for _, board in kBoards do
        table.insert(tabEntries, { board[1], board[2] })
    end
    view.tabs = Widgets.Tabs(page, tabEntries, function(key)
        view:Choose(key)
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

    view.search = Theme.TextField(page, 340, 'Find a player by name', 'search', 60)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search.edit.OnEnterPressed = function()
        view.pageNumber = 1
        view:Load()
        return true
    end
    view.activeBox = Theme.Checkbox(page, 'Played in the last ' .. kActiveDays .. ' days', function(box)
        view.active = box.on
        view.pageNumber = 1
        view.mine = {}
        view:Load()
    end)
    view.activeBox.Left:Set(function() return view.search.Right() + Scale(24) end)
    LayoutHelpers.AtVerticalCenterIn(view.activeBox, view.search)
    view.activeBox:SetOn(true)
    view.pageText = Theme.Text(page, '', 12, C.subtle)
    view.prev = Theme.Button(page, '', function() view:Turn(-1) end, 'ghost', { icon = 'arrowLeft', width = 36 })
    view.next = Theme.Button(page, '', function() view:Turn(1) end, 'ghost', { icon = 'arrowRight', width = 36 })

    -- The ranking on the left, the signed-in player and the chosen one on the right.
    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Right:Set(page.Right)
    detail.Top:Set(function() return view.search.Bottom() + Scale(18) end)
    detail.Bottom:Set(page.Bottom)
    LayoutHelpers.SetWidth(detail, 400)
    detail.Left:Set(function() return detail.Right() - detail.Width() end)
    detail.Height:Set(function() return detail.Bottom() - detail.Top() end)
    -- Right-aligned over the list, but never over the checkbox on a narrow window.
    view.next.Right:Set(function()
        return math.max(detail.Left() - Scale(24), view.activeBox.Right() + Scale(24 + 10 + 4) + view.pageText.Width() +
            view.prev.Width() + view.next.Width())
    end)
    view.next.Top:Set(view.search.Top)
    view.prev.Right:Set(function() return view.next.Left() - Scale(4) end)
    view.prev.Top:Set(view.search.Top)
    view.pageText.Right:Set(function() return view.prev.Left() - Scale(10) end)
    LayoutHelpers.AtVerticalCenterIn(view.pageText, view.search)

    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(function() return detail.Left() - Scale(24) end)
    area.Top:Set(detail.Top)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    view.list = Widgets.VirtualList(area, {
        { 'Rank', 0.1, function(item) return item.rank and ('#' .. item.rank) or '' end, C.subtle },
        { 'Player', 0.4, function(item) return { login = item.login, country = item.country, clan = item.clan } end,
            kind = 'player' },
        { 'Rating', 0.16, function(item) return tostring(item.rating) end, C.gold },
        { 'Games', 0.16, function(item) return tostring(item.games) end, C.muted },
        { 'Win rate', 0.18, function(item) return item.winRate end, C.muted },
    }, function(item, double)
        view.chosen = item
        if double then
            launcher:ShowProfile(item.login)
        end
        view:Paint()
    end)
    LayoutHelpers.FillParent(view.list, area)
    Theme.SizeFromEdges(view.list)
    view.note = Theme.Paragraph(area, 14, C.subtle)
    view.note.Left:Set(area.Left)
    view.note.Right:Set(function() return area.Left() + math.min(area.Width(), Scale(600)) end)
    view.note.Top:Set(function() return area.Top() + Scale(40) end)
    view.loader = Theme.Loader(area)
    LayoutHelpers.AtCenterIn(view.loader, area)

    -- Your standing: the rank big, the numbers under it, Show me beside it. Kept short so the panel fits 900 px.
    local x = 24
    local youCaption = Theme.Caption(detail, 'Your standing', C.accent)
    LayoutHelpers.AtLeftTopIn(youCaption, detail, x, 22)
    view.youRank = Theme.Title(detail, '', 30, C.text)
    view.youRank.Left:Set(youCaption.Left)
    view.youRank.Top:Set(function() return youCaption.Bottom() + Scale(10) end)
    view.findMe = Theme.Button(detail, 'Show me', function() view:FindMe() end, 'secondary', { icon = 'user', width = 130 })
    LayoutHelpers.AtRightIn(view.findMe, detail, x)
    LayoutHelpers.AtVerticalCenterIn(view.findMe, view.youRank)
    view.youFacts = Theme.Text(detail, '', 13, C.muted)
    view.youFacts.Left:Set(youCaption.Left)
    view.youFacts.Top:Set(function() return view.youRank.Bottom() + Scale(8) end)
    local split = Theme.Rect(detail, C.line)
    split.Left:Set(function() return detail.Left() + Scale(x) end)
    split.Right:Set(function() return detail.Right() - Scale(x) end)
    split.Top:Set(function() return view.youFacts.Bottom() + Scale(20) end)
    split.Height:Set(1)
    split.Width:Set(function() return split.Right() - split.Left() end)

    -- The chosen player: name (a click opens the profile) with Profile beside it, the last rated game, and the
    -- numbers in a grid of three columns.
    local chosenCaption = Theme.Caption(detail, 'Player', C.accent)
    chosenCaption.Left:Set(youCaption.Left)
    chosenCaption.Top:Set(function() return split.Bottom() + Scale(20) end)
    view.who = Widgets.PlayerTag(detail, 18, function(login) launcher:ShowProfile(login) end)
    view.who.Left:Set(youCaption.Left)
    view.who.Top:Set(function() return chosenCaption.Bottom() + Scale(10) end)
    view.profileButton = Theme.Button(detail, 'Profile', function()
        if view.chosen then
            launcher:ShowProfile(view.chosen.login)
        end
    end, 'secondary', { icon = 'external', width = 130 })
    LayoutHelpers.AtRightIn(view.profileButton, detail, x)
    LayoutHelpers.AtVerticalCenterIn(view.profileButton, view.who)
    view.lastGame = Theme.Text(detail, '', 12, C.subtle)
    view.lastGame.Left:Set(youCaption.Left)
    view.lastGame.Top:Set(function() return view.who.Bottom() + Scale(6) end)
    -- The numbers as the kit's stat boxes, three to a row; then the rating's history as a sparkline.
    view.stats = {}
    local labels = { 'Rank', 'Rating', 'Win rate', 'Games', 'Won', 'Mean +/- dev.' }
    local statArea = Group(detail)
    statArea:DisableHitTest()
    statArea.Left:Set(function() return detail.Left() + Scale(x) end)
    statArea.Right:Set(function() return detail.Right() - Scale(x) end)
    statArea.Top:Set(function() return view.lastGame.Bottom() + Scale(14) end)
    statArea.Width:Set(function() return statArea.Right() - statArea.Left() end)
    -- Two rows of boxes when the panel has the room for them and the history (1600x900 has room for one).
    local function Short()
        return detail.Bottom() - view.lastGame.Bottom() < Scale(14 + 128 + 14 + 18 + 10 + 44 + 10)
    end
    statArea.Height:Set(function() return Scale(Short() and 60 or 128) end)
    view.short = Short
    local firstRow, secondRow = {}, {}
    for i, label in labels do
        local box = Kit.StatBox(detail, label, true)
        view.stats[i] = box
        table.insert(i <= 3 and firstRow or secondRow, box)
    end
    Kit.Row(statArea, firstRow, 0, 8)
    Kit.Row(statArea, secondRow, 68, 8)
    local historyCaption = Kit.Heading(detail, 'Rating history')
    historyCaption.Left:Set(statArea.Left)
    historyCaption.Top:Set(function() return statArea.Bottom() + Scale(Short() and 10 or 14) end)
    view.historyNote = historyCaption.note
    view.spark = Kit.Sparkline(detail)
    view.spark.Left:Set(statArea.Left)
    view.spark.Right:Set(function() return statArea.Right() - Scale(6) end)
    view.spark.Top:Set(function() return historyCaption.Bottom() + Scale(Short() and 6 or 10) end)
    view.spark.Width:Set(function() return view.spark.Right() - view.spark.Left() end)
    view.spark.Height:Set(function() return Scale(Short() and 26 or 44) end)
    view.history = {} -- by '<board>:<player id>': the ratings after each game, oldest first; false while asked

    ----------------------------------------------------------------------------------------------------------------

    local function Ask(key, query, done, path)
        if not rawget(_G, 'FafLibrary_Api') then
            view.failure = 'This build has no FAF API access.'
            return
        end
        local id, why = FafLibrary_Api(path or '/data/leaderboardRating', query)
        if not id then
            view.failure = tostring(why)
            return
        end
        view.jobs[key] = { id = id, done = done }
    end

    --- The filter every query of the chosen ladder shares: the ladder, and recent players only when asked.
    local function BoardFilter()
        local filter = 'leaderboard.technicalName==' .. view.board
        if view.active and rawget(_G, 'FafLibrary_UtcDate') then
            filter = filter .. ';updateTime=ge=' .. FafLibrary_UtcDate(kActiveDays)
        end
        return filter
    end

    function view:Choose(board)
        self.board = board
        self.pageNumber = 1
        self.chosen = nil
        self:Load()
    end

    function view:Load()
        local text = string.gsub(self.search.edit:GetText() or '', '"', '')
        local filter = BoardFilter()
        self.searching = text ~= ''
        if self.searching then
            filter = filter .. ';player.login=="*' .. text .. '*"'
        end
        self.rows = nil
        self.failure = nil
        local board, number = self.board, self.pageNumber
        Ask('page', { filter = filter, sort = '-rating', include = 'player', ['page[size]'] = tostring(kPageSize),
            ['page[number]'] = tostring(number), ['page[totals]'] = '' }, function(doc)
            if board ~= view.board or number ~= view.pageNumber then
                return -- the player moved on meanwhile
            end
            local store = Store(doc)
            local rows = {}
            for index, rating in (doc.data or {}) do
                local row = Row(store, rating)
                -- A rank only for the plain ranking: a search's places aren't ranks.
                row.rank = not view.searching and ((number - 1) * kPageSize + index) or nil
                table.insert(rows, row)
            end
            view.rows = rows
            local meta = doc.meta and doc.meta.page or {}
            view.pages = meta.totalPages or 1
            view.total = meta.totalRecords or table.getn(rows)
            if view.wantChosen then
                for _, row in rows do
                    if row.playerId == view.wantChosen then
                        view.chosen = row
                        view.list.selectedKey = row.key
                        view.scrollTo = row.key
                    end
                end
                view.wantChosen = nil
            end
            if not view.chosen and rows[1] then
                view.chosen = rows[1]
                view.list.selectedKey = rows[1].key
            end
        end)
        self:AskMine()
    end

    --- Where the signed-in player stands: their rating on the ladder, then how many rate above it.
    function view:AskMine()
        local login = (launcher.lastStatus or {}).login or ''
        local key = self.board .. (self.active and ':active' or ':all')
        if login == '' or (launcher.lastStatus or {}).lobby ~= 'signedin' or self.mine[key] then
            return
        end
        self.mine[key] = { state = 'asking' }
        local mine = self.mine[key]
        Ask('mine', { filter = BoardFilter() .. ';player.login=="' .. login .. '"', include = 'player',
            ['page[size]'] = '1' }, function(doc)
            local rating = doc.data and doc.data[1]
            if not rating then
                mine.state = 'none'
                return
            end
            mine.row = Row(Store(doc), rating)
            mine.state = 'counting'
            -- Lua's numbers here are 32-bit floats: the rating sent back is rounded up a hundredth, so the player
            -- never counts above themselves.
            Ask('mineRank', { filter = BoardFilter() .. ';rating=gt=' .. string.format('%.2f', mine.row.ratingExact + 0.01),
                ['page[size]'] = '1', ['page[totals]'] = '' }, function(counted)
                local meta = counted.meta and counted.meta.page or {}
                mine.row.rank = (meta.totalRecords or 0) + 1
                mine.state = 'done'
            end)
        end)
    end

    function view:FindMe()
        local mine = self.mine[self.board .. (self.active and ':active' or ':all')]
        if not mine or not mine.row or not mine.row.rank then
            return
        end
        self.search.edit:SetText('')
        self.pageNumber = math.floor((mine.row.rank - 1) / kPageSize) + 1
        self.wantChosen = mine.row.playerId
        self.chosen = nil
        self:Load()
    end

    function view:Turn(by)
        local wanted = math.max(1, math.min(self.pages or 1, self.pageNumber + by))
        if wanted ~= self.pageNumber then
            self.pageNumber = wanted
            self.chosen = nil
            self:Load()
            self:Paint()
        end
    end

    function view:Poll()
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if not state or state.state ~= 'working' then
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: leaderboards: reading ' .. key .. ' failed: ' .. tostring(err))
                    end
                elseif key == 'page' then
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                end
                break -- a finished job may start another; the next refresh takes the rest
            end
        end
    end

    function view:Paint()
        local counts = {}
        counts[self.board] = self.total
        self.tabs:Set(self.board, counts)
        Theme.SetVisible(self.loader, self.rows == nil and not self.failure)
        local note = ''
        if self.failure then
            note = 'The ranking didn\'t load: ' .. self.failure
        elseif self.rows and table.getn(self.rows) == 0 then
            note = self.searching and 'No player with that name on this ladder.' or
                (self.active and 'No one played on this ladder in the last ' .. kActiveDays .. ' days.' or
                'No one is rated on this ladder yet.')
        end
        self.note:SetText(note, self.failure and C.bad or C.subtle)
        local rows = self.rows or {}
        if self.list.items ~= rows then
            self.list.top = 1
            self.list:SetItems(rows)
        end
        if self.scrollTo and self.rows then
            for index, item in rows do
                if item.key == self.scrollTo then
                    self.list:ScrollSetTop(nil, index - 3) -- a few rows above it stay in sight
                end
            end
            self.scrollTo = nil
        end
        self.list:Paint()
        Theme.SetText(self.pageText, self.pages and self.pages > 0 and
            ('Page ' .. self.pageNumber .. ' of ' .. self.pages) or '')
        self.prev:SetEnabled(self.pageNumber > 1)
        self.next:SetEnabled(self.pages ~= nil and self.pageNumber < self.pages)

        -- Your standing.
        local status = launcher.lastStatus or {}
        local mine = self.mine[self.board .. (self.active and ':active' or ':all')]
        local signedIn = status.lobby == 'signedin' and (status.login or '') ~= ''
        local row = mine and mine.row
        if not signedIn then
            Theme.SetText(self.youRank, '-')
            Theme.SetText(self.youFacts, 'Connect to FAF to see your place.')
        elseif not mine or mine.state == 'asking' or mine.state == 'counting' then
            Theme.SetText(self.youRank, '...')
            Theme.SetText(self.youFacts, 'Asking FAF where ' .. status.login .. ' stands...')
        elseif mine.state == 'none' then
            Theme.SetText(self.youRank, '-')
            Theme.SetText(self.youFacts, self.active and ('No rated game here in the last ' .. kActiveDays .. ' days.')
                or 'No rated game on this ladder yet.')
        else
            local known = self.total and self.total > 0 and not self.searching
            Theme.SetText(self.youRank, '#' .. tostring(row.rank) .. (known and ('  of ' .. self.total) or ''))
            Theme.SetText(self.youFacts, 'Rating ' .. row.rating .. '  -  ' .. row.games .. ' games  -  ' .. row.winRate ..
                ' won' .. (known and string.format('  -  top %.1f%%', math.max(0.1, row.rank * 100 / self.total)) or ''))
        end
        self.findMe:SetEnabled(row ~= nil and row.rank ~= nil)

        -- The chosen player.
        local chosen = self.chosen
        self.who:Set({ login = chosen and chosen.login or '' })
        local short = self.short() -- 1600x900: one row of boxes, the history's numbers without its line
        local statValues = {
            chosen and chosen.rank and ('#' .. chosen.rank) or '-',
            chosen and tostring(chosen.rating) or '-',
            chosen and chosen.winRate or '-',
            chosen and tostring(chosen.games) or '-',
            chosen and tostring(chosen.won) or '-',
            chosen and string.format('%d +/- %d', math.floor(chosen.mean + 0.5), math.floor(chosen.deviation + 0.5)) or '-',
        }
        for i, value in statValues do
            self.stats[i]:Set(value, i == 2 and value ~= '-' and C.gold or nil)
            Theme.SetVisible(self.stats[i], i <= 3 or not short)
        end
        -- The chosen player's rating after each game on this ladder (the journal's mean - 3 deviations), asked once.
        local historyKey = chosen and chosen.playerId and (self.board .. ':' .. chosen.playerId)
        if historyKey and self.history[historyKey] == nil and not self.jobs.history then
            self.history[historyKey] = false
            Ask('history', {
                filter = 'gamePlayerStats.player.id==' .. chosen.playerId .. ';leaderboard.technicalName==' .. self.board,
                sort = 'gamePlayerStats.scoreTime', ['page[size]'] = '1000',
            }, function(doc)
                local values = {}
                for _, entry in (doc.data or {}) do
                    local attributes = entry.attributes or {}
                    if attributes.meanAfter and attributes.deviationAfter then
                        table.insert(values, attributes.meanAfter - 3 * attributes.deviationAfter)
                    end
                end
                view.history[historyKey] = values
            end, '/data/leaderboardRatingJournal')
        end
        local values = historyKey and self.history[historyKey]
        -- Short of room (1600x900): the history's numbers only, without its line.
        self.spark:Draw(not short and values or {}, C.gold)
        local count = values and table.getn(values) or 0
        local change = count >= 2 and math.floor(values[count] - values[1] + 0.5) or nil
        Theme.SetText(self.historyNote, not chosen and '' or (values == false and 'asking FAF...') or
            (count < 2 and 'too few games to draw') or
            (count .. ' games, ' .. (change >= 0 and '+' or '') .. change .. ' since the first'))
        Theme.SetColor(self.historyNote, change and (change >= 0 and C.good or C.bad) or C.subtle)
        local last = chosen and chosen.updated and rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(chosen.updated)
        Theme.SetText(self.lastGame, last and last ~= '' and ('Last rated game ' .. last) or '')
        self.profileButton:SetEnabled(chosen ~= nil)
    end

    function view:Refresh()
        if not self.rows and not self.jobs.page and not self.failure then
            self:Load()
        end
        if not self.mine[self.board .. (self.active and ':active' or ':all')] then
            self:AskMine()
        end
        self:Poll()
        self:Paint()
    end

    return view
end
