-- The launcher's Co-op page (Play > Co-op): FAF's co-op missions (/data/coopMission, grouped by /data/coopScenario's
-- campaigns), the chosen one's picture, story and fastest completions (/data/coopResult), Host this mission (a FAF
-- game on the coop featured mod with the mission's map), and the co-op games open now to join.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kFactionNames = { uef = 'UEF', aeon = 'Aeon', cybran = 'Cybran', seraphim = 'Seraphim', nomads = 'Nomads' }

-- FAF's API answers (JSON:API): resources by type and id, relationships followed through `included`.
local function Store(doc)
    local store = {}
    local function Add(resource)
        if type(resource) == 'table' and resource.type and resource.id then
            store[resource.type .. ':' .. resource.id] = resource
        end
    end
    for _, resource in (doc and doc.data or {}) do
        Add(resource)
    end
    for _, resource in (doc and doc.included or {}) do
        Add(resource)
    end
    return store
end

local function Rel(store, resource, name)
    local link = resource and resource.relationships and resource.relationships[name]
    local data = link and link.data
    if type(data) ~= 'table' then
        return nil
    end
    if data.type then
        return store[data.type .. ':' .. data.id] or { id = data.id, type = data.type }
    end
    local list = {}
    for _, item in data do
        table.insert(list, store[item.type .. ':' .. item.id] or { id = item.id, type = item.type })
    end
    return list
end

local function Attr(resource, name)
    return resource and resource.attributes and resource.attributes[name]
end

--- "12:34" or "1:02:03" from seconds (or FAF's "PT12M34S" / "12:34:56").
local function Duration(value)
    local seconds = tonumber(value)
    if not seconds and type(value) == 'string' then
        local _, _, h, m, s = string.find(value, '^(%d+):(%d+):(%d+)')
        if h then
            seconds = tonumber(h) * 3600 + tonumber(m) * 60 + tonumber(s)
        else
            local _, _, hh = string.find(value, '(%d+)H')
            local _, _, mm = string.find(value, '(%d+)M')
            local _, _, ss = string.find(value, '([%d%.]+)S')
            seconds = (tonumber(hh) or 0) * 3600 + (tonumber(mm) or 0) * 60 + math.floor(tonumber(ss) or 0)
        end
    end
    seconds = math.floor(seconds or 0)
    if seconds >= 3600 then
        return string.format('%d:%02d:%02d', math.floor(seconds / 3600), math.mod(math.floor(seconds / 60), 60),
            math.mod(seconds, 60))
    end
    return string.format('%d:%02d', math.floor(seconds / 60), math.mod(seconds, 60))
end

--- Plain text from FAF's descriptions (some carry HTML tags).
local function Plain(text)
    text = string.gsub(tostring(text or ''), '<br%s*/?>', ' ')
    text = string.gsub(text, '<[^>]->', '')
    text = string.gsub(text, '&amp;', '&')
    return (string.gsub(text, '%s+', ' '))
end

function Build(launcher, page)
    local view = { missions = nil, results = {}, jobs = {}, thumbJobs = {} }
    launcher.coopView = view

    local title = Theme.Title(page, 'Co-op', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 0)
    local subtitle = Theme.Text(page, 'The campaigns\' missions played together, with FAF\'s fastest completions.', 13,
        C.subtle)
    subtitle.Left:Set(function() return title.Right() + Scale(24) end)
    subtitle.Bottom:Set(function() return title.Bottom() - Scale(3) end)

    local body = Group(page)
    body.Left:Set(page.Left)
    body.Right:Set(page.Right)
    body.Top:Set(function() return title.Bottom() + Scale(22) end)
    body.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(body)

    -- The missions on the left.
    local listArea = Group(body)
    listArea.Left:Set(body.Left)
    listArea.Top:Set(body.Top)
    listArea.Bottom:Set(body.Bottom)
    listArea.Right:Set(function() return body.Left() + math.floor(body.Width() * 0.42) end)
    Theme.SizeFromEdges(listArea)
    view.list = Widgets.VirtualList(listArea, {
        { 'Mission', 0.46, function(item) return item.name end },
        { 'Campaign', 0.36, function(item) return item.campaign end, C.muted },
        { 'Faction', 0.18, function(item) return item.faction end, C.subtle },
    }, function(item, double)
        view:Choose(item)
        if double then
            view:Host()
        end
    end)
    -- Missions over the co-op games open now, in the left column.
    view.list.Left:Set(listArea.Left)
    view.list.Right:Set(listArea.Right)
    view.list.Top:Set(listArea.Top)
    view.list.Bottom:Set(function() return listArea.Top() + math.floor(listArea.Height() * 0.6) end)
    Theme.SizeFromEdges(view.list)
    view.listNote = Theme.Paragraph(listArea, 13, C.subtle)
    view.listNote.Left:Set(listArea.Left)
    view.listNote.Right:Set(listArea.Right)
    view.listNote.Top:Set(function() return listArea.Top() + Scale(40) end)
    view.loader = Theme.Loader(listArea)
    LayoutHelpers.AtCenterIn(view.loader, listArea)

    -- The chosen mission on the right.
    local detail = Theme.Panel(body, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Left:Set(function() return listArea.Right() + Scale(24) end)
    detail.Right:Set(body.Right)
    detail.Top:Set(body.Top)
    detail.Bottom:Set(body.Bottom)
    Theme.SizeFromEdges(detail)
    view.picture = Theme.Panel(detail, 'ff08121a', C.line)
    LayoutHelpers.SetDimensions(view.picture, 170, 170)
    LayoutHelpers.AtLeftTopIn(view.picture, detail, 24, 24)
    view.pictureMap = Bitmap(view.picture)
    view.pictureMap:DisableHitTest()
    LayoutHelpers.FillParentFixedBorder(view.pictureMap, view.picture, 1)
    view.pictureMap.Depth:Set(function() return view.picture.Depth() + 2 end)
    view.placeholder = Theme.Icon(view.picture, 'maps', 40, C.subtle, 1.5)
    LayoutHelpers.AtCenterIn(view.placeholder, view.picture)
    view.name = Theme.Title(detail, '', 18, C.text)
    view.name.Left:Set(function() return view.picture.Right() + Scale(20) end)
    view.name.Top:Set(function() return detail.Top() + Scale(28) end)
    view.facts = Theme.Text(detail, '', 13, C.muted)
    view.facts.Left:Set(view.name.Left)
    view.facts.Top:Set(function() return view.name.Bottom() + Scale(8) end)
    view.story = Theme.Paragraph(detail, 13, C.muted)
    view.story.Left:Set(view.name.Left)
    view.story.Right:Set(function() return detail.Right() - Scale(24) end)
    view.story.Top:Set(function() return view.facts.Bottom() + Scale(12) end)
    view.hostButton = Theme.Button(detail, 'Host this mission', function() view:Host() end, 'primary',
        { icon = 'plus', width = 240 })
    LayoutHelpers.AtRightIn(view.hostButton, detail, 24)
    LayoutHelpers.AtBottomIn(view.hostButton, detail, 22)
    view.status = Theme.Cell(detail, 13, C.muted)
    view.status.Left:Set(function() return detail.Left() + Scale(24) end)
    view.status.Right:Set(function() return view.hostButton.Left() - Scale(16) end)
    LayoutHelpers.AtVerticalCenterIn(view.status, view.hostButton)

    -- The fastest completions, and the co-op games open now.
    local timesCaption = Theme.Caption(detail, 'Fastest completions', C.accent)
    timesCaption.Left:Set(function() return detail.Left() + Scale(24) end)
    timesCaption.Top:Set(function() return math.max(view.picture.Bottom(), view.story.Bottom()) + Scale(22) end)
    view.times = Widgets.VirtualList(detail, {
        { 'Time', 0.2, function(item) return item.time end, C.gold },
        { 'Players', 0.56, function(item) return item.players end },
        { 'Secondary', 0.24, function(item) return item.secondary end, C.muted },
    }, function(item) end)
    view.times.Left:Set(timesCaption.Left)
    view.times.Right:Set(function() return detail.Right() - Scale(24) end)
    view.times.Top:Set(function() return timesCaption.Bottom() + Scale(8) end)
    view.times.Bottom:Set(function() return view.hostButton.Top() - Scale(16) end)
    Theme.SizeFromEdges(view.times)
    local gamesCaption = Theme.Caption(listArea, 'Co-op games open now  (double-click to join)', C.accent)
    gamesCaption.Left:Set(listArea.Left)
    gamesCaption.Top:Set(function() return view.list.Bottom() + Scale(18) end)
    view.games = Widgets.VirtualList(listArea, {
        { 'Game', 0.4, function(item) return item.title end },
        { 'Mission', 0.4, function(item) return item.mapname end, C.muted },
        { 'Players', 0.2, function(item) return item.numPlayers .. ' / ' .. item.maxPlayers end, C.subtle },
    }, function(item, double)
        if double and item.game then
            launcher:Join(item.game)
        end
    end)
    view.games.Left:Set(listArea.Left)
    view.games.Right:Set(listArea.Right)
    view.games.Top:Set(function() return gamesCaption.Bottom() + Scale(8) end)
    view.games.Bottom:Set(listArea.Bottom)
    Theme.SizeFromEdges(view.games)

    ----------------------------------------------------------------------------------------------------------------

    local function Ask(key, path, query, done)
        if not rawget(_G, 'FafLibrary_Api') then
            view.failure = 'This build has no FAF API access.'
            return
        end
        local id, why = FafLibrary_Api(path, query)
        if not id then
            view.failure = tostring(why)
            return
        end
        view.jobs[key] = { id = id, done = done }
    end

    function view:Load()
        self.loading = true
        Ask('missions', '/data/coopScenario', { include = 'maps', sort = 'order', ['page[size]'] = '1000' }, function(doc)
            local store = Store(doc)
            local missions = {}
            for _, scenario in (doc.data or {}) do
                local faction = kFactionNames[string.lower(tostring(Attr(scenario, 'faction') or ''))] or ''
                for _, mission in (Rel(store, scenario, 'maps') or {}) do
                    if mission.attributes then
                        table.insert(missions, {
                            key = mission.id, id = mission.id, name = Attr(mission, 'name') or '?',
                            campaign = Attr(scenario, 'name') or '', faction = faction,
                            scenarioOrder = Attr(scenario, 'order') or 0, order = Attr(mission, 'order') or 0,
                            story = Plain(Attr(mission, 'description')),
                            folder = Attr(mission, 'mapFolderName') or Attr(mission, 'folderName') or '',
                            thumbnail = Attr(mission, 'thumbnailUrlLarge') or Attr(mission, 'thumbnailUrlSmall'),
                            version = Attr(mission, 'version'),
                        })
                    end
                end
            end
            table.sort(missions, function(a, b)
                if a.scenarioOrder ~= b.scenarioOrder then
                    return a.scenarioOrder < b.scenarioOrder
                end
                return a.order < b.order
            end)
            view.missions = missions
            if not view.chosen and missions[1] then
                view:Choose(missions[1])
            end
        end)
    end

    function view:Choose(mission)
        self.chosen = mission
        self.list.selectedKey = mission.key
        if not self.results[mission.id] and not self.jobs['results' .. mission.id] then
            local id = mission.id
            Ask('results' .. id, '/data/coopResult', { filter = 'mission==' .. id, sort = 'duration',
                ['page[size]'] = '20', include = 'game.playerStats.player' }, function(doc)
                local store = Store(doc)
                local rows = {}
                for index, result in (doc.data or {}) do
                    local names = {}
                    local game = Rel(store, result, 'game')
                    for _, stats in (game and Rel(store, game, 'playerStats') or {}) do
                        local player = Rel(store, stats, 'player')
                        if player and Attr(player, 'login') then
                            table.insert(names, Attr(player, 'login'))
                        end
                    end
                    table.insert(rows, { key = result.id, time = Duration(Attr(result, 'duration')),
                        players = table.getn(names) > 0 and table.concat(names, ', ') or
                            (tostring(Attr(result, 'playerCount') or '?') .. ' players'),
                        secondary = Attr(result, 'secondaryObjectives') and 'all' or '' })
                end
                view.results[id] = rows
            end)
        end
        self:Paint()
    end

    function view:Host()
        local mission = self.chosen
        if not mission or mission.folder == '' then
            return
        end
        local ok, why = launcher:HostRequest({ title = mission.name, map = mission.folder, mod = 'coop',
            visibility = 'public' })
        self.statusText = ok and ('Hosting ' .. mission.name .. '...') or tostring(why)
        self.statusColor = ok and C.accent or C.bad
        LOG('LAUNCHER: co-op: host ' .. mission.name .. ' (' .. mission.folder .. '): ' .. tostring(ok))
        self:Paint()
    end

    function view:Poll()
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if not state or state.state ~= 'working' then
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: co-op: reading ' .. key .. ' failed: ' .. tostring(err))
                    end
                else
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                end
                self.loading = false
                break -- a finished job may start another; the next refresh takes the rest
            end
        end
    end

    function view:Paint()
        local mission = self.chosen
        Theme.SetVisible(self.loader, self.missions == nil and not self.failure)
        local note = ''
        if self.failure and not self.missions then
            note = 'The missions didn\'t load: ' .. self.failure
        elseif self.missions and table.getn(self.missions) == 0 then
            note = 'FAF lists no co-op missions.'
        end
        self.listNote:SetText(note, self.failure and C.bad or C.subtle)
        if self.missions and self.list.items ~= self.missions then
            self.list:SetItems(self.missions)
        end
        self.list:Paint()
        Theme.SetText(self.name, mission and mission.name or '')
        Theme.SetText(self.facts, mission and ((mission.campaign ~= '' and mission.campaign or 'Co-op') ..
            (mission.faction ~= '' and ('  -  ' .. mission.faction) or '') .. (mission.version and ('  -  v' ..
            mission.version) or '')) or '')
        if self.storyFor ~= mission then
            self.storyFor = mission
            self.story:SetText(mission and mission.story or '', C.muted)
        end
        -- The mission's picture from FAF's content server: downloaded once, readable after the download is mounted.
        local picture = nil
        if mission and mission.thumbnail and rawget(_G, 'FafLibrary_Thumbnail') then
            local path, job = FafLibrary_Thumbnail(mission.thumbnail)
            picture = path
            if not path and job and job > 0 and not self.thumbJobs[job] then
                self.thumbJobs[job] = true
            elseif not path and job == 0 then
                self.mountWanted = true
            end
        end
        for job in self.thumbJobs do
            local state = FafLibrary_Job(job)
            if not state or state.state ~= 'working' then
                self.thumbJobs[job] = nil
                self.mountWanted = true
            end
        end
        if self.mountWanted and not next(self.thumbJobs) then
            self.mountWanted = false
            FafLibrary_MountThumbnails()
        end
        if picture and self.shownPicture ~= picture then
            self.shownPicture = picture
            self.pictureMap:SetTexture(picture)
        end
        Theme.SetVisible(self.pictureMap, picture ~= nil)
        Theme.SetVisible(self.placeholder, picture == nil)
        local results = mission and self.results[mission.id]
        self.times:SetItems(results or {})
        -- Co-op games FAF's lobby lists now.
        local games = {}
        for _, game in (rawget(_G, 'FafOnline_Games') and FafOnline_Games() or {}) do
            if game.featuredMod == 'coop' then
                table.insert(games, { key = game.uid, title = game.title, mapname = game.map or '',
                    numPlayers = type(game.players) == 'number' and game.players or 0, maxPlayers = game.maxPlayers or 0,
                    game = game })
            end
        end
        self.games:SetItems(games)
        local status = launcher.lastStatus or {}
        self.hostButton:SetEnabled(mission ~= nil and status.lobby == 'signedin')
        Theme.SetText(self.status, self.statusText or (status.lobby ~= 'signedin' and
            'Connect to FAF on Custom games to host or join.' or (results and (table.getn(results) ..
            ' completions on record') or 'Asking FAF for the fastest completions...')))
        Theme.SetColor(self.status, self.statusColor or C.muted)
    end

    function view:Refresh()
        if not self.missions and not self.loading and not self.failure then
            self:Load()
        end
        self:Poll()
        self:Paint()
    end

    return view
end
