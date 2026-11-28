-- A FAF player's profile in the launcher's look: who the player is (flag, clan, name, online or not), the ratings of
-- every leaderboard, the rating history of one as a chart, the maps of the latest games, previous names and the clan
-- with its members. Everything comes from FAF's API with the player's sign-in (FafLibrary_Api, run on the engine's
-- threads and asked after each frame); what FAF's lobby knows (country, online) comes from FafOnline_Player.
-- Open(launcher, login) shows it over the launcher; a name in it opens that player's profile instead.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale
local Kit = import('/fafengine/modules/lua/ui/launcher/kit.lua') -- the launcher's shared pieces (stat boxes, the chart)
local DateText, Thousands, Percent = Kit.DateText, Kit.Thousands, Kit.Percent
local Heading, FactRow, RatingCard, StatBox, Row, Chart = Kit.Heading, Kit.FactRow, Kit.RatingCard, Kit.StatBox, Kit.Row,
    Kit.Chart

local kMapGames = 100 -- the Maps tab counts this many of the player's latest games

local current = false -- the profile on screen

------------------------------------------------------------------------------------------------------------------------
-- FAF's API answers (JSON:API): resources by type and id, relationships followed through `included`.

local function Store(doc)
    local store = {}
    local function Add(resource)
        if type(resource) == 'table' and resource.type and resource.id then
            store[resource.type .. ':' .. resource.id] = resource
        end
    end
    local data = doc and doc.data
    if type(data) == 'table' and data.type then
        Add(data)
    elseif type(data) == 'table' then
        for _, resource in data do
            Add(resource)
        end
    end
    for _, resource in (doc and doc.included or {}) do
        Add(resource)
    end
    return store
end

--- The resource (or the list of them) a relationship points at; unknown ones as {id, type}.
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

local function List(doc)
    local data = doc and doc.data
    if type(data) ~= 'table' or data.type then
        return data and { data } or {}
    end
    return data
end

--- Seconds since 1970 from FAF's ISO time (for lengths and ages), or nil.
local function IsoSeconds(iso)
    local _, _, y, mo, d, h, mi, s = string.find(tostring(iso or ''), '^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)')
    if not y then
        return nil
    end
    y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
    -- Days from the civil date (Howard Hinnant's days_from_civil).
    if mo <= 2 then
        y = y - 1
    end
    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local mp = math.mod(mo + 9, 12)
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    return days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(s)
end

--- A leaderboard's name for people: global, 1v1, 2v2, 4v4 full share...
local function BoardName(technical)
    local names = {
        global = 'Global', ladder_1v1 = '1v1', tmm_2v2 = '2v2', tmm_4v4_full_share = '4v4 full share',
        tmm_4v4_share_until_death = '4v4',
    }
    if names[technical] then
        return names[technical]
    end
    local text = string.gsub(string.gsub(tostring(technical or ''), '^tmm_', ''), '_', ' ')
    return text
end

local function BoardOrder(technical)
    local order = { global = 1, ladder_1v1 = 2, tmm_2v2 = 3, tmm_4v4_share_until_death = 4, tmm_4v4_full_share = 5 }
    return order[technical] or 10
end

------------------------------------------------------------------------------------------------------------------------
-- The profile.

local Profile = {}

local function Ask(profile, key, path, query, onDone)
    if not rawget(_G, 'FafLibrary_Api') then
        profile.errors[key] = 'This build has no FAF API access.'
        return
    end
    local id, why = FafLibrary_Api(path, query)
    if not id then
        profile.errors[key] = why or 'FAF\'s API refused the request.'
        return
    end
    profile.jobs[key] = { id = id, onDone = onDone, generation = profile.generation }
end

--- Builds the profile over `launcher`'s screen.
local function Build(launcher)
    local frameW, frameH = Widgets.FrameUnits()
    local cover = Widgets.Modal(launcher.root, math.min(1200, frameW - 40), math.min(820, frameH - 40))
    cover.Depth:Set(function() return launcher.root.Depth() + 600 end)
    local panel = cover.panel
    local profile = { cover = cover, panel = panel, launcher = launcher, jobs = {}, errors = {}, generation = 0 }
    for name, fn in Profile do
        profile[name] = fn
    end

    -- Head: flag, [clan] name, YOU; online, country, global rating and games; another player; close.
    local head = Group(panel)
    head:DisableHitTest()
    LayoutHelpers.AtLeftTopIn(head, panel, 0, 0)
    head.Right:Set(panel.Right)
    LayoutHelpers.SetHeight(head, 92)
    profile.flag = Bitmap(head)
    profile.flag:DisableHitTest()
    -- The flag after the name, near the size FAF's flag pictures are drawn at (larger they blur).
    LayoutHelpers.SetDimensions(profile.flag, 24, 16)
    profile.clanTag = Theme.Text(head, '', 24, C.accent, true)
    profile.name = Theme.Text(head, '', 24, C.text, true)
    LayoutHelpers.AtTopIn(profile.clanTag, head, 18)
    LayoutHelpers.AtTopIn(profile.name, head, 18)
    profile.you = Theme.Tag(head, 'You', C.accent)
    profile.flag.Left:Set(function() return profile.name.Right() + Scale(12) end)
    profile.flag.Top:Set(function() return profile.name.Top() + Scale(9) end)
    profile.you.Left:Set(function() return profile.name.Right() + Scale(12) end)
    profile.you.Top:Set(function() return profile.name.Top() + Scale(8) end)
    profile.dot = Theme.Dot(head, 8, C.good)
    profile.dot.Left:Set(profile.clanTag.Left)
    LayoutHelpers.AtTopIn(profile.dot, head, 59)
    profile.facts = Theme.Text(head, '', 13, C.muted)
    profile.facts.Left:Set(function() return profile.dot.Right() + Scale(6) end)
    LayoutHelpers.AtVerticalCenterIn(profile.facts, profile.dot)

    local close = Theme.Button(head, '', function() profile:Close() end, 'secondary', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(close, head, 24, 26)
    profile.another = Theme.TextField(head, 280, 'View another player...', 'search', 40)
    -- TextField places itself at its parent's left: its Left is what moves it.
    profile.another.Left:Set(function() return close.Left() - Scale(12) - profile.another.Width() end)
    LayoutHelpers.AtTopIn(profile.another, head, 26)
    profile.another.edit.OnEnterPressed = function(self, text)
        if text and text ~= '' then
            profile:Load(text)
        end
        return true
    end
    local headLine = Theme.Rect(panel, C.line)
    headLine.Left:Set(panel.Left)
    headLine.Right:Set(panel.Right)
    headLine.Top:Set(head.Bottom)
    headLine.Height:Set(1)
    headLine.Width:Set(function() return headLine.Right() - headLine.Left() end)
    headLine:DisableHitTest()

    profile.tabs = Widgets.Tabs(panel, {
        { 'overview', 'Overview' }, { 'history', 'Rating history' }, { 'maps', 'Maps' }, { 'stats', 'Statistics' },
        { 'names', 'Previous names' }, { 'clan', 'Clan' },
    }, function(key) profile:ShowTab(key) end)
    profile.tabs.Left:Set(function() return panel.Left() + Scale(28) end)
    profile.tabs.Right:Set(function() return panel.Right() - Scale(28) end)
    profile.tabs.Top:Set(function() return head.Bottom() + Scale(6) end)

    local body = Group(panel)
    body.Left:Set(function() return panel.Left() + Scale(28) end)
    body.Right:Set(function() return panel.Right() - Scale(28) end)
    body.Top:Set(function() return profile.tabs.Bottom() + Scale(20) end)
    body.Bottom:Set(function() return panel.Bottom() - Scale(24) end)
    Theme.SizeFromEdges(body)
    profile.body = body

    -- What is still on its way, or why it failed.
    profile.loader = Theme.Loader(panel)
    LayoutHelpers.AtCenterIn(profile.loader, body)
    profile.message = Theme.Paragraph(panel, 13, C.subtle)
    profile.message.centered = true
    profile.message.Left:Set(function() return body.Left() + Scale(60) end)
    profile.message.Right:Set(function() return body.Right() - Scale(60) end)
    profile.message.Top:Set(function() return body.Top() + Scale(120) end)

    profile.pages = {}
    profile:BuildOverview(body)
    profile:BuildHistory(body)
    profile:BuildMaps(body)
    profile:BuildStats(body)
    profile:BuildNames(body)
    profile:BuildClan(body)

    -- Answers are asked after on every frame while the profile is open.
    cover:SetNeedsFrameUpdate(true)
    cover.OnFrame = function(self, delta)
        profile:Poll()
        profile:PollThumbnails()
    end
    cover.OnDestroy = function(self)
        if current == profile then
            current = false
        end
    end
    profile.tab = 'overview'
    return profile
end

function Profile:Close()
    self.cover:Destroy()
    if current == self then
        current = false
    end
end

function Profile:Poll()
    -- An answer may ask for more (the player, then the ratings): finished requests leave the table before any of
    -- them is read, as a table can't grow while it is walked.
    local finished = {}
    for key, job in self.jobs do
        local state = FafLibrary_Job(job.id)
        if not state or state.state ~= 'working' then
            table.insert(finished, { key = key, job = job, state = state })
        end
    end
    for _, entry in finished do
        local key, job, state = entry.key, entry.job, entry.state
        self.jobs[key] = nil
        do
            if job.generation == self.generation then
                if state and state.state == 'done' then
                    local ok, err = pcall(job.onDone, state.data)
                    if not ok then
                        WARN('LAUNCHER: profile: reading ' .. key .. ' failed: ' .. tostring(err))
                        self.errors[key] = 'Reading FAF\'s answer failed.'
                    end
                else
                    self.errors[key] = (state and state.message ~= '' and state.message) or
                        'FAF\'s API didn\'t answer.'
                    LOG('LAUNCHER: profile: ' .. key .. ': ' .. tostring(self.errors[key]))
                end
                self:Paint()
            end
        end
    end
end

--- Shows `login`'s profile: everything is asked again.
function Profile:Load(login)
    self.generation = self.generation + 1
    self.jobs = {}
    self.errors = {}
    self.login = login
    self.player = nil
    self.boards = nil
    self.history = {}
    self.historyBoard = nil
    self.maps = nil
    self.names = nil
    self.clan = nil
    self.members = nil
    self.events = nil
    self.tab = 'overview'
    LOG('LAUNCHER: profile of ' .. tostring(login))
    self:AskPlayer('login=="' .. login .. '"', true)
    self:Paint()
end

function Profile:AskPlayer(filter, firstTry)
    Ask(self, 'player', '/data/player', {
        filter = filter,
        include = 'names,clanMembership.clan',
        ['page[size]'] = '1',
    }, function(doc)
        local store = Store(doc)
        local player = List(doc)[1]
        if not player then
            if firstTry then
                -- Perhaps a name the player used before.
                self:AskPlayer('names.name=="' .. self.login .. '"', false)
            else
                self.errors.player = 'FAF has no player called ' .. self.login .. '.'
            end
            return
        end
        self.player = {
            id = player.id,
            login = Attr(player, 'login') or self.login,
            country = Attr(player, 'country'), -- FAF's API has it for everyone; the lobby only for who is online
            created = Attr(player, 'createTime'),
            updated = Attr(player, 'updateTime'),
        }
        local names = {}
        for _, record in (Rel(store, player, 'names') or {}) do
            table.insert(names, { key = record.id, name = Attr(record, 'name') or '?', changed = Attr(record, 'changeTime') })
        end
        table.sort(names, function(a, b) return tostring(a.changed or '') > tostring(b.changed or '') end)
        self.names = names
        local membership = Rel(store, player, 'clanMembership')
        local clan = membership and Rel(store, membership, 'clan')
        if clan and Attr(clan, 'tag') then
            local leader = Rel(store, clan, 'leader')
            local founder = Rel(store, clan, 'founder')
            self.clan = {
                id = clan.id, tag = Attr(clan, 'tag'), name = Attr(clan, 'name') or '',
                created = Attr(clan, 'createTime'), joined = Attr(membership, 'createTime'),
                description = Attr(clan, 'description') or '', leaderId = leader and leader.id,
                founderId = founder and founder.id,
            }
        else
            self.clan = false
        end
        self:AskBoards()
    end)
end

function Profile:AskBoards()
    Ask(self, 'boards', '/data/leaderboardRating', {
        filter = 'player.id==' .. self.player.id,
        include = 'leaderboard',
        ['page[size]'] = '50',
    }, function(doc)
        local store = Store(doc)
        local boards = {}
        for _, rating in List(doc) do
            local board = Rel(store, rating, 'leaderboard')
            local technical = Attr(board, 'technicalName') or ('leaderboard ' .. tostring(board and board.id))
            local mean = Attr(rating, 'mean') or 0
            local deviation = Attr(rating, 'deviation') or 0
            table.insert(boards, {
                id = board and board.id, technical = technical, name = BoardName(technical),
                rating = math.floor(Attr(rating, 'rating') or (mean - 3 * deviation)), mean = mean,
                deviation = deviation, games = Attr(rating, 'totalGames') or 0, wins = Attr(rating, 'wonGames') or 0,
            })
        end
        table.sort(boards, function(a, b)
            if BoardOrder(a.technical) ~= BoardOrder(b.technical) then
                return BoardOrder(a.technical) < BoardOrder(b.technical)
            end
            return a.games > b.games
        end)
        self.boards = boards
    end)
end

function Profile:AskHistory(board)
    self.historyBoard = board
    if self.history[board.id] or self.jobs['history' .. board.id] then
        return
    end
    Ask(self, 'history' .. board.id, '/data/leaderboardRatingJournal', {
        filter = 'gamePlayerStats.player.id==' .. self.player.id .. ';leaderboard.id==' .. board.id ..
            ';gamePlayerStats.scoreTime=isnull=false',
        include = 'gamePlayerStats',
        sort = 'gamePlayerStats.scoreTime',
        ['page[size]'] = '10000',
    }, function(doc)
        local store = Store(doc)
        local points = {}
        for _, entry in List(doc) do
            local mean = Attr(entry, 'meanAfter')
            local deviation = Attr(entry, 'deviationAfter')
            if mean and deviation then
                local stats = Rel(store, entry, 'gamePlayerStats')
                table.insert(points, {
                    rating = mean - 3 * deviation, mean = mean, deviation = deviation, when = Attr(stats, 'scoreTime'),
                    result = Attr(stats, 'result'),
                })
            end
        end
        self.history[board.id] = points
    end)
end

function Profile:AskMaps()
    if self.maps or self.jobs.maps then
        return
    end
    Ask(self, 'maps', '/data/game', {
        filter = 'playerStats.player.id==' .. self.player.id .. ';endTime=isnull=false',
        include = 'mapVersion.map,playerStats',
        sort = '-startTime',
        ['page[size]'] = tostring(kMapGames),
    }, function(doc)
        local store = Store(doc)
        local byMap = {}
        local maps = {}
        local games = 0
        for _, game in List(doc) do
            games = games + 1
            local version = Rel(store, game, 'mapVersion')
            local map = version and Rel(store, version, 'map')
            local key = (map and map.id) or (version and version.id) or 'unknown'
            local entry = byMap[key]
            if not entry then
                local width = Attr(version, 'width')
                entry = {
                    key = key, name = Attr(map, 'displayName') or Attr(version, 'folderName') or 'Unknown map',
                    size = width and (math.floor(width / 51.2 + 0.5) .. ' km') or '', games = 0, wins = 0,
                    folder = Attr(version, 'folderName'), thumbnail = Attr(version, 'thumbnailUrlSmall'),
                    seconds = 0, timed = 0, last = '',
                }
                byMap[key] = entry
                table.insert(maps, entry)
            end
            entry.games = entry.games + 1
            for _, stats in (Rel(store, game, 'playerStats') or {}) do
                local who = Rel(store, stats, 'player')
                if who and who.id == self.player.id and Attr(stats, 'result') == 'VICTORY' then
                    entry.wins = entry.wins + 1
                end
            end
            local started, ended = IsoSeconds(Attr(game, 'startTime')), IsoSeconds(Attr(game, 'endTime'))
            if started and ended and ended > started then
                entry.seconds = entry.seconds + (ended - started)
                entry.timed = entry.timed + 1
            end
            if tostring(Attr(game, 'startTime') or '') > entry.last then
                entry.last = Attr(game, 'startTime')
            end
        end
        table.sort(maps, function(a, b)
            if a.games ~= b.games then
                return a.games > b.games
            end
            return a.name < b.name
        end)
        self.maps = maps
        self.mapGames = games
    end)
end

function Profile:AskClan()
    if not self.clan or self.members or self.jobs.clan then
        return
    end
    Ask(self, 'clan', '/data/clan/' .. self.clan.id, { include = 'memberships.player' }, function(doc)
        local store = Store(doc)
        local clan = List(doc)[1]
        local members = {}
        local ids = {}
        for _, membership in (Rel(store, clan, 'memberships') or {}) do
            local player = Rel(store, membership, 'player')
            if player then
                local role = (player.id == self.clan.leaderId and 'Leader') or
                    (player.id == self.clan.founderId and 'Founder') or 'Member'
                table.insert(members, {
                    key = player.id, id = player.id, login = Attr(player, 'login') or '?', role = role,
                    joined = Attr(membership, 'createTime'), rating = nil,
                })
                table.insert(ids, player.id)
            end
        end
        table.sort(members, function(a, b)
            local order = { Leader = 1, Founder = 2, Member = 3 }
            if order[a.role] ~= order[b.role] then
                return order[a.role] < order[b.role]
            end
            return string.lower(a.login) < string.lower(b.login)
        end)
        self.members = members
        if table.getn(ids) > 0 then
            Ask(self, 'clanRatings', '/data/leaderboardRating', {
                filter = 'leaderboard.technicalName==global;player.id=in=(' .. table.concat(ids, ',') .. ')',
                ['page[size]'] = '200',
            }, function(ratings)
                local store2 = Store(ratings)
                local byPlayer = {}
                for _, rating in List(ratings) do
                    local who = Rel(store2, rating, 'player')
                    if who then
                        byPlayer[who.id] = rating
                    end
                end
                for _, member in self.members or {} do
                    local rating = byPlayer[member.id]
                    if rating then
                        member.rating = math.floor(Attr(rating, 'rating') or 0)
                        member.games = Attr(rating, 'totalGames') or 0
                    end
                end
            end)
        end
    end)
end

function Profile:ShowTab(key)
    self.tab = key
    if self.player then
        if key == 'history' and not self.historyBoard and self.boards and self.boards[1] then
            self:AskHistory(self.boards[1])
        elseif key == 'maps' then
            self:AskMaps()
        elseif key == 'stats' then
            self:AskEvents()
        elseif key == 'clan' then
            self:AskClan()
        end
    end
    self:Paint()
end

------------------------------------------------------------------------------------------------------------------------
-- Statistics: FAF's player events (/data/playerEvent), the counts FAF keeps over all of a player's games. The event ids
-- are the FAF client's (EventService).

local kEvents = {
    customGames = 'cfa449a6-655b-48d5-9a27-6044804fe35c', ladderGames = '4a929def-e347-45b4-b26d-4325a3115859',
    lostAcus = 'd6a699b7-99bc-4a7f-b128-15e1e289a7b3', seconds = 'cc791f00-343c-48d4-b5b3-8900b83209c0',
    builtAir = '3ebb0c4d-5e92-4446-bf52-d17ba9c5cd3c', lostAir = '225e9b2e-ae09-4ae1-a198-eca8780b0fcd',
    builtLand = 'ea123d7f-bb2e-4a71-bd31-88859f0c3c00', lostLand = 'a1a3fd33-abe2-4e56-800a-b72f4c925825',
    builtNaval = 'b5265b42-1747-4ba1-936c-292202637ce6', lostNaval = '3a7b3667-0f79-4ac7-be63-ba841fd5ef05',
    builtT1 = 'a8ee4f40-1e30-447b-bc2c-b03065219795', lostT1 = '3dd3ed78-ce78-4006-81fd-10926738fbf3',
    builtT2 = '89d4f391-ed2d-4beb-a1ca-6b93db623c04', lostT2 = 'aebd750b-770b-4869-8e37-4d4cfdc480d0',
    builtT3 = '92617974-8c1f-494d-ab86-65c2a95d1486', lostT3 = '7f15c2be-80b7-4573-8f41-135f84773e0f',
    builtExp = 'ed9fd79d-5ec7-4243-9ccf-f18c4f5baef1', lostExp = '701ca426-0943-4931-85af-6a08d36d9aaa',
    builtEng = '60bb1fc0-601b-45cd-bd26-83b1a1ac979b', lostEng = 'e8e99a68-de1b-4676-860d-056ad2207119',
    aeonPlays = '96ccc66a-c5a0-4f48-acaa-888b00778b57', aeonWins = 'a6b51c26-64e6-4e7a-bda7-ea1cfe771ebb',
    cybranPlays = 'ad193982-e7ca-465c-80b0-5493f9739559', cybranWins = '56b06197-1890-42d0-8b59-25e1add8dc9a',
    uefPlays = '1b900d26-90d2-43d0-a64e-ed90b74c3704', uefWins = '7be6fdc5-7867-4467-98ce-f7244a66625a',
    seraphimPlays = 'fefcb392-848f-4836-9683-300b283bc308', seraphimWins = '15b6c19a-6084-4e82-ada9-6c30e282191f',
}
local kFactionRows = { { 'UEF', 'uef' }, { 'Aeon', 'aeon' }, { 'Cybran', 'cybran' }, { 'Seraphim', 'seraphim' } }
local kUnitRows = { { 'Land', 'Land' }, { 'Air', 'Air' }, { 'Naval', 'Naval' }, { 'Tech 1', 'T1' }, { 'Tech 2', 'T2' },
    { 'Tech 3', 'T3' }, { 'Experimentals', 'Exp' }, { 'Engineers', 'Eng' } }

--- A labelled bar inside `parent`: :Set(share 0..1, text, color, second share 0..1 drawn fainter behind it).
local function BarRow(parent)
    local row = Group(parent)
    row:DisableHitTest()
    LayoutHelpers.SetHeight(row, 30)
    row.label = Theme.Text(row, '', 13, C.text)
    LayoutHelpers.AtLeftIn(row.label, row, 0)
    LayoutHelpers.AtVerticalCenterIn(row.label, row)
    row.value = Theme.Text(row, '', 12, C.muted)
    row.value.Right:Set(row.Right)
    LayoutHelpers.AtVerticalCenterIn(row.value, row)
    row.track = Theme.Rect(row, C.line)
    row.track.Left:Set(function() return row.Left() + Scale(110) end)
    row.track.Right:Set(function() return row.Right() - Scale(190) end)
    row.track.Height:Set(Scale(8))
    row.track.Width:Set(function() return row.track.Right() - row.track.Left() end)
    LayoutHelpers.AtVerticalCenterIn(row.track, row)
    row.back = Theme.Rect(row, C.lineStrong)
    row.back.Left:Set(row.track.Left)
    row.back.Top:Set(row.track.Top)
    row.back.Height:Set(row.track.Height)
    row.fill = Theme.Rect(row, C.accent)
    row.fill.Left:Set(row.track.Left)
    row.fill.Top:Set(row.track.Top)
    row.fill.Height:Set(row.track.Height)
    row.Set = function(self, label, share, text, color, behind)
        Theme.SetText(self.label, label)
        Theme.SetText(self.value, text)
        local function Width(part)
            return function() return math.max(1, math.floor(self.track.Width() * math.max(0, math.min(1, part or 0)))) end
        end
        self.fill.Width:Set(Width(share))
        self.fill:SetSolidColor(color or C.accent)
        Theme.SetVisible(self.fill, (share or 0) > 0)
        self.back.Width:Set(Width(behind))
        Theme.SetVisible(self.back, (behind or 0) > 0)
    end
    return row
end

function Profile:BuildStats(body)
    local page = Group(body)
    LayoutHelpers.FillParent(page, body)
    page:DisableHitTest()
    self.pages.stats = page
    page.boxes = {}
    for i, caption in { 'Time played', 'Custom games', '1v1 games', 'ACUs lost' } do
        page.boxes[i] = StatBox(page, caption)
    end
    Row(page, page.boxes, 0, 14)
    -- Factions on the left, units on the right.
    local left = Group(page)
    left.Left:Set(page.Left)
    left.Right:Set(function() return page.Left() + math.floor(page.Width() / 2) - Scale(16) end)
    left.Top:Set(function() return page.boxes[1].Bottom() + Scale(26) end)
    left.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(left)
    left:DisableHitTest()
    local right = Group(page)
    right.Left:Set(function() return page.Left() + math.floor(page.Width() / 2) + Scale(16) end)
    right.Right:Set(page.Right)
    right.Top:Set(left.Top)
    right.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(right)
    right:DisableHitTest()
    page.factionHeading = Heading(page, 'Factions')
    page.factionHeading.Left:Set(left.Left)
    page.factionHeading.Top:Set(left.Top)
    page.unitHeading = Heading(page, 'Units built and lost')
    page.unitHeading.Left:Set(right.Left)
    page.unitHeading.Top:Set(right.Top)
    local function Rows(column, heading, count)
        local rows = {}
        for i = 1, count do
            local row = BarRow(column)
            row.Left:Set(column.Left)
            row.Right:Set(column.Right)
            row.Width:Set(function() return row.Right() - row.Left() end)
            local index = i - 1
            row.Top:Set(function() return heading.Bottom() + Scale(12 + index * 32) end)
            rows[i] = row
        end
        return rows
    end
    page.factions = Rows(left, page.factionHeading, table.getn(kFactionRows))
    page.units = Rows(right, page.unitHeading, table.getn(kUnitRows))
    page.legend = Theme.Text(page, 'Factions: wins in green over the games played.  Units: lost in orange over the units built.', 11, C.subtle)
    page.legend.Left:Set(left.Left)
    page.legend.Top:Set(function() return page.factions[table.getn(page.factions)].Bottom() + Scale(16) end)
    page.empty = Theme.Text(page, '', 13, C.subtle)
    page.empty.Left:Set(left.Left)
    page.empty.Top:Set(function() return page.legend.Bottom() + Scale(10) end)
end

function Profile:AskEvents()
    if self.events or self.jobs.events or not self.player then
        return
    end
    Ask(self, 'events', '/data/playerEvent', {
        filter = 'player.id==' .. self.player.id,
        include = 'event',
        ['page[size]'] = '200',
    }, function(doc)
        local counts = {}
        for _, item in List(doc) do
            local event = item.relationships and item.relationships.event and item.relationships.event.data
            if event and event.id then
                counts[event.id] = tonumber(Attr(item, 'currentCount')) or 0
            end
        end
        self.events = counts
    end)
end

function Profile:PaintStats(page)
    local events = self.events
    local function Count(name)
        return events and events[kEvents[name]] or 0
    end
    local hours = Count('seconds') / 3600
    page.boxes[1]:Set(events and (hours >= 10 and Thousands(hours) or string.format('%.1f', hours)) .. ' h' or nil, nil,
        events and (Thousands(Count('customGames') + Count('ladderGames')) .. ' games') or nil)
    page.boxes[2]:Set(events and Thousands(Count('customGames')) or nil)
    page.boxes[3]:Set(events and Thousands(Count('ladderGames')) or nil)
    page.boxes[4]:Set(events and Thousands(Count('lostAcus')) or nil, C.bad)
    local most = 1
    for _, faction in kFactionRows do
        most = math.max(most, Count(faction[2] .. 'Plays'))
    end
    for i, faction in kFactionRows do
        local plays, wins = Count(faction[2] .. 'Plays'), Count(faction[2] .. 'Wins')
        page.factions[i]:Set(faction[1], wins / most, Thousands(plays) .. ' games  -  ' .. Percent(wins, plays) .. ' won',
            C.good, plays / most)
    end
    local biggest = 1
    for _, kind in kUnitRows do
        biggest = math.max(biggest, Count('built' .. kind[2]), Count('lost' .. kind[2]))
    end
    for i, kind in kUnitRows do
        local built, lost = Count('built' .. kind[2]), Count('lost' .. kind[2])
        page.units[i]:Set(kind[1], lost / biggest, Thousands(built) .. ' built  -  ' .. Thousands(lost) .. ' lost',
            C.warn, built / biggest)
    end
    Theme.SetText(page.empty, events and next(events) == nil and 'FAF has no statistics for this player yet.' or
        (not events and 'Asking FAF for the statistics...' or ''))
end

------------------------------------------------------------------------------------------------------------------------
-- The tabs' pages.

function Profile:BuildOverview(body)
    local page = Group(body)
    LayoutHelpers.FillParent(page, body)
    page:DisableHitTest()
    self.pages.overview = page
    local ratings = Heading(page, 'Ratings')
    LayoutHelpers.AtLeftTopIn(ratings, page, 0, 0)
    ratings.note:SetText('Every leaderboard this player has played')
    page.cards = {}
    page.cardArea = Group(page)
    page.cardArea:DisableHitTest()
    page.cardArea.Left:Set(page.Left)
    page.cardArea.Right:Set(page.Right)
    page.cardArea.Top:Set(function() return ratings.Bottom() + Scale(12) end)
    LayoutHelpers.SetHeight(page.cardArea, 212)
    page.noRatings = Theme.Text(page, '', 13, C.subtle)
    LayoutHelpers.AtLeftIn(page.noRatings, page, 0)
    page.noRatings.Top:Set(function() return page.cardArea.Top() + Scale(10) end)

    -- Account facts on the left, previous names and clan in short on the right.
    local account = Heading(page, 'Account')
    account.Left:Set(page.Left)
    account.Top:Set(function() return page.cardArea.Bottom() + Scale(26) end)
    local box = Theme.Panel(page, 'ff08121a', C.line)
    box.Left:Set(page.Left)
    box.Right:Set(function() return page.Left() + math.floor(page.Width() / 2) - Scale(12) end)
    box.Top:Set(function() return account.Bottom() + Scale(12) end)
    LayoutHelpers.SetHeight(box, 192)
    page.facts = {}
    for i, label in { 'Player ID', 'Registered', 'Account changed', 'Clan', 'Joined clan', 'In FAF\'s lobby now' } do
        page.facts[i] = FactRow(box, label, 6 + (i - 1) * 30)
    end

    local about = Heading(page, 'Names and clan')
    about.Left:Set(function() return page.Left() + math.floor(page.Width() / 2) + Scale(12) end)
    about.Top:Set(account.Top)
    local aboutBox = Theme.Panel(page, 'ff08121a', C.line)
    aboutBox.Left:Set(about.Left)
    aboutBox.Right:Set(page.Right)
    aboutBox.Top:Set(box.Top)
    aboutBox.Height:Set(box.Height)
    page.about = Theme.Paragraph(aboutBox, 13, C.muted)
    page.about.Left:Set(function() return aboutBox.Left() + Scale(16) end)
    page.about.Right:Set(function() return aboutBox.Right() - Scale(16) end)
    page.about.Top:Set(function() return aboutBox.Top() + Scale(14) end)
end

function Profile:BuildHistory(body)
    local page = Group(body)
    LayoutHelpers.FillParent(page, body)
    page:DisableHitTest()
    self.pages.history = page
    page.choices = {}
    page.stats = {}
    for i, caption in { 'Current', 'Peak', 'Lowest', 'Games', 'Win rate', 'Last 30 games' } do
        page.stats[i] = StatBox(page, caption)
    end
    page.statArea = Group(page)
    page.statArea:DisableHitTest()
    page.statArea.Left:Set(page.Left)
    page.statArea.Right:Set(page.Right)
    page.statArea.Top:Set(function() return page.Top() + Scale(48) end)
    LayoutHelpers.SetHeight(page.statArea, 84)
    Row(page.statArea, page.stats, 0, 12)
    page.chart = Chart(page)
    page.chart.Left:Set(page.Left)
    page.chart.Right:Set(page.Right)
    page.chart.Top:Set(function() return page.statArea.Bottom() + Scale(16) end)
    page.chart.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(page.chart)
end

function Profile:BuildMaps(body)
    local page = Group(body)
    LayoutHelpers.FillParent(page, body)
    self.pages.maps = page
    page.heading = Heading(page, 'Maps')
    LayoutHelpers.AtLeftTopIn(page.heading, page, 0, 0)
    page.top = 1

    -- The columns: {title, share of the width, right-aligned}.
    local columns = {
        { 'Map', 0.34 }, { 'Games', 0.1, true }, { 'Wins', 0.1, true }, { 'Win rate', 0.18, true },
        { 'Avg length', 0.13, true }, { 'Last played', 0.15, true },
    }
    local function Edges(index)
        local share = 0
        for i = 1, index - 1 do
            share = share + columns[i][2]
        end
        local width = columns[index][2]
        return function() return page.Left() + math.floor(share * page.Width()) + Scale(16) end,
            function() return page.Left() + math.floor((share + width) * page.Width()) - Scale(16) end
    end
    local header = Theme.Panel(page, 'ff08121a', C.line)
    header.Left:Set(page.Left)
    header.Right:Set(page.Right)
    header.Top:Set(function() return page.heading.Bottom() + Scale(14) end)
    LayoutHelpers.SetHeight(header, 34)
    for index, column in columns do
        local left, right = Edges(index)
        local title = Theme.Text(header, string.upper(column[1]), 11, C.muted, true)
        if column[3] then
            title.Right:Set(right)
        else
            title.Left:Set(left)
        end
        LayoutHelpers.AtVerticalCenterIn(title, header)
    end
    page.rowsTop = function() return header.Bottom() end

    -- Rows: as many as fit; the wheel moves through the maps.
    local kRow = 64
    page.rows = {}
    local function Visible()
        return math.max(1, math.floor((page.Bottom() - header.Bottom()) / Scale(kRow)))
    end
    page.Visible = Visible
    for i = 1, 14 do
        local offset = (i - 1) * kRow
        local row = Group(page)
        row:DisableHitTest()
        row.Left:Set(page.Left)
        row.Right:Set(page.Right)
        row.Top:Set(function() return header.Bottom() + Scale(offset) end)
        LayoutHelpers.SetHeight(row, kRow)
        local line = Theme.Rect(row, C.line)
        line.Left:Set(row.Left)
        line.Right:Set(row.Right)
        line.Bottom:Set(row.Bottom)
        line.Height:Set(1)
        line.Width:Set(function() return line.Right() - line.Left() end)
        line:DisableHitTest()
        -- The map's picture: its own preview when it is on this computer, FAF's thumbnail otherwise.
        row.frame = Theme.Panel(row, 'ff08121a', C.line)
        LayoutHelpers.SetDimensions(row.frame, 48, 48)
        LayoutHelpers.AtLeftIn(row.frame, row, 14)
        LayoutHelpers.AtVerticalCenterIn(row.frame, row)
        Widgets.MapPicture(row.frame)
        row.thumb = Bitmap(row.frame)
        row.thumb:DisableHitTest()
        LayoutHelpers.FillParentFixedBorder(row.thumb, row.frame, 1)
        row.thumb.Depth:Set(function() return row.frame.Depth() + 3 end)
        row.name = Theme.Cell(row, 14, C.text)
        row.name.Left:Set(function() return row.frame.Right() + Scale(14) end)
        row.name.Right:Set(function() return page.Left() + math.floor(0.34 * page.Width()) - Scale(16) end)
        row.name.Top:Set(function() return row.Top() + Scale(14) end)
        row.size = Theme.Text(row, '', 12, C.subtle)
        row.size.Left:Set(row.name.Left)
        row.size.Top:Set(function() return row.Top() + Scale(35) end)
        row.cells = {}
        for index = 2, table.getn(columns) do
            local _, right = Edges(index)
            local cell = Theme.Text(row, '', 13, C.text)
            cell.Right:Set(right)
            LayoutHelpers.AtVerticalCenterIn(cell, row)
            row.cells[index] = cell
        end
        -- The win rate's bar, left of its number.
        row.track = Theme.Rect(row, C.line)
        LayoutHelpers.SetDimensions(row.track, 80, 4)
        row.track.Right:Set(function() return row.cells[4].Left() - Scale(10) end)
        LayoutHelpers.AtVerticalCenterIn(row.track, row)
        row.track:DisableHitTest()
        row.fill = Theme.Rect(row, C.accent)
        row.fill.Left:Set(row.track.Left)
        row.fill.Top:Set(row.track.Top)
        row.fill.Height:Set(row.track.Height)
        row.fill:DisableHitTest()
        page.rows[i] = row
    end
    page.empty = Theme.Text(page, '', 13, C.subtle)
    LayoutHelpers.AtLeftIn(page.empty, page, 0)
    page.empty.Top:Set(function() return header.Bottom() + Scale(16) end)
    local area = Theme.HitArea(page, function(self, event)
        if event.Type == 'WheelRotation' and self.profile and self.profile.maps then
            local count = table.getn(self.profile.maps)
            page.top = math.max(1, math.min(page.top + (event.WheelRotation > 0 and -2 or 2),
                count - Visible() + 1))
            self.profile:PaintMaps(page)
            return true
        end
        return false
    end)
    area.profile = self
end

function Profile:BuildNames(body)
    local page = Group(body)
    LayoutHelpers.FillParent(page, body)
    self.pages.names = page
    page.heading = Heading(page, 'Previous names')
    LayoutHelpers.AtLeftTopIn(page.heading, page, 0, 0)
    page.list = Widgets.VirtualList(page, {
        { 'Name', 0.5, function(item) return item.name end },
        { 'Used until', 0.5, function(item) return DateText(item.changed) end, C.muted },
    }, function(item, double) end)
    page.list.Left:Set(page.Left)
    page.list.Right:Set(page.Right)
    page.list.Top:Set(function() return page.heading.Bottom() + Scale(14) end)
    page.list.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(page.list)
end

function Profile:BuildClan(body)
    local page = Group(body)
    LayoutHelpers.FillParent(page, body)
    self.pages.clan = page
    local heading = Heading(page, 'Clan')
    LayoutHelpers.AtLeftTopIn(heading, page, 0, 0)
    local box = Theme.Panel(page, 'ff08121a', C.line)
    box.Left:Set(page.Left)
    box.Right:Set(page.Right)
    box.Top:Set(function() return heading.Bottom() + Scale(12) end)
    LayoutHelpers.SetHeight(box, 96)
    page.tag = Theme.Text(box, '', 22, C.accent, true)
    LayoutHelpers.AtLeftTopIn(page.tag, box, 20, 18)
    page.name = Theme.Text(box, '', 22, C.text, true)
    page.name.Left:Set(function() return page.tag.Right() + Scale(10) end)
    page.name.Top:Set(page.tag.Top)
    page.since = Theme.Text(box, '', 13, C.muted)
    LayoutHelpers.AtLeftTopIn(page.since, box, 20, 56)
    page.count = Theme.Text(box, '', 26, C.text, true)
    LayoutHelpers.AtRightTopIn(page.count, box, 24, 16)
    local countCaption = Theme.Text(box, 'MEMBERS', 10, C.muted, true)
    countCaption.Right:Set(page.count.Right)
    countCaption.Top:Set(function() return page.count.Bottom() + Scale(4) end)
    page.members = Heading(page, 'Members')
    page.members.Left:Set(page.Left)
    page.members.Top:Set(function() return box.Bottom() + Scale(22) end)
    page.members.note:SetText('click a member to see their profile')
    page.list = Widgets.VirtualList(page, {
        { 'Player', 0.34, function(item) return { login = item.login } end, kind = 'player' },
        { 'Role', 0.16, function(item) return item.role end, C.muted },
        { 'Status', 0.14, function(item)
            return (Widgets.PlayerFacts(item.login).id ~= nil) and 'online' or 'offline'
        end, C.muted },
        { 'Joined', 0.16, function(item) return DateText(item.joined) end, C.muted },
        { 'Global rating', 0.2, function(item) return item.rating and tostring(item.rating) or '-' end, C.gold },
    }, function(item, double)
        if item and item.login then
            self:Load(item.login)
        end
    end)
    page.list.Left:Set(page.Left)
    page.list.Right:Set(page.Right)
    page.list.Top:Set(function() return page.members.Bottom() + Scale(14) end)
    page.list.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(page.list)
    page.none = Theme.Text(page, '', 13, C.subtle)
    LayoutHelpers.AtLeftIn(page.none, page, 0)
    page.none.Top:Set(function() return heading.Bottom() + Scale(14) end)
end

------------------------------------------------------------------------------------------------------------------------
-- Painting.

function Profile:PaintHead()
    local facts = Widgets.PlayerFacts(self.player and self.player.login or self.login)
    local country = (self.player and self.player.country and self.player.country ~= '' and self.player.country) or
        facts.country
    local flag = Widgets.FlagPath(country)
    if flag then
        self.flag:SetTexture(flag)
        LayoutHelpers.SetDimensions(self.flag, 24, 16)
    end
    Theme.SetVisible(self.flag, flag ~= nil)
    -- YOU after the flag when there is one (set here: a hidden flag doesn't move what is laid out after it).
    self.you.Left:Set(function() return (flag and self.flag.Right() or self.name.Right()) + Scale(12) end)
    self.clanTag.Left:Set(function() return self.panel.Left() + Scale(28) end)
    local tag = (self.clan and self.clan.tag) or facts.clan or ''
    Theme.SetText(self.clanTag, tag ~= '' and ('[' .. tag .. ']') or '')
    self.name.Left:Set(function() return self.clanTag.Right() + Scale(tag ~= '' and 8 or 0) end)
    Theme.SetText(self.name, self.player and self.player.login or self.login or '')
    local status = self.launcher.lastStatus or {}
    local own = status.login and self.login and string.lower(status.login) == string.lower(self.player and
        self.player.login or self.login)
    Theme.SetVisible(self.you, own and true or false)
    local online = facts.id ~= nil
    self.dot:SetDotColor(online and C.good or C.subtle)
    local parts = { online and 'Online' or 'Not in FAF\'s lobby' }
    if country and country ~= '' then
        table.insert(parts, string.upper(country))
    end
    local global = self.boards and self.boards[1] and self.boards[1].technical == 'global' and self.boards[1]
    if global then
        table.insert(parts, global.rating .. ' global')
    end
    local games = 0
    for _, board in (self.boards or {}) do
        if board.technical == 'global' or board.technical == 'ladder_1v1' or string.find(board.technical, '^tmm') then
            games = games + board.games
        end
    end
    if self.boards then
        table.insert(parts, Thousands(games) .. ' rated games')
    end
    Theme.SetText(self.facts, table.concat(parts, '  -  '))
end

function Profile:PaintOverview(page)
    local boards = self.boards or {}
    local shown = math.min(table.getn(boards), 6)
    for i = 1, shown do
        local card = page.cards[i]
        if not card then
            card = RatingCard(page.cardArea, function(board)
                self:AskHistory(board)
                self:ShowTab('history')
            end)
            page.cards[i] = card
        end
        card:Set(boards[i])
        Theme.SetVisible(card, true)
    end
    for i = shown + 1, table.getn(page.cards) do
        Theme.SetVisible(page.cards[i], false)
    end
    local visible = {}
    for i = 1, shown do
        visible[i] = page.cards[i]
    end
    if shown > 0 then
        -- At most six cards a row; fewer stay card-sized instead of stretching across.
        local area = page.cardArea
        for i, card in visible do
            local index = i - 1
            card.Left:Set(function()
                local width = math.min(Scale(220), (area.Width() - Scale(12) * 5) / 6)
                return area.Left() + math.floor(index * (width + Scale(12)))
            end)
            card.Width:Set(function() return math.floor(math.min(Scale(220), (area.Width() - Scale(12) * 5) / 6)) end)
            card.Top:Set(area.Top)
        end
    end
    Theme.SetText(page.noRatings, self.boards and shown == 0 and 'No rated games yet.' or '')

    local player = self.player or {}
    local facts = Widgets.PlayerFacts(player.login or self.login)
    page.facts[1]:Set(player.id or '')
    page.facts[2]:Set(DateText(player.created))
    page.facts[3]:Set(DateText(player.updated))
    if self.clan then
        page.facts[4]:Set('[' .. self.clan.tag .. '] ' .. self.clan.name, C.accent)
        page.facts[5]:Set(DateText(self.clan.joined))
    else
        page.facts[4]:Set(self.clan == false and 'None' or '')
        page.facts[5]:Set('')
    end
    page.facts[6]:Set(facts.id and 'Online now' or 'No', facts.id and C.good or C.muted)

    local lines = {}
    if self.names and table.getn(self.names) > 0 then
        local list = {}
        for i = 1, math.min(5, table.getn(self.names)) do
            table.insert(list, self.names[i].name)
        end
        table.insert(lines, 'Played before as ' .. table.concat(list, ', ') ..
            (table.getn(self.names) > 5 and (' and ' .. (table.getn(self.names) - 5) .. ' more.') or '.'))
    elseif self.names then
        table.insert(lines, 'No previous names.')
    end
    if self.clan and self.clan.description ~= '' then
        table.insert(lines, '[' .. self.clan.tag .. '] ' .. self.clan.description)
    end
    page.about:SetText(table.concat(lines, '  '))
end

function Profile:PaintHistory(page)
    local boards = self.boards or {}
    for i, board in boards do
        local choice = page.choices[i]
        if not choice then
            local index = i
            choice = Theme.Choice(page, '', 170, function()
                self:AskHistory(self.boards[index])
                self:Paint()
            end)
            LayoutHelpers.AtTopIn(choice, page, 0)
            local before = page.choices[i - 1]
            if before then
                choice.Left:Set(function() return before.Right() + Scale(10) end)
            else
                choice.Left:Set(page.Left)
            end
            page.choices[i] = choice
        end
        choice.selected = self.historyBoard and self.historyBoard.id == board.id or false
        Theme.SetVisible(choice, i <= 7)
        choice.label = board.name .. '  ' .. board.rating
        choice:Paint(false)
    end
    for i = table.getn(boards) + 1, table.getn(page.choices) do
        Theme.SetVisible(page.choices[i], false)
    end
    -- The choices' texts: Theme.Choice draws its label once, so each one keeps a text of its own.
    for i, choice in page.choices do
        if not choice.text then
            choice.text = Theme.Text(choice, '', 13, C.muted)
            LayoutHelpers.AtCenterIn(choice.text, choice)
        end
        Theme.SetText(choice.text, choice.label or '')
        Theme.SetColor(choice.text, choice.selected and C.accent or C.muted)
    end

    local board = self.historyBoard
    local points = board and self.history[board.id]
    local count = points and table.getn(points) or 0
    if board then
        page.stats[1]:Set(tostring(board.rating), C.gold, string.format('%d +/- %d', math.floor(board.mean + 0.5),
            math.floor(board.deviation + 0.5)))
        page.stats[4]:Set(Thousands(board.games))
        page.stats[5]:Set(Percent(board.wins, board.games))
    end
    if count > 0 then
        local peak, lowest = 1, 1
        for i, point in points do
            if point.rating > points[peak].rating then
                peak = i
            end
            if point.rating < points[lowest].rating then
                lowest = i
            end
        end
        local function When(index)
            local date = DateText(points[index].when)
            return 'game ' .. Thousands(index) .. (date ~= '' and ('  -  ' .. date) or '')
        end
        page.stats[2]:Set(tostring(math.floor(points[peak].rating)), nil, When(peak))
        page.stats[3]:Set(tostring(math.floor(points[lowest].rating)), nil, When(lowest))
        local from = points[math.max(1, count - 30)].rating
        local change = math.floor(points[count].rating - from + 0.5)
        page.stats[6]:Set((change > 0 and '+' or '') .. change, change > 0 and C.good or (change < 0 and C.bad or C.text))
    else
        for _, i in { 2, 3, 6 } do
            page.stats[i]:Set('-')
        end
    end
    if points and page.chart.drawnFor ~= points then
        page.chart.drawnFor = points
        page.chart:Draw(points, board.name .. '  -  ' .. Thousands(count) .. ' games')
    elseif not points and page.chart.drawnFor ~= false then
        page.chart.drawnFor = false
        page.chart:Draw({}, '')
    end
end

function Profile:PaintMaps(page)
    local maps = self.maps or {}
    page.heading.note:SetText(self.maps and string.format('%d maps in the last %d games', table.getn(maps),
        self.mapGames or 0) or '')
    Theme.SetText(page.empty, self.maps and table.getn(maps) == 0 and 'No finished games yet.' or '')
    local visible = page.Visible()
    page.top = math.max(1, math.min(page.top, table.getn(maps) - visible + 1))
    for i, row in page.rows do
        local map = (i <= visible) and maps[page.top + i - 1] or nil
        Theme.SetVisible(row, map ~= nil)
        if map then
            -- Its own preview when the map is on this computer; FAF's thumbnail over it otherwise.
            local installed = map.folder and Widgets.LocalScenario(map.folder)
            row.frame:SetMap(installed and map.folder or nil)
            local thumb = not installed and self:Thumbnail(map.thumbnail)
            if thumb then
                if row.thumbPath ~= thumb then
                    row.thumbPath = thumb
                    row.thumb:SetTexture(thumb)
                end
            end
            Theme.SetVisible(row.thumb, thumb and true or false)
            Theme.SetText(row.name, map.name)
            Theme.SetText(row.size, map.size)
            Theme.SetText(row.cells[2], tostring(map.games))
            Theme.SetText(row.cells[3], tostring(map.wins))
            Theme.SetText(row.cells[4], Percent(map.wins, map.games))
            Theme.SetText(row.cells[5], map.timed > 0 and (math.floor(map.seconds / map.timed / 60 + 0.5) .. ' min') or '-')
            Theme.SetText(row.cells[6], DateText(map.last))
            local rate = map.games > 0 and map.wins / map.games or 0
            local width = math.floor(80 * rate + 0.5)
            row.fill.Width:Set(Scale(math.max(1, width)))
            row.fill:SetSolidColor((rate >= 0.55 and C.good) or (rate < 0.45 and C.bad) or C.accent)
            Theme.SetVisible(row.fill, width > 0)
        end
    end
end

--- A thumbnail from FAF's content server as a path of the game's files, or nil while it is on its way (it is asked
--- for once; the profile mounts the new ones when the page's downloads are in and paints again).
function Profile:Thumbnail(url)
    if not url or url == '' or not rawget(_G, 'FafLibrary_Thumbnail') then
        return nil
    end
    self.thumbs = self.thumbs or {}
    local known = self.thumbs[url]
    if known ~= nil then
        return known or nil
    end
    local path, id = FafLibrary_Thumbnail(url)
    if path then
        self.thumbs[url] = path
        return path
    end
    self.thumbs[url] = false
    if id and id > 0 then
        self.thumbJobs = self.thumbJobs or {}
        self.thumbJobs[id] = url
    elseif id == 0 then
        self.thumbsWaiting = true -- on disk, not mounted yet
    end
    return nil
end

--- The thumbnails' downloads: once none is left, the new pictures are mounted and the page painted with them.
function Profile:PollThumbnails()
    local busy = false
    for id, url in (self.thumbJobs or {}) do
        local job = FafLibrary_Job(id)
        if job and job.state == 'working' then
            busy = true
        else
            self.thumbJobs[id] = nil
            if job and job.state == 'done' then
                self.thumbsWaiting = true
            else
                self.thumbFailed = self.thumbFailed or {}
                self.thumbFailed[url] = true -- not asked for again while this profile is open
                LOG('LAUNCHER: profile: thumbnail ' .. url .. ': ' .. tostring(job and job.message))
            end
        end
    end
    if not busy and self.thumbsWaiting then
        self.thumbsWaiting = false
        FafLibrary_MountThumbnails()
        -- Everything not shown yet is asked for again.
        for url, path in self.thumbs or {} do
            if not path and not (self.thumbFailed and self.thumbFailed[url]) then
                self.thumbs[url] = nil
            end
        end
        if self.tab == 'maps' then
            self:PaintMaps(self.pages.maps)
        end
    end
end

function Profile:PaintNames(page)
    if self.names and page.list.items ~= self.names then
        page.list:SetItems(self.names)
    end
    page.heading.note:SetText(self.names and (table.getn(self.names) == 0 and 'none' or
        (table.getn(self.names) .. ' names')) or '')
end

function Profile:PaintClan(page)
    local clan = self.clan
    Theme.SetText(page.none, clan == false and 'This player is in no clan.' or '')
    for _, control in { page.tag, page.name, page.since, page.count } do
        Theme.SetVisible(control, clan and true or false)
    end
    if not clan then
        return
    end
    Theme.SetText(page.tag, '[' .. clan.tag .. ']')
    Theme.SetText(page.name, clan.name)
    Theme.SetText(page.since, 'Founded ' .. DateText(clan.created) .. '  -  ' .. (self.player and self.player.login or '') ..
        ' joined ' .. DateText(clan.joined))
    Theme.SetText(page.count, self.members and tostring(table.getn(self.members)) or '')
    if self.members then
        page.list:SetItems(self.members)
    end
end

function Profile:Paint()
    self:PaintHead()
    self.tabs:Set(self.tab, { names = self.names and table.getn(self.names) or nil })
    for key, page in self.pages do
        local show = key == self.tab and self.player ~= nil
        -- A Show shows every piece under the page again: the page's paint below hides what it doesn't use.
        page.reshown = show and page:IsHidden()
        Theme.SetVisible(page, show)
        if page.reshown and page.list then
            page.list:Paint()
        end
        if page.reshown and page.chart then
            page.chart.drawnFor = nil
        end
    end
    local waiting = false
    local failed = nil
    for key, _ in self.jobs do
        waiting = true
    end
    for key, why in self.errors do
        failed = failed or why
    end
    if self.player then
        local page = self.pages[self.tab]
        if self.tab == 'overview' then
            self:PaintOverview(page)
        elseif self.tab == 'history' then
            self:PaintHistory(page)
        elseif self.tab == 'maps' then
            self:PaintMaps(page)
        elseif self.tab == 'stats' then
            self:PaintStats(page)
        elseif self.tab == 'names' then
            self:PaintNames(page)
        elseif self.tab == 'clan' then
            self:PaintClan(page)
        end
    end
    Theme.SetVisible(self.loader, waiting and not self.player)
    self.message:SetText(failed or '', C.bad)
end

------------------------------------------------------------------------------------------------------------------------

--- Shows `login`'s profile over the launcher (the one already open shows that player instead).
function Open(launcher, login)
    if not login or login == '' then
        return
    end
    if not current then
        current = Build(launcher)
    end
    current:Load(login)
    return current
end

--- The profile on screen (tests), or false.
function Current()
    return current
end
