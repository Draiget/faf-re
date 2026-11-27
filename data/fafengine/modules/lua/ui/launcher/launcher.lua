-- The in-game launcher: the screen the game opens on instead of FAF's main menu (main.lua's CreateUI, hooked in
-- /fafengine/lua/ui/menus/main.lua). Games online (FAF's and our servers') on its main page; skirmish, campaign,
-- LAN, replays, mods and options open FAF's own screens as FAF's main menu does (main.lua ButtonSkirmish ...
-- ButtonOptions) and come back here; FAF's own main menu is one button away.
--
-- Its look is its own (theme.lua): a command console inside the game. Every call into FAF's screens is protected: if
-- one fails to open, the launcher says which and stays. If the launcher itself fails to build, the hook shows FAF's
-- main menu instead.
--
-- The online part talks to the engine through the FafOnline_* functions (src/moho/app/OnlineLauncher.cpp), which
-- only client builds with the online library have. No sign-in data, join line or token ever reaches Lua.

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Group = import('/lua/maui/group.lua').Group
local Movie = import('/lua/maui/movie.lua').Movie
local Prefs = import('/lua/user/prefs.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local C = Theme.Colors
local Scale = Theme.Scale

-- The featured mods a host can pick, as the Rust client offers them (FAForeverRustClient, HostGameModal.tsx).
FeaturedMods = {
    { id = 'faf', name = 'FAF', short = 'FAF', text = 'Standard game balance' },
    { id = 'fafbeta', name = 'FAF Beta', short = 'Beta', text = 'Upcoming balance changes' },
    { id = 'fafdevelop', name = 'FAF Develop', short = 'Develop', text = 'Bleeding-edge development' },
    { id = 'nomads', name = 'Nomads', short = 'Nomads', text = 'Adds the 5th Nomads faction' },
}

local kRailWidth = 214
local kStatusHeight = 28
local kRefreshSeconds = 0.5

-- One launcher at a time; a new CreateUI replaces it.
local current = false
-- What a restart on another featured mod took up in this start ('host true', 'join'), for the test walk.
resumedThisStart = false
-- On FAF's main menu opened from the launcher: its button back to the launcher.
local fafMenuBack = false

--- Whether the game opens on the launcher: on, unless the player turned it off (options key fafre_launcher = false)
--- or the game started with /nolauncher.
function Wanted()
    if HasCommandLineArg('/nolauncher') then
        return false
    end
    return Prefs.GetOption('fafre_launcher') ~= false
end

--- What a failed build left on screen goes, so FAF's menu can take its place.
function Cleanup()
    if current and current.root then
        current.root:Destroy()
    end
    current = false
end

local function Online()
    return rawget(_G, 'FafOnline_Status') ~= nil
end

local function ModName(id)
    for _, mod in FeaturedMods do
        if mod.id == id then
            return mod.name
        end
    end
    return id or ''
end

-- Whether the game can play on a featured mod: the one loaded, or one whose game files are on this computer (the game
-- starts again on them). Kept 10 s per mod, as the list asks for every game on each refresh.
local modFilesCache = {}
local function ModFiles(id, status)
    if id == '' or id == status.loadedMod then
        return true
    end
    if not rawget(_G, 'FafOnline_FeaturedModFiles') then
        return false, 'this build can\'t switch featured mod'
    end
    local cached = modFilesCache[id]
    if not cached or GetSystemTimeSeconds() - cached.at > 10 then
        local ready, why = FafOnline_FeaturedModFiles(id)
        cached = { ready = ready, why = why, at = GetSystemTimeSeconds() }
        modFilesCache[id] = cached
    end
    return cached.ready, cached.why
end

local function ModShort(id)
    for _, mod in FeaturedMods do
        if mod.id == id then
            return mod.short
        end
    end
    return id or ''
end

local function RatingText(game)
    if not game.ratingMin and not game.ratingMax then
        return nil
    end
    local low = game.ratingMin and tostring(math.floor(game.ratingMin)) or 'any'
    local high = game.ratingMax and tostring(math.floor(game.ratingMax)) or 'any'
    return low .. ' - ' .. high
end

--- Team "1" is FA's "no team" (free for all); "2" is the lobby's Team 1.
local function TeamName(team)
    local number = tonumber(team) or 0
    if number <= 1 then
        return 'No team'
    end
    return 'Team ' .. (number - 1)
end

--- Each team's players with ratings, their sums and the game's average (nil without ratings).
local function TeamFigures(game)
    local teams = {}
    local sum, count = 0, 0
    for _, team in game.teams or {} do
        local entry = { team = team.team, players = team.players, total = 0, rated = 0 }
        for _, player in team.players do
            if player.rating then
                entry.total = entry.total + player.rating
                entry.rated = entry.rated + 1
                sum = sum + player.rating
                count = count + 1
            end
        end
        table.insert(teams, entry)
    end
    table.sort(teams, function(a, b) return (tonumber(a.team) or 0) < (tonumber(b.team) or 0) end)
    return teams, count > 0 and math.floor(sum / count + 0.5) or nil
end

--- Why this build can't play a game right now, or nil.
local function WhyNotJoinable(game, status)
    if game.source == 'server' then
        if game.joinable then
            return nil
        end
        return game.why ~= '' and game.why or 'This game can\'t be joined from here.'
    end
    if game.state ~= 'open' then
        return 'The game has started.'
    end
    if status.loadedMod == '' then
        return 'This game was not started on FAF\'s game files (/init init_faf.lua).'
    end
    if game.featuredMod ~= '' and game.featuredMod ~= status.loadedMod then
        local ready, why = ModFiles(game.featuredMod, status)
        if not ready then
            return 'It runs ' .. ModName(game.featuredMod) .. ': ' .. tostring(why) .. '.'
        end
    end
    if game.players >= game.maxPlayers and game.maxPlayers > 0 then
        return 'The game is full.'
    end
    return nil
end

-- The shared pieces (widgets.lua).
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local LocalScenario = Widgets.LocalScenario
local MapTitle = Widgets.MapTitle
local MapPicture = Widgets.MapPicture
local Modal = Widgets.Modal
local Message = Widgets.Message
local FrameUnits = Widgets.FrameUnits
local ScrollMark = Widgets.ScrollMark
local VirtualList = Widgets.VirtualList

-- ---------------------------------------------------------------------------------------------------------------
-- The games: tiles in a grid, or rows in a list, with controls only for what is on screen.

local function StatBlock(parent, caption)
    local block = Group(parent)
    block:DisableHitTest()
    block.value = Theme.Text(block, '', 17, C.text, true)
    LayoutHelpers.AtLeftTopIn(block.value, block, 0, 0)
    block.caption = Theme.Caption(block, caption)
    LayoutHelpers.AtLeftTopIn(block.caption, block, 0, 21)
    LayoutHelpers.SetDimensions(block, 84, 34)
    return block
end

--- Tags that sit in a row, each after the last; :SetTags({ {text, color}, ... }) shows the first few.
local function TagRow(parent, count)
    local row = Group(parent)
    row:DisableHitTest()
    LayoutHelpers.SetHeight(row, 18)
    row.tags = {}
    for i = 1, count do
        local tag = Theme.Tag(row, '', C.muted)
        LayoutHelpers.AtTopIn(tag, row, 0)
        if i == 1 then
            tag.Left:Set(row.Left)
        else
            local before = row.tags[i - 1]
            tag.Left:Set(function() return before.Right() + Scale(6) end)
        end
        row.tags[i] = tag
    end
    row.SetTags = function(self, tags)
        for i, tag in self.tags do
            local want = tags[i]
            -- Past the row's right edge a tag is left out rather than cut.
            Theme.SetVisible(tag, want ~= nil)
            if want then
                tag:SetTag(want[1], want[2])
            end
        end
    end
    return row
end

--- How a game runs: on our server (client-server) or between the players (P2P, every FAF game).
local function NetworkKind(game)
    if game.source == 'server' then
        return 'SERVER', 'server', C.accent, 'Server game'
    end
    return 'P2P', 'p2p', C.subtle, 'P2P game'
end

local function GameTags(game, status)
    local tags = {}
    if game.source ~= 'server' and game.featuredMod ~= '' and game.featuredMod ~= 'faf' then
        table.insert(tags, { ModShort(game.featuredMod), C.violet })
    end
    if game.state ~= 'open' then
        table.insert(tags, { 'Started', C.subtle })
    end
    local range = RatingText(game)
    if range then
        table.insert(tags, { range, game.enforceRating and C.warn or C.muted })
    end
    if game.simMods and game.simMods > 0 then
        table.insert(tags, { game.simMods == 1 and '1 sim mod' or (game.simMods .. ' sim mods'), C.warn })
    end
    if game.password then
        table.insert(tags, { 'Password', C.bad })
    end
    if game.visibility == 'friends' then
        table.insert(tags, { 'Friends', C.good })
    end
    return tags
end

--- One game as a tile: its map, title, players, average rating, tags and host.
local function MakeTile(grid, launcher)
    local tile = Theme.Panel(grid, C.panel, C.line)
    local frame = Theme.Panel(tile, C.field, C.line)
    LayoutHelpers.AtLeftTopIn(frame, tile, 10, 10)
    frame.Bottom:Set(function() return tile.Bottom() - Scale(10) end)
    frame.Width:Set(function() return frame.Bottom() - frame.Top() end)
    MapPicture(frame)
    local strip = Theme.Rect(frame, 'c0000000')
    strip.Left:Set(function() return frame.Left() + 1 end)
    strip.Right:Set(function() return frame.Right() - 1 end)
    strip.Bottom:Set(function() return frame.Bottom() - 1 end)
    strip.Height:Set(Scale(20))
    strip.Width:Set(function() return strip.Right() - strip.Left() end)
    strip:DisableHitTest()
    strip.Depth:Set(function() return frame.Depth() + 3 end)
    tile.mapName = Theme.Cell(frame, 11, C.text)
    tile.mapName.Left:Set(function() return frame.Left() + Scale(6) end)
    tile.mapName.Right:Set(function() return frame.Right() - Scale(4) end)
    LayoutHelpers.AtVerticalCenterIn(tile.mapName, strip)
    tile.mapName.Depth:Set(function() return strip.Depth() + 1 end)
    tile.lock = Theme.Icon(frame, 'lock', 14, C.text)
    LayoutHelpers.AtRightTopIn(tile.lock, frame, 6, 6)
    tile.lock.Depth:Set(function() return frame.Depth() + 4 end)

    local left = function() return frame.Right() + Scale(14) end
    -- P2P or server, at the top right: an icon per kind (an icon's colour is fixed) and the word.
    tile.kindText = Theme.Text(tile, '', 10, C.subtle, true)
    tile.kindText.Right:Set(function() return tile.Right() - Scale(12) end)
    LayoutHelpers.AtTopIn(tile.kindText, tile, 13)
    tile.kindIcons = {}
    for _, name in { 'server', 'p2p' } do
        local icon = Theme.Icon(tile, name, 13, name == 'server' and C.accent or C.subtle, 2)
        icon.Right:Set(function() return tile.kindText.Left() - Scale(5) end)
        LayoutHelpers.AtTopIn(icon, tile, 11)
        tile.kindIcons[name] = icon
    end
    tile.title = Theme.Cell(tile, 15, C.text, true)
    tile.title.Left:Set(left)
    tile.title.Right:Set(function() return tile.kindText.Left() - Scale(26) end)
    LayoutHelpers.AtTopIn(tile.title, tile, 10)
    tile.players = StatBlock(tile, 'Players')
    tile.players.Left:Set(left)
    LayoutHelpers.AtTopIn(tile.players, tile, 34)
    tile.rating = StatBlock(tile, 'Avg. rating')
    tile.rating.Left:Set(function() return tile.players.Left() + Scale(86) end)
    LayoutHelpers.AtTopIn(tile.rating, tile, 34)
    tile.tags = TagRow(tile, 3)
    tile.tags.Left:Set(left)
    tile.tags.Right:Set(function() return tile.Right() - Scale(12) end)
    LayoutHelpers.AtTopIn(tile.tags, tile, 76)
    tile.host = Theme.Cell(tile, 12, C.muted)
    tile.host.Left:Set(left)
    tile.host.Right:Set(function() return tile.Right() - Scale(12) end)
    tile.host.Bottom:Set(function() return tile.Bottom() - Scale(10) end)
    tile.brackets = Theme.Brackets(tile, C.accent, false, 10)

    tile.Bind = function(self, item, selected, hover)
        self.item = item
        Theme.SetVisible(self, item ~= nil)
        if not item then
            return
        end
        local status = launcher.lastStatus or {}
        local dim = item.color ~= nil
        frame:SetMap(item.map)
        Theme.SetText(self.mapName, MapTitle(item.map))
        Theme.SetVisible(self.lock, item.password and true or false)
        Theme.SetText(self.title, item.title)
        Theme.SetColor(self.title, selected and C.accent or (dim and C.muted or C.text))
        local kindWord, kindIcon, kindColor = NetworkKind(item)
        Theme.SetText(self.kindText, kindWord)
        Theme.SetColor(self.kindText, kindColor)
        for name, icon in self.kindIcons do
            Theme.SetVisible(icon, name == kindIcon)
        end
        Theme.SetText(self.players.value, string.format('%d / %d', item.players, item.maxPlayers))
        local _, average = TeamFigures(item)
        Theme.SetText(self.rating.value, average and tostring(average) or '-')
        Theme.SetColor(self.rating.value, average and C.gold or C.subtle)
        self.tags:SetTags(GameTags(item, status))
        Theme.SetText(self.host, (item.source == 'server' and 'Server: ' or 'Host: ') .. (item.host or ''))
        self:SetColors(selected and C.selected or (hover and C.raised or C.panel),
            selected and C.accent or (hover and C.lineStrong or C.line))
        for _, bracket in self.brackets do
            Theme.SetVisible(bracket, selected)
        end
    end
    return tile
end

--- One game as a row of the list.
local function MakeRow(grid, launcher)
    local row = Theme.Panel(grid, C.panel, C.line)
    local function Column(from, to, size, color, bold)
        local cell = Theme.Cell(row, size, color, bold)
        cell.Left:Set(function() return row.Left() + math.floor(row.Width() * from) + Scale(10) end)
        cell.Right:Set(function() return row.Left() + math.floor(row.Width() * to) - Scale(4) end)
        LayoutHelpers.AtVerticalCenterIn(cell, row)
        return cell
    end
    row.source = Column(0, 0.08, 10, C.subtle, true)
    row.title = Column(0.08, 0.40, 13, C.text, true)
    row.map = Column(0.40, 0.60, 12, C.muted)
    row.players = Column(0.60, 0.69, 13, C.text, true)
    row.rating = Column(0.69, 0.78, 13, C.gold)
    row.info = Column(0.78, 0.88, 11, C.muted)
    row.host = Column(0.88, 1.0, 12, C.muted)
    row.Bind = function(self, item, selected, hover)
        self.item = item
        Theme.SetVisible(self, item ~= nil)
        if not item then
            return
        end
        local _, average = TeamFigures(item)
        local kindWord, _, kindColor = NetworkKind(item)
        Theme.SetText(self.source, kindWord)
        Theme.SetColor(self.source, kindColor)
        Theme.SetText(self.title, (item.password and '[locked] ' or '') .. item.title)
        Theme.SetColor(self.title, selected and C.accent or (item.color and C.muted or C.text))
        Theme.SetText(self.map, MapTitle(item.map))
        Theme.SetText(self.players, string.format('%d / %d', item.players, item.maxPlayers))
        Theme.SetText(self.rating, average and tostring(average) or '-')
        Theme.SetText(self.info, RatingText(item) or (item.source == 'server' and '' or ModShort(item.featuredMod)))
        Theme.SetText(self.host, item.host or '')
        self:SetColors(selected and C.selected or (hover and C.raised or C.panel),
            selected and C.accent or (hover and C.lineStrong or C.line))
    end
    return row
end

local function GameGrid(parent, launcher)
    local grid = Group(parent, 'launcher games')
    grid.items = {}
    grid.top = 1
    grid.cells = {}
    grid.mode = Prefs.GetFromCurrentProfile('fafre_launcher_view') or 'grid'
    grid.selectedKey = false
    grid.hoverKey = false

    function grid:Geometry()
        if self.mode == 'list' then
            return 1, Scale(38), Scale(4)
        end
        local gap = Scale(12)
        local cols = math.max(1, math.floor((self.Width() + gap) / (Scale(300) + gap)))
        return cols, Scale(132), gap
    end

    function grid:Rebuild()
        for _, cell in self.cells do
            cell:Destroy()
        end
        self.cells = {}
        local cols, cellHeight, gap = self:Geometry()
        local rows = math.max(1, math.floor((self.Height() + gap) / (cellHeight + gap)))
        local cellWidth = math.floor((self.Width() - Scale(10) - (cols - 1) * gap) / cols)
        for r = 1, rows do
            for c = 1, cols do
                local cell = (self.mode == 'list' and MakeRow or MakeTile)(grid, launcher)
                local x = (c - 1) * (cellWidth + gap)
                local y = (r - 1) * (cellHeight + gap)
                cell.Left:Set(function() return grid.Left() + x end)
                cell.Top:Set(function() return grid.Top() + y end)
                cell.Width:Set(cellWidth)
                cell.Height:Set(cellHeight)
                Theme.HitArea(cell, function(self, event)
                    if event.Type == 'WheelRotation' then
                        grid:Scroll(event.WheelRotation > 0 and -1 or 1)
                        if grid.onHover then
                            grid.onHover(nil)
                        end
                        return true
                    end
                    local item = cell.item
                    if not item then
                        return false
                    end
                    if event.Type == 'MouseEnter' then
                        grid.hoverKey = item.key
                        grid:Paint()
                        if grid.onHover and grid.mode ~= 'list' then
                            grid.onHover(item, cell)
                        end
                    elseif event.Type == 'MouseExit' then
                        if grid.hoverKey == item.key then
                            grid.hoverKey = false
                            if grid.onHover then
                                grid.onHover(nil)
                            end
                        end
                        grid:Paint()
                    elseif (event.Type == 'ButtonPress' or event.Type == 'ButtonDClick') and event.Modifiers.Left then
                        Theme.ClickSound()
                        launcher:SelectGame(item.key)
                        if event.Type == 'ButtonDClick' then
                            launcher:JoinSelected()
                        end
                        return true
                    end
                    return false
                end)
                table.insert(self.cells, cell)
            end
        end
        self.cols = cols
        self.rows = rows
        self.shape = self.mode .. ':' .. cols .. 'x' .. rows .. ':' .. self.Width() .. 'x' .. self.Height()
    end

    function grid:Scrolled()
        local total = math.ceil(table.getn(self.items) / math.max(1, self.cols or 1))
        return self.top, self.rows or 1, total
    end

    function grid:Scroll(rows)
        local _, shown, total = self:Scrolled()
        local top = math.max(1, math.min(self.top + rows, math.max(1, total - shown + 1)))
        if top ~= self.top then
            self.top = top
            self:Paint()
        end
    end

    function grid:SetItems(items)
        self.items = items
        self:Paint()
    end

    function grid:SetMode(mode)
        self.mode = mode
        Prefs.SetToCurrentProfile('fafre_launcher_view', mode)
        self.shape = false
        self.top = 1
        self:Paint()
    end

    function grid:Paint()
        local cols, cellHeight, gap = self:Geometry()
        local rows = math.max(1, math.floor((self.Height() + gap) / (cellHeight + gap)))
        if self.shape ~= self.mode .. ':' .. cols .. 'x' .. rows .. ':' .. self.Width() .. 'x' .. self.Height() then
            self:Rebuild()
        end
        local _, shown, total = self:Scrolled()
        self.top = math.max(1, math.min(self.top, math.max(1, total - shown + 1)))
        for i, cell in self.cells do
            local item = self.items[(self.top - 1) * self.cols + i]
            cell:Bind(item, item ~= nil and item.key == self.selectedKey, item ~= nil and item.key == self.hoverKey)
        end
        if self.mark then
            self.mark:Update()
        end
    end

    grid.mark = ScrollMark(grid, grid)
    return grid
end

-- ---------------------------------------------------------------------------------------------------------------
-- The selected game: its map, its teams with their share of the rating, and Join.

local function DetailsPanel(parent, launcher)
    local panel = Theme.Panel(parent, C.panel, C.line)
    Theme.Brackets(panel, C.accent)
    local caption = Theme.Caption(panel, 'Game details', C.accent)
    LayoutHelpers.AtLeftTopIn(caption, panel, 18, 16)
    local sourceTag = Theme.Tag(panel, 'FAF', C.subtle)
    LayoutHelpers.AtRightTopIn(sourceTag, panel, 18, 13)

    local content = Group(panel)
    LayoutHelpers.AtLeftTopIn(content, panel, 18, 40)
    content.Right:Set(function() return panel.Right() - Scale(18) end)
    content.Bottom:Set(function() return panel.Bottom() - Scale(96) end)
    content:DisableHitTest()

    local title = Theme.Cell(content, 18, C.text, true)
    title.Left:Set(content.Left)
    title.Right:Set(content.Right)
    LayoutHelpers.AtTopIn(title, content, 0)
    local meta = Theme.Cell(content, 12, C.muted)
    meta.Left:Set(content.Left)
    meta.Right:Set(content.Right)
    LayoutHelpers.AtTopIn(meta, content, 26)

    local frame = Theme.Panel(content, C.field, C.line)
    frame.Left:Set(content.Left)
    frame.Right:Set(content.Right)
    LayoutHelpers.AtTopIn(frame, content, 50)
    frame.Height:Set(function() return math.min(frame.Width(), Scale(150)) end)
    frame.Width:Set(function() return frame.Right() - frame.Left() end)
    MapPicture(frame)
    local mapLine = Theme.Cell(content, 12, C.muted)
    mapLine.Left:Set(content.Left)
    mapLine.Right:Set(content.Right)
    mapLine.Top:Set(function() return frame.Bottom() + Scale(6) end)

    -- The share of the rating each team brings, as one bar.
    local balanceCaption = Theme.Caption(content, 'Share of team rating')
    balanceCaption.Left:Set(content.Left)
    balanceCaption.Top:Set(function() return mapLine.Bottom() + Scale(14) end)
    local teamCount = Theme.Text(content, '', 11, C.subtle)
    teamCount.Right:Set(content.Right)
    teamCount.Top:Set(balanceCaption.Top)
    local bar = Group(content)
    bar:DisableHitTest()
    bar.Left:Set(content.Left)
    bar.Right:Set(content.Right)
    bar.Top:Set(function() return balanceCaption.Bottom() + Scale(6) end)
    bar.Height:Set(Scale(20))
    bar.Width:Set(function() return bar.Right() - bar.Left() end)
    local segments = {}
    for i = 1, 8 do
        local segment = Theme.Rect(bar, C.clear)
        segment:DisableHitTest()
        segment.Top:Set(bar.Top)
        segment.Bottom:Set(bar.Bottom)
        segment.Height:Set(function() return segment.Bottom() - segment.Top() end)
        segment.label = Theme.Text(bar, '', 11, C.page, true)
        LayoutHelpers.AtVerticalCenterIn(segment.label, segment)
        segment.label.Depth:Set(function() return segment.Depth() + 1 end)
        segments[i] = segment
    end

    -- The players, team by team, in rows of one height.
    local roster = Group(content)
    roster:DisableHitTest()
    roster.Left:Set(content.Left)
    roster.Right:Set(content.Right)
    -- Under the bar when it shows, else straight under the map's line.
    roster.Top:Set(function()
        return (panel.barShown and bar.Bottom() or mapLine.Bottom()) + Scale(14)
    end)
    roster.Bottom:Set(content.Bottom)
    local rosterRows = {}

    local empty = Theme.Text(panel, 'Pick a game to see its players.', 13, C.subtle)
    LayoutHelpers.AtCenterIn(empty, panel)

    local join = Theme.Button(panel, 'Join game', function()
        launcher:JoinSelected()
    end, 'primary', { height = 44 })
    join.Left:Set(function() return panel.Left() + Scale(18) end)
    join.Right:Set(function() return panel.Right() - Scale(18) end)
    join.Width:Set(function() return join.Right() - join.Left() end)
    LayoutHelpers.AtBottomIn(join, panel, 40)
    local note = Theme.Cell(panel, 12, C.subtle)
    note.Left:Set(join.Left)
    note.Right:Set(join.Right)
    LayoutHelpers.AtBottomIn(note, panel, 16)
    panel.join = join

    local function RosterRow(i)
        local row = rosterRows[i]
        if not row then
            row = Group(roster)
            row:DisableHitTest()
            row.Left:Set(roster.Left)
            row.Right:Set(roster.Right)
            row.Top:Set(function() return roster.Top() + (i - 1) * Scale(22) end)
            row.Height:Set(Scale(22))
            row.Width:Set(function() return row.Right() - row.Left() end)
            row.left = Theme.Cell(row, 13, C.text)
            row.left.Left:Set(row.Left)
            row.left.Right:Set(function() return row.Right() - Scale(70) end)
            LayoutHelpers.AtVerticalCenterIn(row.left, row)
            row.right = Theme.Text(row, '', 12, C.muted)
            row.right.Right:Set(row.Right)
            LayoutHelpers.AtVerticalCenterIn(row.right, row)
            rosterRows[i] = row
        end
        return row
    end

    panel.Show = function(self, game, status)
        local hasGame = game ~= nil
        Theme.SetVisible(content, hasGame)
        Theme.SetVisible(sourceTag, hasGame)
        Theme.SetVisible(empty, not hasGame)
        if not hasGame then
            join:SetEnabled(false)
            Theme.SetText(note, 'Double-click a game to join it directly.')
            return
        end
        local _, _, kindColor, kindName = NetworkKind(game)
        sourceTag:SetTag(kindName, kindColor)
        Theme.SetText(title, game.title)
        local metaText
        if game.source == 'server' then
            metaText = (game.state == 'open' and 'Waiting for players' or 'In game') .. ' on ' .. (game.host or '')
        else
            metaText = ModName(game.featuredMod) .. ' - hosted by ' .. (game.host or '')
            if RatingText(game) then
                metaText = metaText .. ' - rating ' .. RatingText(game)
            end
        end
        Theme.SetText(meta, metaText)
        frame:SetMap(game.map)
        local scenario = LocalScenario(game.map)
        local mapText = MapTitle(game.map)
        if scenario and scenario.size then
            mapText = mapText .. string.format('  -  %d x %d km', math.floor(scenario.size[1] / 51.2 + 0.5),
                math.floor(scenario.size[2] / 51.2 + 0.5))
        elseif not scenario then
            mapText = mapText .. '  -  not on this computer'
        end
        Theme.SetText(mapLine, mapText)

        local teams = TeamFigures(game)
        local rated = {}
        local total = 0
        for _, team in teams do
            if team.total > 0 and (tonumber(team.team) or 0) > 1 then
                table.insert(rated, team)
                total = total + team.total
            end
        end
        local showBar = table.getn(rated) >= 2
        if panel.barShown ~= showBar then
            panel.barShown = showBar
            roster.Top:Set(function()
                return (panel.barShown and bar.Bottom() or mapLine.Bottom()) + Scale(14)
            end)
        end
        Theme.SetVisible(balanceCaption, showBar)
        Theme.SetVisible(teamCount, showBar)
        Theme.SetVisible(bar, showBar)
        if showBar then
            Theme.SetText(teamCount, table.getn(rated) .. ' teams')
            local x = 0
            local width = bar.Width()
            for i, loopSegment in segments do
                -- Lua 5.0 keeps one loop variable for every pass: the closures below need their own copy.
                local segment = loopSegment
                local team = rated[i]
                Theme.SetVisible(segment, team ~= nil)
                Theme.SetVisible(segment.label, team ~= nil)
                if team then
                    local share = team.total / total
                    local from, to = x, (i == table.getn(rated)) and width or math.floor(x + width * share)
                    segment.Left:Set(function() return bar.Left() + from end)
                    segment.Right:Set(function() return bar.Left() + to - (team ~= rated[table.getn(rated)] and Scale(2) or 0) end)
                    segment.Width:Set(function() return segment.Right() - segment.Left() end)
                    local color = Theme.TeamColors[math.mod((tonumber(team.team) or 2) - 2, 8) + 1]
                    segment:SetSolidColor(color)
                    Theme.SetText(segment.label, string.format('%d%%', math.floor(share * 100 + 0.5)))
                    segment.label.Left:Set(function() return segment.Left() + Scale(6) end)
                    x = to
                end
            end
        end

        -- Rows: a header per team, then its players; open seats at the end.
        local lines = {}
        if game.source == 'server' then
            table.insert(lines, { 'Seats taken', string.format('%d of %d', game.players, game.maxPlayers), C.text })
            table.insert(lines, { 'Server', game.host or '', C.muted })
        else
            for _, team in teams do
                local number = tonumber(team.team) or 0
                local color = number > 1 and Theme.TeamColors[math.mod(number - 2, 8) + 1] or C.muted
                local average = team.rated > 0 and math.floor(team.total / team.rated + 0.5) or nil
                table.insert(lines, { string.upper(TeamName(team.team)),
                    average and ('avg ' .. average .. '  total ' .. math.floor(team.total + 0.5)) or '', color, true })
                for _, player in team.players do
                    table.insert(lines, { player.login .. (player.clan and player.clan ~= '' and (' [' .. player.clan .. ']') or ''),
                        player.rating and tostring(math.floor(player.rating + 0.5)) or '', C.text })
                end
            end
            local open = math.max(0, game.maxPlayers - game.players)
            if open > 0 then
                table.insert(lines, { open == 1 and '1 open slot' or (open .. ' open slots'), '', C.subtle })
            end
        end
        local fit = math.max(0, math.floor(roster.Height() / Scale(22)))
        for i = 1, math.max(fit, table.getn(rosterRows)) do
            local line = lines[i]
            if i <= fit then
                local row = RosterRow(i)
                Theme.SetVisible(row, line ~= nil)
                if line then
                    if i == fit and table.getn(lines) > fit then
                        line = { '+ ' .. (table.getn(lines) - fit + 1) .. ' more', '', C.subtle }
                    end
                    Theme.SetText(row.left, line[1])
                    Theme.SetColor(row.left, line[3])
                    Theme.SetText(row.right, line[2])
                    Theme.SetColor(row.right, line[4] and line[3] or C.muted)
                end
            elseif rosterRows[i] then
                Theme.SetVisible(rosterRows[i], false)
            end
        end

        local why = WhyNotJoinable(game, status)
        local busy = status.match == 'preparing' or status.match == 'running'
        join:SetEnabled(why == nil and not busy)
        Theme.SetText(note, why or (busy and 'A game is starting.' or 'Or double-click its card.'))
        Theme.SetColor(note, why and C.warn or C.subtle)
    end
    return panel
end

-- ---------------------------------------------------------------------------------------------------------------
-- The game under the mouse, after a short pause: the share of the rating each team brings and the teams side by side,
-- each player with flag and rating (FAF games; our servers' lobbies have no rated roster here).

local kHoverDelay = 0.35
local kHoverRow = 22

--- A country's flag as FAF ships them (/countries/<code>.dds, lower case), or nil.
local function FlagFile(country)
    if country and country ~= '' then
        local path = UIUtil.UIFile('/countries/' .. string.lower(country) .. '.dds')
        if DiskGetFileInfo(path) then
            return path
        end
    end
    return nil
end

local function TeamColor(team)
    local number = tonumber(team) or 0
    return number > 1 and Theme.TeamColors[math.mod(number - 2, 8) + 1] or C.muted
end

local function HoverCard(parent, launcher)
    local card = Theme.Panel(parent, 'f60a141c', C.lineStrong)
    card.Depth:Set(function() return parent.Depth() + 200 end)
    Theme.Brackets(card, C.accent)
    LayoutHelpers.SetDimensions(card, 10, 10)
    LayoutHelpers.AtLeftTopIn(card, parent, 0, 0)
    card:DisableHitTest(true)
    Theme.SetVisible(card, false)
    -- A Show on the page shows every child, this card too: hidden again unless it shows a game now.
    card.Paint = function(self)
        if not (self.shown and self.content) then
            Theme.SetVisible(self, false)
        end
    end
    Theme.Paintable(card)

    -- The pause before it shows, counted on a control of its own (a hidden one gets no frames).
    local ticker = Group(parent)
    ticker:DisableHitTest()
    LayoutHelpers.SetDimensions(ticker, 1, 1)
    LayoutHelpers.AtLeftTopIn(ticker, parent, 0, 0)
    ticker:SetNeedsFrameUpdate(true)
    ticker.OnFrame = function(self, delta)
        if card.want and not card.shown and GetSystemTimeSeconds() - card.since >= kHoverDelay then
            card.shown = true
            local ok, err = pcall(card.Build, card, card.want, card.anchor)
            if not ok then
                WARN('LAUNCHER: the game card failed: ' .. tostring(err))
                Theme.SetVisible(card, false)
            end
        end
    end

    --- The game the mouse is over now (nil: none), and its tile.
    card.Want = function(self, item, cell)
        if item and self.want and self.want.key == item.key then
            return
        end
        self.want = item
        self.anchor = cell
        self.since = GetSystemTimeSeconds()
        self.shown = false
        Theme.SetVisible(self, false)
    end

    card.Build = function(self, game, cell)
        if self.content then
            self.content:Destroy()
            self.content = false
        end
        if game.source == 'server' or not game.teams or table.getn(game.teams) == 0 or not cell then
            return
        end
        local content = Group(self)
        content:DisableHitTest()
        self.content = content
        local width = math.min(math.max(cell.Width(), Scale(560)), parent.Width())
        local pad = Scale(16)
        local inner = width - 2 * pad
        content.Left:Set(function() return self.Left() + pad end)
        content.Top:Set(function() return self.Top() + pad end)
        content.Width:Set(inner)
        content.Height:Set(10)
        local y = 0
        local function At(control, x, top)
            control.Left:Set(function() return content.Left() + x end)
            control.Top:Set(function() return content.Top() + top end)
        end

        local title = Theme.Cell(content, 16, C.text, true)
        At(title, 0, 0)
        title.Right:Set(function() return content.Left() + inner end)
        title:SetText(game.title or '')
        y = Scale(30)

        -- The bar: each team's share of the rating, when two or more teams have ratings.
        local teams = TeamFigures(game)
        local rated, total = {}, 0
        for _, team in teams do
            if (tonumber(team.team) or 0) > 1 and team.total > 0 then
                table.insert(rated, team)
                total = total + team.total
            end
        end
        if table.getn(rated) >= 2 then
            local x = 0
            for i, team in rated do
                local share = team.total / total
                local segmentWidth = (i == table.getn(rated)) and (inner - x) or math.floor(inner * share)
                local segment = Theme.Rect(content, TeamColor(team.team))
                At(segment, x, y)
                segment.Width:Set(math.max(1, segmentWidth - (i < table.getn(rated) and Scale(2) or 0)))
                segment.Height:Set(Scale(18))
                local label = Theme.Text(content, string.format('%d%%', math.floor(share * 100 + 0.5)), 11, C.page, true)
                label.Left:Set(function() return segment.Left() + Scale(6) end)
                LayoutHelpers.AtVerticalCenterIn(label, segment)
                label.Depth:Set(function() return segment.Depth() + 1 end)
                x = x + segmentWidth
            end
            y = y + Scale(26)
        end

        -- The teams side by side, two to a band; with two teams "VS" between them.
        local gap = Scale(36)
        local columnWidth = math.floor((inner - gap) / 2)
        local function TeamColumn(team, x, top)
            local color = TeamColor(team.team)
            local head = Theme.Caption(content, TeamName(team.team), color)
            At(head, x, top)
            local figures = Theme.Text(content, '', 11, C.subtle)
            if team.rated > 0 then
                figures:SetText(string.format('Avg %d  -  Total %d', math.floor(team.total / team.rated + 0.5),
                    math.floor(team.total + 0.5)))
            end
            figures.Right:Set(function() return content.Left() + x + columnWidth end)
            figures.Top:Set(function() return content.Top() + top end)
            local line = Theme.Rect(content, C.line)
            At(line, x, top + Scale(16))
            line.Width:Set(columnWidth)
            line.Height:Set(1)
            local rowTop = top + Scale(22)
            for _, player in team.players do
                -- The closures below keep this row's place; rowTop itself moves on (Lua keeps the variable).
                local thisTop = rowTop
                local flagFile = FlagFile(player.country)
                if flagFile then
                    local flag = Bitmap(content, flagFile)
                    flag:DisableHitTest()
                    LayoutHelpers.SetDimensions(flag, 20, 14)
                    At(flag, x, rowTop + Scale(4))
                end
                local name = Theme.Text(content, player.login .. ((player.clan and player.clan ~= '') and
                    (' [' .. player.clan .. ']') or ''), 13, C.text)
                At(name, x + Scale(28), rowTop + Scale(2))
                if player.login == game.host then
                    local star = Theme.Icon(content, 'star', 13, C.gold, 2)
                    star.Left:Set(function() return name.Right() + Scale(6) end)
                    star.Top:Set(function() return name.Top() + Scale(2) end)
                end
                local rating = Theme.Text(content, player.rating and tostring(math.floor(player.rating + 0.5)) or '', 13,
                    C.muted)
                rating.Right:Set(function() return content.Left() + x + columnWidth end)
                rating.Top:Set(function() return content.Top() + thisTop + Scale(2) end)
                rowTop = rowTop + Scale(kHoverRow)
            end
            return rowTop
        end
        local i = 1
        while teams[i] do
            local left, right = teams[i], teams[i + 1]
            local bottom = TeamColumn(left, 0, y)
            if right then
                bottom = math.max(bottom, TeamColumn(right, columnWidth + gap, y))
                if table.getn(teams) == 2 then
                    local versus = Theme.Text(content, 'VS', 13, C.subtle, true)
                    versus.Left:Set(function()
                        return content.Left() + columnWidth + math.floor((gap - versus.Width()) / 2)
                    end)
                    local bandTop = y
                    versus.Top:Set(function() return content.Top() + bandTop + Scale(40) end)
                end
            end
            y = bottom + Scale(12)
            i = i + 2
        end

        local open = math.max(0, (game.maxPlayers or 0) - (game.players or 0))
        if open > 0 then
            local note = Theme.Text(content, open == 1 and '1 open slot' or (open .. ' open slots'), 12, C.subtle)
            At(note, 0, y)
            y = y + Scale(20)
        end

        -- Under the tile when it fits, else over it; never past the list's sides.
        local height = y + 2 * pad
        self.Width:Set(width)
        self.Height:Set(height)
        local left = math.max(parent.Left(), math.min(cell.Left(), parent.Right() - width))
        local top = cell.Bottom() + Scale(8)
        if top + height > parent.Bottom() then
            top = math.max(parent.Top(), cell.Top() - Scale(8) - height)
        end
        self.Left:Set(left)
        self.Top:Set(top)
        self:DisableHitTest(true)
        Theme.SetVisible(self, true)
    end
    return card
end


-- ---------------------------------------------------------------------------------------------------------------
-- The multiplayer page.

local function SortGames(a, b)
    if (a.source == 'server') ~= (b.source == 'server') then
        return a.source == 'server'
    end
    if (a.state == 'open') ~= (b.state == 'open') then
        return a.state == 'open'
    end
    if (a.color == nil) ~= (b.color == nil) then
        return a.color == nil
    end
    if a.players ~= b.players then
        return a.players > b.players
    end
    return a.title < b.title
end

local function Matches(game, filter)
    if filter == '' then
        return true
    end
    for _, text in { game.title, game.map, game.host, MapTitle(game.map) } do
        if string.find(string.lower(text or ''), filter, 1, true) then
            return true
        end
    end
    return false
end

--- Tabs: labels with a count each, the chosen one in cyan and underlined.
local function Tabs(parent, entries, onPick)
    local tabs = Group(parent)
    tabs:DisableHitTest()
    LayoutHelpers.SetHeight(tabs, 40)
    tabs.items = {}
    for i, entry in entries do
        local key = entry[1]
        local tab = Group(tabs)
        tab.label = Theme.Text(tab, string.upper(entry[2]), 13, C.muted, true)
        tab.count = Theme.Text(tab, '', 11, C.subtle, true)
        LayoutHelpers.AtLeftIn(tab.label, tab, 0)
        LayoutHelpers.AtVerticalCenterIn(tab.label, tab)
        tab.count.Left:Set(function() return tab.label.Right() + Scale(8) end)
        LayoutHelpers.AtVerticalCenterIn(tab.count, tab)
        tab.Width:Set(function() return tab.count.Right() - tab.Left() end)
        tab.Top:Set(tabs.Top)
        tab.Bottom:Set(tabs.Bottom)
        tab.Height:Set(function() return tab.Bottom() - tab.Top() end)
        if i == 1 then
            tab.Left:Set(tabs.Left)
        else
            local before = tabs.items[i - 1]
            tab.Left:Set(function() return before.Right() + Scale(28) end)
        end
        tab.underline = Theme.Rect(tab, C.accent)
        tab.underline.Left:Set(tab.Left)
        tab.underline.Right:Set(tab.Right)
        tab.underline.Bottom:Set(tab.Bottom)
        tab.underline.Height:Set(Scale(2))
        tab.underline.Width:Set(function() return tab.underline.Right() - tab.underline.Left() end)
        tab.underline:DisableHitTest()
        tab.key = key
        Theme.HitArea(tab, function(self, event)
            if event.Type == 'MouseEnter' then
                tab.over = true
                tabs:Paint()
            elseif event.Type == 'MouseExit' then
                tab.over = false
                tabs:Paint()
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                Theme.ClickSound()
                onPick(key)
                return true
            end
            return false
        end)
        tabs.items[i] = tab
    end
    tabs.Paint = function(self)
        for _, tab in self.items do
            local chosen = tab.key == self.chosen
            Theme.SetColor(tab.label, chosen and C.accent or (tab.over and C.text or C.muted))
            Theme.SetVisible(tab.underline, chosen)
        end
    end
    tabs.Set = function(self, chosen, counts)
        self.chosen = chosen
        for _, tab in self.items do
            Theme.SetText(tab.count, counts[tab.key] and tostring(counts[tab.key]) or '')
        end
        self:Paint()
    end
    return tabs
end

local function BuildOnlinePage(launcher, page)
    local view = {}
    launcher.online = view
    -- One list for FAF's games and our servers' games, our servers' first; the heading counts the open ones.
    view.tab = 'all'

    local title = Theme.Title(page, 'Multiplayer', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Tabs(page, { { 'all', 'Games' } }, function(key)
        view.grid.top = 1
        launcher:Refresh()
    end)
    view.tabs.Left:Set(function() return title.Right() + Scale(40) end)
    LayoutHelpers.AtTopIn(view.tabs, page, 0)
    view.tabs.Right:Set(function() return page.Right() - Scale(300) end)

    -- Who is signed in, at the header's right.
    local account = Group(page)
    account:DisableHitTest()
    LayoutHelpers.SetHeight(account, 40)
    account.Right:Set(page.Right)
    LayoutHelpers.AtTopIn(account, page, 0)
    account.Width:Set(Scale(300))
    view.avatar = Theme.Avatar(account, '', 28)
    view.avatar.Right:Set(account.Right)
    LayoutHelpers.AtVerticalCenterIn(view.avatar, account)
    view.who = Theme.Text(account, '', 14, C.text, true)
    view.who.Right:Set(function() return view.avatar.Left() - Scale(10) end)
    LayoutHelpers.AtTopIn(view.who, account, 3)
    view.whoNote = Theme.Text(account, '', 11, C.muted)
    view.whoNote.Right:Set(view.who.Right)
    LayoutHelpers.AtTopIn(view.whoNote, account, 22)

    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return view.tabs.Bottom() end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    if not Online() then
        local card = Theme.Panel(page, C.panel, C.line)
        LayoutHelpers.SetDimensions(card, 520, 140)
        LayoutHelpers.AtCenterIn(card, page)
        Theme.Brackets(card, C.accent)
        local text = Theme.Text(card, 'Online play is not part of this build of the game.', 15, C.muted)
        LayoutHelpers.AtCenterIn(text, card)
        view.unavailable = true
        return
    end

    -- Signed out or signing in: one card in the middle.
    local signIn = Theme.Panel(page, C.panel, C.line)
    LayoutHelpers.SetDimensions(signIn, 560, 360)
    LayoutHelpers.AtCenterIn(signIn, page, 20)
    Theme.Brackets(signIn, C.accent, true)
    view.signIn = signIn
    local signIcon = Theme.Icon(signIn, 'user', 30, C.accent, 1.6)
    LayoutHelpers.AtHorizontalCenterIn(signIcon, signIn)
    LayoutHelpers.AtTopIn(signIcon, signIn, 26)
    view.signHead = Theme.Title(signIn, 'Sign in to FAF', 18)
    LayoutHelpers.AtHorizontalCenterIn(view.signHead, signIn)
    LayoutHelpers.AtTopIn(view.signHead, signIn, 70)
    view.signText = Theme.Text(signIn, '', 13, C.muted)
    LayoutHelpers.AtHorizontalCenterIn(view.signText, signIn)
    LayoutHelpers.AtTopIn(view.signText, signIn, 106)
    view.signCode = Theme.Title(signIn, '', 30, C.accent)
    LayoutHelpers.AtHorizontalCenterIn(view.signCode, signIn)
    LayoutHelpers.AtTopIn(view.signCode, signIn, 134)
    -- The page's address, cut to the panel (it is long; Copy link takes all of it), and how the hand-off went.
    view.signUrl = Theme.Cell(signIn, 12, C.subtle)
    view.signUrl.Width:Set(function() return signIn.Width() - Scale(60) end)
    LayoutHelpers.AtLeftIn(view.signUrl, signIn, 30)
    LayoutHelpers.AtTopIn(view.signUrl, signIn, 186)
    view.pageNote = Theme.Text(signIn, '', 12, C.muted)
    LayoutHelpers.AtHorizontalCenterIn(view.pageNote, signIn)
    LayoutHelpers.AtTopIn(view.pageNote, signIn, 208)
    view.signButton = Theme.Button(signIn, 'Sign in with FAF', function()
        local status = FafOnline_Status()
        if status.signIn == 'waiting' or status.signIn == 'working' then
            FafOnline_CancelSignIn()
        else
            FafOnline_SignIn()
        end
        launcher:Refresh()
    end, 'primary', { width = 220, icon = 'external' })
    LayoutHelpers.AtHorizontalCenterIn(view.signButton, signIn)
    LayoutHelpers.AtBottomIn(view.signButton, signIn, 26)
    -- Under the address: open it again, or copy it for a browser of the player's choosing.
    view.openPage = Theme.Button(signIn, 'Open the page again', function()
        FafOnline_OpenSignInPage()
        launcher:Refresh()
    end, 'secondary', { width = 210, icon = 'external' })
    view.openPage.Right:Set(function() return signIn.Left() + signIn.Width() / 2 - Scale(6) end)
    LayoutHelpers.AtTopIn(view.openPage, signIn, 240)
    view.copyLink = Theme.Button(signIn, 'Copy link', function()
        local status = FafOnline_Status()
        if status.url ~= '' and CopyToClipboard(status.url) then
            view.copiedAt = GetSystemTimeSeconds()
            view.copyLink:SetLabel('Copied')
        end
    end, 'secondary', { width = 210, icon = 'copy' })
    view.copyLink.Left:Set(function() return signIn.Left() + signIn.Width() / 2 + Scale(6) end)
    LayoutHelpers.AtTopIn(view.copyLink, signIn, 240)

    -- Signed in: the toolbar, the games, the details.
    local games = Group(page, 'online games')
    games.Left:Set(page.Left)
    games.Right:Set(page.Right)
    games.Top:Set(function() return divider.Bottom() + Scale(16) end)
    games.Bottom:Set(page.Bottom)
    view.games = games

    view.hostButton = Theme.Button(games, 'Create game', function()
        launcher:OpenHostDialog()
    end, 'primary', { icon = 'plus' })
    LayoutHelpers.AtLeftTopIn(view.hostButton, games, 0, 0)

    view.search = Theme.TextField(games, 260, 'Search games, maps, hosts', 'search', 40)
    view.search.Left:Set(function() return view.hostButton.Right() + Scale(12) end)
    LayoutHelpers.AtTopIn(view.search, games, 0)
    view.search:OnChange(function()
        view.grid.top = 1
        launcher:Refresh()
    end)

    view.filters = {}
    local lastFilter = view.search
    for _, entry in { { 'hidePrivate', 'Hide private' }, { 'hideModded', 'Hide sim mods' }, { 'showStarted', 'Show started' } } do
        local key = entry[1]
        local box = Theme.Checkbox(games, entry[2], function(self)
            Prefs.SetToCurrentProfile('fafre_launcher_' .. key, self.on)
            view.grid.top = 1
            launcher:Refresh()
        end)
        box:SetOn(Prefs.GetFromCurrentProfile('fafre_launcher_' .. key) and true or false)
        local after = lastFilter
        box.Left:Set(function() return after.Right() + Scale(18) end)
        LayoutHelpers.AtTopIn(box, games, 0)
        view.filters[key] = box
        lastFilter = box
    end

    -- Grid or list.
    view.listButton = Theme.Button(games, '', function()
        view.grid:SetMode('list')
        launcher:Refresh()
    end, 'ghost', { icon = 'list', width = 34 })
    view.gridButton = Theme.Button(games, '', function()
        view.grid:SetMode('grid')
        launcher:Refresh()
    end, 'ghost', { icon = 'grid', width = 34 })
    LayoutHelpers.AtTopIn(view.listButton, games, 0)
    LayoutHelpers.AtTopIn(view.gridButton, games, 0)

    -- The details panel when there is room for it beside two tiles; else Join goes into the footer.
    local listArea = Group(games)
    listArea.Left:Set(games.Left)
    listArea.Top:Set(function() return view.hostButton.Bottom() + Scale(16) end)
    listArea.Bottom:Set(function() return games.Bottom() - Scale(30) end)
    local wide = function() return LayoutHelpers.InvScaleNumber(games.Width()) >= 940 end
    view.details = DetailsPanel(games, launcher)
    view.details.Right:Set(games.Right)
    view.details.Top:Set(listArea.Top)
    view.details.Bottom:Set(games.Bottom)
    view.details.Width:Set(Scale(320))
    view.details.Left:Set(function() return view.details.Right() - view.details.Width() end)
    listArea.Right:Set(function()
        return wide() and view.details.Left() - Scale(16) or games.Right()
    end)
    view.gridButton.Right:Set(games.Right)
    view.listButton.Right:Set(function() return view.gridButton.Left() - Scale(4) end)
    view.wide = wide

    view.grid = GameGrid(listArea, launcher)
    LayoutHelpers.FillParent(view.grid, listArea)
    view.grid.Width:Set(function() return view.grid.Right() - view.grid.Left() end)
    view.grid.Height:Set(function() return view.grid.Bottom() - view.grid.Top() end)
    -- The teams of the game under the mouse, over the list.
    view.hover = HoverCard(games, launcher)
    view.grid.onHover = function(item, cell)
        view.hover:Want(item, cell)
    end

    view.empty = Theme.Text(listArea, '', 14, C.subtle)
    LayoutHelpers.AtCenterIn(view.empty, listArea)
    -- While FAF's lobby connects and sends its games: dots over the message.
    view.loader = Theme.Loader(listArea)
    LayoutHelpers.AtHorizontalCenterIn(view.loader, listArea)
    view.loader.Bottom:Set(function() return view.empty.Top() - Scale(14) end)
    Theme.SetVisible(view.loader, false)
    -- FAF's lobby failed: the engine tries again by itself; this tries now.
    view.retryLobby = Theme.Button(listArea, 'Try again', function()
        if rawget(_G, 'FafOnline_RetryLobby') then
            FafOnline_RetryLobby()
        end
        launcher:Refresh()
    end, 'secondary', { width = 150, icon = 'refresh' })
    LayoutHelpers.AtHorizontalCenterIn(view.retryLobby, listArea)
    view.retryLobby.Top:Set(function() return view.empty.Bottom() + Scale(18) end)
    Theme.SetVisible(view.retryLobby, false)

    view.footer = Theme.Cell(games, 12, C.subtle)
    view.footer.Left:Set(games.Left)
    view.footer.Right:Set(function() return listArea.Right() - Scale(150) end)
    view.footer.Bottom:Set(function() return games.Bottom() - Scale(6) end)
    view.footerJoin = Theme.Button(games, 'Join', function()
        launcher:JoinSelected()
    end, 'primary', { width = 120, height = 26 })
    view.footerJoin.Right:Set(listArea.Right)
    view.footerJoin.Bottom:Set(games.Bottom)
end

local function RefreshOnline(launcher)
    local view = launcher.online
    if not view then
        return
    end
    if view.unavailable then
        Theme.SetText(view.who, 'Offline')
        return
    end
    local status = FafOnline_Status()
    launcher.lastStatus = status

    local signedIn = status.signIn == 'signedin'
    local waiting = status.signIn == 'waiting' or status.signIn == 'working'
    Theme.SetVisible(view.signIn, not signedIn)
    if signedIn and view.games:IsHidden() then
        Theme.SetVisible(view.games, true)
        -- The Show showed every piece the page keeps hidden (brackets of disabled buttons, the hover card).
        Theme.RepaintAll()
    else
        Theme.SetVisible(view.games, signedIn)
    end
    view.avatar:SetLogin(signedIn and status.login or '')
    Theme.SetText(view.who, signedIn and status.login or 'Not signed in')
    local lobbyText = ({ off = 'not connected', connecting = 'connecting', signedin = 'FAF lobby connected',
        failed = 'FAF lobby failed' })[status.lobby] or status.lobby
    Theme.SetText(view.whoNote, signedIn and lobbyText or 'Sign in to play online')
    Theme.SetColor(view.whoNote, status.lobby == 'failed' and C.bad or C.muted)

    if not signedIn then
        local haveCode = waiting and status.code ~= ''
        Theme.SetVisible(view.openPage, haveCode)
        Theme.SetVisible(view.copyLink, haveCode)
        if view.copiedAt and GetSystemTimeSeconds() - view.copiedAt > 2 then
            view.copiedAt = nil
            view.copyLink:SetLabel('Copy link')
        end
        if haveCode then
            Theme.SetText(view.signHead, '')
            Theme.SetText(view.signText, 'Approve the sign-in in your browser. It shows this code:')
            Theme.SetText(view.signCode, status.code)
            Theme.SetText(view.signUrl, status.url)
            -- How the hand-off to the browser went (the engine opens the page when the code comes).
            local pageOpen = status.pageOpen or ''
            local note, color = string.format('%d s left', status.secondsLeft), C.muted
            if pageOpen == 'opening' then
                note = 'Opening your browser...'
            elseif pageOpen == 'opened' then
                note = string.format('Opened in your browser. Not there? Copy the link.  (%d s left)',
                    status.secondsLeft)
            elseif pageOpen ~= '' then
                note, color = "Your browser didn't open: " .. pageOpen .. '. Copy the link into it.', C.bad
            end
            Theme.SetText(view.pageNote, note)
            Theme.SetColor(view.pageNote, color)
            view.signButton:SetLabel('Cancel')
        else
            Theme.SetText(view.pageNote, '')
            Theme.SetText(view.signHead, waiting and 'Asking FAF' or 'Sign in to FAF')
            Theme.SetText(view.signText, status.message ~= '' and status.message or
                'Your browser opens FAF\'s page; the game signs in once you approve.')
            Theme.SetText(view.signCode, '')
            Theme.SetText(view.signUrl, '')
            view.signButton:SetLabel(waiting and 'Cancel' or 'Sign in with FAF')
        end
        view.tabs:Set(view.tab, {})
        return
    end

    view.hostButton:SetEnabled(status.lobby == 'signedin' and status.match ~= 'preparing' and status.match ~= 'running')
    launcher:Resume(status)
    local filter = string.lower(view.search.edit:GetText())
    view.search:Refresh()
    local hidePrivate = view.filters.hidePrivate.on
    local hideModded = view.filters.hideModded.on
    local showStarted = view.filters.showStarted.on

    local all = FafOnline_Games()
    for _, game in all do
        game.source = 'faf'
    end
    if rawget(_G, 'FafOnline_ServerGames') then
        for _, lobby in FafOnline_ServerGames() do
            local state = nil
            if lobby.state == 'starting' or lobby.state == 'lobby' then
                state = 'open'
            elseif lobby.state == 'game' then
                state = 'playing'
            end
            if state then
                table.insert(all, {
                    source = 'server', uid = lobby.key, title = lobby.name ~= '' and lobby.name or lobby.key,
                    map = lobby.map, players = lobby.humans, maxPlayers = lobby.humanSeats, featuredMod = '',
                    host = lobby.host, state = state, password = false, joinable = lobby.joinable, why = lobby.why,
                })
            end
        end
    end
    local counts = { all = 0 }
    local items = {}
    local shownTotal = 0
    for _, game in all do
        if game.state == 'open' then
            counts.all = counts.all + 1
        end
        do
            local visible = (showStarted or game.state == 'open') and Matches(game, filter) and
                not (hidePrivate and (game.password or game.visibility == 'friends')) and
                not (hideModded and game.simMods and game.simMods > 0)
            if game.state == 'open' or showStarted then
                shownTotal = shownTotal + 1
            end
            if visible then
                game.key = game.source .. ':' .. game.uid
                game.color = WhyNotJoinable(game, status) and C.muted or nil
                table.insert(items, game)
            end
        end
    end
    table.sort(items, SortGames)
    view.tabs:Set(view.tab, counts)
    view.grid:SetItems(items)

    local selected = nil
    for _, item in items do
        if item.key == view.grid.selectedKey then
            selected = item
        end
    end
    view.selected = selected
    local wide = view.wide()
    Theme.SetVisible(view.details, wide)
    if wide then
        view.details:Show(selected, status)
    end

    local empty = ''
    -- FAF's lobby not there yet: the games are still on their way, whatever the filters say.
    local loading = status.lobby == 'connecting' or status.lobby == 'off'
    if loading and table.getn(items) == 0 then
        empty = status.lobby == 'off' and 'Connecting to the FAF lobby...' or 'Loading games from the FAF lobby...'
    elseif status.lobby == 'failed' and table.getn(items) == 0 then
        -- The engine's message starts with its own "the lobby: ".
        local why = string.gsub(status.lobbyMessage or '', '^the lobby: ', '')
        empty = 'No connection to the FAF lobby' .. (why ~= '' and (': ' .. why) or '') .. '.'
        if (status.lobbyRetryIn or 0) > 0 then
            empty = empty .. string.format(' Trying again in %d s.', status.lobbyRetryIn)
        end
    elseif table.getn(items) == 0 then
        if filter ~= '' or hidePrivate or hideModded then
            empty = 'No game matches the search and filters.'
        else
            empty = 'No open games right now. Create one.'
        end
    end
    Theme.SetText(view.empty, empty)
    Theme.SetColor(view.empty, status.lobby == 'failed' and C.bad or C.subtle)
    Theme.SetVisible(view.loader, loading and table.getn(items) == 0)
    Theme.SetVisible(view.retryLobby, status.lobby == 'failed' and table.getn(items) == 0 and
        rawget(_G, 'FafOnline_RetryLobby') ~= nil)

    local footer
    local footerColor = C.subtle
    if status.match == 'preparing' or status.match == 'running' then
        footer = status.matchMessage ~= '' and status.matchMessage or 'Starting the game'
        footerColor = C.accent
    elseif status.match == 'failed' and status.matchMessage ~= '' then
        footer = status.matchMessage
        footerColor = C.bad
    elseif launcher.lastError then
        footer = launcher.lastError
        footerColor = C.bad
    elseif launcher.resume then
        footer = (launcher.resume.kind == 'join' and 'Joining the game' or 'Creating your game') .. ' on ' ..
            ModName(launcher.resume.mod) .. ' once the FAF lobby answers.'
        footerColor = C.accent
    elseif loading then
        footer = 'Connecting to the FAF lobby. Create game unlocks once it answers.'
        footerColor = C.accent
    elseif selected and not wide then
        local why = WhyNotJoinable(selected, status)
        footer = why or (selected.title .. ' on ' .. MapTitle(selected.map) .. ', hosted by ' .. selected.host)
        footerColor = why and C.warn or C.text
    elseif selected and selected.source == 'faf' and selected.featuredMod ~= '' and
        selected.featuredMod ~= status.loadedMod and not WhyNotJoinable(selected, status) then
        footer = 'Joining starts the game again on ' .. ModName(selected.featuredMod) .. '\'s files.'
        footerColor = C.accent
    else
        footer = string.format('Showing %d of %d games. Click a game for details, double-click to join.',
            table.getn(items), shownTotal)
    end
    Theme.SetText(view.footer, footer)
    Theme.SetColor(view.footer, footerColor)
    Theme.SetVisible(view.footerJoin, not wide)
    view.footerJoin:SetEnabled(selected ~= nil and WhyNotJoinable(selected, status) == nil and
        status.match ~= 'preparing' and status.match ~= 'running')
    view.listButton.icon:SetIcon('list', view.grid.mode == 'list' and C.accent or C.muted)
    view.gridButton.icon:SetIcon('grid', view.grid.mode == 'grid' and C.accent or C.muted)
end


-- ---------------------------------------------------------------------------------------------------------------
-- The host dialog.

local function MapFolder(scenarioPath)
    local _, _, folder = string.find(scenarioPath or '', '^/maps/([^/]+)/')
    return folder and string.lower(folder) or nil
end

local function OpenHostDialog(launcher)
    local status = FafOnline_Status()
    local frameWidth, frameHeight = FrameUnits()
    local cover = Modal(launcher.root, math.min(820, frameWidth - 24), math.max(452, math.min(580, frameHeight - 24)))
    local panel = cover.panel
    launcher.hostDialog = cover

    local head = Theme.Title(panel, 'Create game', 20)
    LayoutHelpers.AtLeftTopIn(head, panel, 26, 22)
    local note = Theme.Text(panel, 'Hosted on FAF: players on FAF\'s own client see it and can join.', 12, C.muted)
    LayoutHelpers.AtLeftTopIn(note, panel, 26, 52)

    local function Label(text, top)
        local caption = Theme.Caption(panel, text)
        LayoutHelpers.AtLeftTopIn(caption, panel, 26, top)
        return caption
    end

    Label('Title', 84)
    local titleField = Theme.TextField(panel, 340, 'The game\'s name', nil, 60)
    titleField.edit:SetText(Prefs.GetFromCurrentProfile('fafre_host_title') or
        ((status.login ~= '' and status.login or 'My') .. '\'s game'))
    titleField:Refresh()
    LayoutHelpers.AtLeftTopIn(titleField, panel, 26, 100)

    Label('Password', 144)
    local passwordField = Theme.TextField(panel, 340, 'None: anyone can join', 'lock', 40)
    LayoutHelpers.AtLeftTopIn(passwordField, panel, 26, 160)

    Label('Featured mod', 204)
    local modChoices = {}
    local modNoteRefresh = nil -- set once the note exists
    local chosenMod = status.loadedMod ~= '' and status.loadedMod or 'faf'
    for i, mod in FeaturedMods do
        local id = mod.id
        local choice = Theme.Choice(panel, mod.name, 166, function(self)
            chosenMod = id
            for _, other in modChoices do
                other.selected = other.id == id
                other:Paint(false)
            end
            if modNoteRefresh then
                modNoteRefresh()
            end
        end)
        choice.id = id
        local ready, why = ModFiles(id, status)
        choice.enabled = ready
        choice.why = why
        choice.selected = id == chosenMod
        choice:Paint(false)
        LayoutHelpers.AtLeftTopIn(choice, panel, 26 + math.mod(i - 1, 2) * 174, 220 + math.floor((i - 1) / 2) * 38)
        modChoices[i] = choice
    end
    local modNote = Theme.Cell(panel, 11, C.subtle)
    LayoutHelpers.AtLeftTopIn(modNote, panel, 26, 296)
    modNote.Right:Set(function() return panel.Left() + Scale(366) end)
    local tip = Theme.Tip(panel, 340)
    -- What the pick means (a restart on another featured mod's files) under the choices; why a greyed one can't be
    -- picked in a tip by it.
    local function ModNote(hovered)
        if hovered and not hovered.enabled then
            tip:Say(ModName(hovered.id) .. ': ' .. tostring(hovered.why) .. '.', C.warn, hovered)
            return
        end
        tip:Quiet()
        if chosenMod ~= status.loadedMod then
            Theme.SetText(modNote, 'The game starts again on ' .. ModName(chosenMod) .. '\'s files, then creates it.')
            Theme.SetColor(modNote, C.accent)
        else
            Theme.SetText(modNote, '')
        end
    end
    for _, choice in modChoices do
        local this = choice
        this.onDisabledHover = function(over)
            ModNote(over and this or nil)
        end
    end
    modNoteRefresh = function() ModNote() end
    ModNote()
    cover.modChoices = modChoices -- for the test walk

    Label('Who sees it', 322)
    local visibility = 'public'
    local visChoices = {}
    for i, entry in { { 'public', 'Everyone' }, { 'friends', 'Friends only' } } do
        local value = entry[1]
        local choice = Theme.Choice(panel, entry[2], 166, function(self)
            visibility = value
            for _, other in visChoices do
                other.selected = other.value == value
                other:Paint(false)
            end
        end)
        choice.value = value
        choice.selected = value == visibility
        choice:Paint(false)
        LayoutHelpers.AtLeftTopIn(choice, panel, 26 + (i - 1) * 174, 338)
        visChoices[i] = choice
    end

    Label('Rating range', 382)
    local minField = Theme.TextField(panel, 100, 'Any', nil, 5)
    LayoutHelpers.AtLeftTopIn(minField, panel, 26, 398)
    local dash = Theme.Text(panel, '-', 14, C.subtle)
    LayoutHelpers.AtLeftTopIn(dash, panel, 134, 405)
    local maxField = Theme.TextField(panel, 100, 'Any', nil, 5)
    LayoutHelpers.AtLeftTopIn(maxField, panel, 148, 398)
    local enforce = Theme.Checkbox(panel, 'Enforce', function() end)
    LayoutHelpers.AtLeftTopIn(enforce, panel, 262, 398)

    -- The map: its picture, a search and the maps on this computer, by name.
    local right = function() return panel.Right() - Scale(26) end
    local mapLeft = function() return panel.Left() + Scale(400) end
    local mapCaption = Theme.Caption(panel, 'Map')
    mapCaption.Left:Set(mapLeft)
    LayoutHelpers.AtTopIn(mapCaption, panel, 84)
    local frame = Theme.Panel(panel, C.field, C.line)
    frame.Left:Set(mapLeft)
    LayoutHelpers.AtTopIn(frame, panel, 100)
    frame.Height:Set(Scale(124))
    frame.Width:Set(Scale(124))
    MapPicture(frame)
    local mapTitle = Theme.Cell(panel, 15, C.text, true)
    mapTitle.Left:Set(function() return frame.Right() + Scale(14) end)
    mapTitle.Right:Set(right)
    mapTitle.Top:Set(frame.Top)
    local mapInfo = Theme.Cell(panel, 12, C.muted)
    mapInfo.Left:Set(mapTitle.Left)
    mapInfo.Right:Set(right)
    mapInfo.Top:Set(function() return mapTitle.Bottom() + Scale(4) end)
    local mapSearch = Theme.TextField(panel, 300, 'Search maps', 'search', 40)
    mapSearch.Left:Set(mapLeft)
    mapSearch.Right:Set(right)
    mapSearch.Width:Set(function() return mapSearch.Right() - mapSearch.Left() end)
    mapSearch.Top:Set(function() return frame.Bottom() + Scale(12) end)

    local paths = {}
    for _, path in DiskFindFiles('/maps', '*_scenario.lua') do
        table.insert(paths, path)
    end
    table.sort(paths)
    local last = Prefs.GetFromCurrentProfile('fafre_host_map') or Prefs.GetFromCurrentProfile('LastScenario') or
        UIUtil.defaultScenario
    local names = {}
    local function NameOf(path)
        if names[path] == nil then
            local ok, scenario = pcall(import('/lua/ui/maputil.lua').LoadScenario, path)
            names[path] = ok and scenario and scenario.name and LOC(scenario.name) or false
        end
        return names[path] or MapFolder(path) or path
    end
    local function ShowMap(item)
        if not item then
            return
        end
        frame:SetMap(item.folder)
        Theme.SetText(mapTitle, NameOf(item.path))
        local scenario = LocalScenario(item.folder)
        local info = item.folder
        if scenario and scenario.size then
            info = info .. string.format('  -  %d x %d km', math.floor(scenario.size[1] / 51.2 + 0.5),
                math.floor(scenario.size[2] / 51.2 + 0.5))
        end
        if scenario and scenario.Configurations and scenario.Configurations.standard and
            scenario.Configurations.standard.teams and scenario.Configurations.standard.teams[1] then
            info = info .. '  -  ' .. table.getn(scenario.Configurations.standard.teams[1].armies or {}) .. ' players'
        end
        Theme.SetText(mapInfo, info)
    end
    local mapList = VirtualList(panel, {
        { 'Map', 0.64, function(item) return NameOf(item.path) end },
        { 'Folder', 0.36, function(item) return item.folder end, C.subtle },
    }, function(item, double)
        ShowMap(item)
    end)
    mapList.Left:Set(mapLeft)
    mapList.Right:Set(right)
    mapList.Top:Set(function() return mapSearch.Bottom() + Scale(10) end)
    mapList.Bottom:Set(function() return panel.Bottom() - Scale(76) end)
    mapList.selectedKey = last
    local function FillMaps()
        local filter = string.lower(mapSearch.edit:GetText())
        local items = {}
        for _, path in paths do
            local folder = MapFolder(path)
            if folder and (filter == '' or string.find(folder, filter, 1, true) or
                string.find(string.lower(names[path] or ''), filter, 1, true)) then
                table.insert(items, { key = path, path = path, folder = folder })
            end
        end
        mapList:SetItems(items)
    end
    mapSearch:OnChange(function()
        mapList.top = 1
        FillMaps()
    end)
    FillMaps()
    for index, item in mapList.items do
        if item.key == last then
            mapList:ScrollSetTop(nil, index - 3)
            ShowMap(item)
        end
    end

    -- Why Create game didn't go: wrapped onto lines left of the buttons.
    local errorText = Theme.Paragraph(panel, 12, C.bad)
    errorText.Left:Set(function() return panel.Left() + Scale(26) end)
    errorText.Right:Set(function() return panel.Right() - Scale(340) end)
    errorText.Top:Set(function() return panel.Bottom() - Scale(62) end)

    local function Close()
        launcher.hostDialog = false
        cover:Destroy()
        launcher:SetHomeEscape()
    end
    local cancel = Theme.Button(panel, 'Cancel', Close, 'secondary', { width = 120 })
    LayoutHelpers.AtRightIn(cancel, panel, 26)
    LayoutHelpers.AtBottomIn(cancel, panel, 22)
    local host = Theme.Button(panel, 'Create game', function()
        local map = mapList:Selected()
        if not map then
            errorText:SetText('Pick a map.')
            return
        end
        local request = {
            title = titleField.edit:GetText(),
            map = map.folder,
            mod = chosenMod,
            visibility = visibility,
            password = passwordField.edit:GetText(),
            ratingMin = tonumber(minField.edit:GetText()),
            ratingMax = tonumber(maxField.edit:GetText()),
            enforceRating = enforce.on,
        }
        if request.title == '' then
            errorText:SetText('The game needs a title.')
            return
        end
        Prefs.SetToCurrentProfile('fafre_host_title', request.title)
        Prefs.SetToCurrentProfile('fafre_host_map', map.path)
        local ok, why = launcher:HostRequest(request)
        if not ok then
            errorText:SetText(tostring(why))
            return
        end
        LOG('LAUNCHER: hosting ' .. request.map .. ' on ' .. request.mod)
        Close()
        launcher:Refresh()
    end, 'primary', { width = 170 })
    host.Right:Set(function() return cancel.Left() - Scale(12) end)
    LayoutHelpers.AtBottomIn(host, panel, 22)

    import('/lua/ui/uimain.lua').SetEscapeHandler(Close)
    return cover
end

local function AskPassword(launcher, game)
    local cover = Modal(launcher.root, 460, 210)
    local panel = cover.panel
    local head = Theme.Title(panel, 'Password', 16)
    LayoutHelpers.AtLeftTopIn(head, panel, 24, 20)
    local text = Theme.Cell(panel, 13, C.muted)
    LayoutHelpers.AtLeftTopIn(text, panel, 24, 54)
    LayoutHelpers.AtRightIn(text, panel, 24)
    text:SetText(game.title .. ' needs a password.')
    local field = Theme.TextField(panel, 412, 'Password', 'lock', 40)
    LayoutHelpers.AtLeftTopIn(field, panel, 24, 84)
    field.edit:AcquireFocus()
    local function Join()
        local password = field.edit:GetText()
        cover:Destroy()
        launcher:Join(game, password)
    end
    field.edit.OnEnterPressed = function(self, value)
        Join()
        return true
    end
    local cancel = Theme.Button(panel, 'Cancel', function() cover:Destroy() end, 'secondary', { width = 110 })
    LayoutHelpers.AtRightIn(cancel, panel, 24)
    LayoutHelpers.AtBottomIn(cancel, panel, 20)
    local join = Theme.Button(panel, 'Join', Join, 'primary', { width = 110 })
    join.Right:Set(function() return cancel.Left() - Scale(10) end)
    LayoutHelpers.AtBottomIn(join, panel, 20)
end

-- ---------------------------------------------------------------------------------------------------------------
-- The launcher.

local Launcher = {}
Launcher.__index = Launcher

function Launcher:SetHomeEscape()
    local launcher = self
    import('/lua/ui/uimain.lua').SetEscapeHandler(function() launcher:Exit() end)
end

function Launcher:Refresh()
    local ok, err = pcall(RefreshOnline, self)
    if not ok and not self.refreshFailed then
        self.refreshFailed = true
        WARN('LAUNCHER: the online page failed to update: ' .. tostring(err))
    end
    if self.status then
        self.status:Update()
    end
end

function Launcher:SelectGame(key)
    if self.online and self.online.grid then
        self.online.grid.selectedKey = key
        self.lastError = false
        self:Refresh()
    end
end

function Launcher:OpenHostDialog()
    if self.hostDialog then
        return
    end
    self.lastError = false
    local ok, err = pcall(OpenHostDialog, self)
    if not ok then
        WARN('LAUNCHER: the host dialog failed: ' .. tostring(err))
        if self.hostDialog then
            self.hostDialog:Destroy()
            self.hostDialog = false
        end
        Message(self.root, 'Create game', 'The dialog failed to open: ' .. tostring(err))
    end
end

--- Hosts `request` on FAF. On another featured mod than the loaded one, the game starts again on its files and the
--- new start hosts it (RestartOn keeps the request for it).
function Launcher:HostRequest(request)
    local status = FafOnline_Status()
    if request.mod and request.mod ~= '' and request.mod ~= status.loadedMod then
        local action = { kind = 'host' }
        for key, value in request do
            action[key] = value
        end
        return self:RestartOn(request.mod, action)
    end
    local ok, why = FafOnline_Host(request)
    if not ok then
        return false, 'FAF refused: ' .. tostring(why)
    end
    return true
end

--- Starts the game again on `mod`'s files with `action` for the new start, and quits this one.
function Launcher:RestartOn(mod, action)
    if not rawget(_G, 'FafOnline_RestartOn') then
        return false, 'This build can\'t switch featured mod.'
    end
    local ok, why = FafOnline_RestartOn(mod, action)
    if not ok then
        return false, 'Can\'t switch to ' .. ModName(mod) .. ': ' .. tostring(why)
    end
    LOG('LAUNCHER: starting again on ' .. mod .. ' to ' .. tostring(action.kind))
    if rawget(_G, 'SavePreferences') then
        SavePreferences()
    end
    self:StopSounds()
    self.root:Destroy()
    ExitApplication()
    return true
end

--- After a restart on another featured mod: what the launcher was doing, once FAF's lobby answers. Given up after
--- 5 minutes (signing in again can take a while).
function Launcher:Resume(status)
    local resume = self.resume
    if not resume then
        return
    end
    if GetSystemTimeSeconds() - self.resumeSince > 300 then
        self.resume = false
        self.lastError = 'Gave up waiting for the FAF lobby to ' .. (resume.kind == 'join' and 'join the game.' or
            'create the game.')
        return
    end
    if status.lobby ~= 'signedin' or status.match == 'preparing' or status.match == 'running' then
        return
    end
    self.resume = false
    if resume.kind == 'host' then
        resume.kind = nil
        local ok, why = FafOnline_Host(resume)
        self.resumed = 'host ' .. tostring(ok)
        resumedThisStart = self.resumed
        if ok then
            LOG('LAUNCHER: hosting ' .. tostring(resume.map) .. ' on ' .. tostring(resume.mod) .. ' after the restart')
        else
            self.lastError = 'Could not create the game on ' .. ModName(resume.mod) .. ': ' .. tostring(why)
        end
    elseif resume.kind == 'join' then
        self.resumed = 'join'
        resumedThisStart = self.resumed
        LOG('LAUNCHER: joining game ' .. tostring(resume.uid) .. ' after the restart')
        self:Join({ source = 'faf', uid = resume.uid, featuredMod = resume.mod }, resume.password)
    end
end

function Launcher:Join(game, password)
    local ok, why
    local status = FafOnline_Status()
    if game.source ~= 'server' and game.featuredMod and game.featuredMod ~= '' and
        game.featuredMod ~= status.loadedMod then
        ok, why = self:RestartOn(game.featuredMod,
            { kind = 'join', uid = game.uid, password = password or '', mod = game.featuredMod })
        if not ok then
            self.lastError = why
            self:Refresh()
        end
        return
    end
    if game.source == 'server' then
        ok, why = FafOnline_JoinServer(game.uid)
    else
        ok, why = FafOnline_Join(game.uid, password)
    end
    if ok then
        self.lastError = false
        LOG('LAUNCHER: joining game ' .. game.uid)
    else
        self.lastError = 'Could not join: ' .. tostring(why)
    end
    self:Refresh()
end

function Launcher:JoinSelected()
    local view = self.online
    if not view or not view.selected then
        return
    end
    local game = view.selected
    if WhyNotJoinable(game, self.lastStatus or FafOnline_Status()) then
        return
    end
    if game.password then
        AskPassword(self, game)
    else
        self:Join(game, nil)
    end
end


--- Hides the launcher while one of FAF's screens is open over it; `back` shows it again.
function Launcher:OpenScreen(name, open, stopMusic)
    local launcher = self
    if stopMusic then
        self:StopSounds()
    end
    self.body:Hide()
    import('/fafengine/modules/lua/ui/uiscale.lua').SetMainMenuVisible(false)
    local host = Group(self.root, 'launcher screen ' .. name)
    LayoutHelpers.FillParent(host, self.root)
    host.Depth:Set(function() return launcher.root.Depth() + 100 end)
    self.screen = host
    self.screenName = name
    local function Back()
        if launcher.screen == host then
            launcher.screen = false
            launcher.screenName = false
            host:Destroy()
            launcher:ShowHome()
        end
    end
    local ok, err = pcall(open, host, Back)
    if not ok then
        WARN('LAUNCHER: ' .. name .. ' failed to open: ' .. tostring(err))
        Back()
        Message(self.root, name, name .. ' failed to open: ' .. tostring(err))
        return false
    end
    LOG('LAUNCHER: opened ' .. name)
    return true
end

function Launcher:ShowHome()
    if self.root:IsHidden() then
        return
    end
    self.body:Show()
    for name, page in self.pages do
        Theme.SetVisible(page, name == self.page)
    end
    -- Show on the body showed every piece a control keeps hidden (check marks, brackets): each paints itself again.
    Theme.RepaintAll()
    for _, item in self.navItems do
        item:Paint(false)
    end
    self:StartSounds()
    self:SetHomeEscape()
    import('/fafengine/modules/lua/ui/uiscale.lua').SetMainMenuVisible(true)
    self:Refresh()
end

--- Back to the launcher from a screen opened by OpenScreen, whether or not that screen closed itself (a test, or
--- a screen whose own way back failed).
function Launcher:CloseScreen()
    if self.screen then
        local host = self.screen
        self.screen = false
        self.screenName = false
        host:Destroy()
        self:ShowHome()
    end
end

function Launcher:StartSounds()
    if not self.music and not HasCommandLineArg('/nomusic') then
        self.music = PlaySound(Sound({ Cue = 'Main_Menu', Bank = 'Music' }))
    end
    if self.movie and not self.ambient and not HasCommandLineArg('/nomovie') then
        self.ambient = PlaySound(Sound({ Cue = 'AMB_Menu_Loop', Bank = 'AmbientTest' }))
    end
end

function Launcher:StopSounds()
    if self.music then
        StopSound(self.music)
        self.music = false
    end
    if self.ambient then
        StopSound(self.ambient)
        self.ambient = false
    end
end

--- FAF's first-time prompt for the tutorial, as its main menu asks before campaign and skirmish (main.lua).
function Launcher:TutorialPrompt(callback)
    if Prefs.GetFromCurrentProfile('MenuTutorialPrompt') then
        callback()
        return
    end
    Prefs.SetToCurrentProfile('MenuTutorialPrompt', true)
    local launcher = self
    UIUtil.QuickDialog(GetFrame(0),
        '<LOC EXITDLG_0006>This appears to be your first time playing Supreme Commander: Forged Alliance. Would you like to play the tutorial before you begin?',
        '<LOC _Yes>', function()
            launcher:StopSounds()
            launcher.root:Destroy()
            LaunchSinglePlayerSession(import('/lua/singleplayerlaunch.lua').SetupCampaignSession(
                import('/lua/ui/maputil.lua').LoadScenario('/maps/X1CA_TUT/X1CA_TUT_scenario.lua'), 2, nil, nil, true))
        end,
        '<LOC _No>', callback,
        nil, nil, true, { worldCover = true, enterButton = 1, escapeButton = 2 })
end

function Launcher:Skirmish()
    local launcher = self
    self:TutorialPrompt(function()
        launcher:OpenScreen('Skirmish', function(host, back)
            local playerName = Prefs.GetCurrentProfile().Name or 'Unknown'
            local lobby = import('/lua/ui/lobby/lobby.lua')
            lobby.CreateLobby('None', 0, playerName, nil, nil, host, back)
            lobby.HostGame(playerName .. '\'s Skirmish', Prefs.GetFromCurrentProfile('LastScenario') or
                UIUtil.defaultScenario, true)
        end, true)
    end)
end

function Launcher:Campaign()
    local launcher = self
    self:TutorialPrompt(function()
        launcher:StopSounds()
        local ok, err = pcall(function()
            launcher.root:Destroy()
            current = false
            -- It builds its own screen and calls main.lua's CreateUI to come back, which is this launcher again.
            import('/lua/ui/campaign/selectcampaign.lua').CreateUI()
        end)
        if not ok then
            WARN('LAUNCHER: the campaign failed to open: ' .. tostring(err))
            import('/lua/ui/menus/main.lua').CreateUI()
        end
    end)
end

function Launcher:Lan()
    self:OpenScreen('Multiplayer LAN', function(host, back)
        import('/lua/ui/lobby/gameselect.lua').CreateUI(host, back)
    end)
end

function Launcher:Replays()
    -- Replays of any FAF game version play, with the engine patches of the nearest version this engine models
    -- (rep_PlayAnyVersion, as /noversioncheck); their own game files at runtime come later.
    ConExecute('rep_PlayAnyVersion true')
    self:OpenScreen('Replays', function(host, back)
        import('/lua/ui/dialogs/replay.lua').CreateDialog(host, true, back)
    end)
end

function Launcher:Mods()
    self:OpenScreen('Mods', function(host, back)
        -- FAF's own main menu goes through /lua/ui/dialogs/modmanager.lua, which hands its callback to the mod
        -- manager as `availableMods`; the manager loops over that table (`for _, peerMods in mods.availableToAll`),
        -- and a function there is called as the loop's iterator, so the callback ran at once. Called here as the
        -- manager takes it: editable, no other players, no callback, so Save stores the choice itself
        -- (SetSelectedMods). Back here once its popup is gone, a tick later, as its Close destroys it after
        -- OnClosed.
        local dialog = import('/lua/ui/lobby/modsmanager.lua').CreateDialog(host, true, {}, nil)
        if dialog then
            local onDestroy = dialog.OnDestroy
            dialog.OnDestroy = function(self)
                if onDestroy then
                    onDestroy(self)
                end
                ForkThread(back)
            end
        end
    end)
end

function Launcher:Options()
    local UiScale = import('/fafengine/modules/lua/ui/uiscale.lua')
    self:OpenScreen('Options', function(host, back)
        UiScale.SetOptionsFromMainMenu(true)
        import('/lua/ui/dialogs/options.lua').CreateDialog(host, function()
            UiScale.SetOptionsFromMainMenu(false)
            back()
        end)
    end)
end

--- FAF's own main menu, with one button on it back to the launcher.
function Launcher:FafMenu()
    local buildFafMenu = self.buildFafMenu
    self:StopSounds()
    self.root:Destroy()
    current = false
    local captured = false
    local createScreenGroup = UIUtil.CreateScreenGroup
    UIUtil.CreateScreenGroup = function(root, name)
        local group = createScreenGroup(root, name)
        if name == 'Main Menu ScreenGroup' and not captured then
            captured = group
        end
        return group
    end
    local ok, err = pcall(buildFafMenu)
    UIUtil.CreateScreenGroup = createScreenGroup
    if not ok then
        WARN('LAUNCHER: FAF\'s main menu failed: ' .. tostring(err))
        return
    end
    if captured then
        fafMenuBack = function()
            fafMenuBack = false
            captured:Destroy()
            import('/lua/ui/menus/main.lua').CreateUI()
        end
        local back = Theme.Button(captured, 'Launcher', function() fafMenuBack() end, 'primary',
            { icon = 'arrowLeft', width = 150 })
        LayoutHelpers.AtLeftTopIn(back, captured, 20, 20)
        back.Depth:Set(function() return captured.Depth() + 1000 end)
    end
    LOG('LAUNCHER: opened FAF\'s main menu')
end

function Launcher:Exit()
    if self.exitDialog then
        return
    end
    local launcher = self
    self.exitDialog = UIUtil.QuickDialog(GetFrame(0), '<LOC EXITDLG_0003>Are you sure you\'d like to exit?',
        '<LOC _Yes>', function()
            launcher:StopSounds()
            launcher.root:Destroy()
            ExitApplication()
        end,
        '<LOC _No>', function() launcher.exitDialog = false end,
        nil, nil, true, { worldCover = true, enterButton = 1, escapeButton = 2 })
end

function Launcher:ShowPage(name)
    self.page = name
    for pageName, page in self.pages do
        Theme.SetVisible(page, pageName == name)
    end
    for _, item in self.navItems do
        item:Paint(false)
    end
    self:Refresh()
end

-- ---------------------------------------------------------------------------------------------------------------
-- The rail on the left: where everything starts.

local function NavItem(launcher, rail, iconName, label, action, page)
    local item = Group(rail)
    LayoutHelpers.SetHeight(item, 38)
    local back = Theme.Fill(item, C.clear)
    back.Depth:Set(function() return item.Depth() end)
    local bar = Theme.Rect(item, C.accent)
    bar.Left:Set(item.Left)
    bar.Top:Set(item.Top)
    bar.Bottom:Set(item.Bottom)
    bar.Width:Set(Scale(3))
    bar.Height:Set(function() return bar.Bottom() - bar.Top() end)
    bar:DisableHitTest()
    local icon = Theme.Icon(item, iconName, 18, C.muted)
    LayoutHelpers.AtLeftIn(icon, item, 22)
    LayoutHelpers.AtVerticalCenterIn(icon, item)
    local text = Theme.Text(item, string.upper(label), 12, C.muted, true)
    text.Left:Set(function() return icon.Right() + Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(text, item)
    item.Paint = function(self, over)
        local chosen = page ~= nil and launcher.page == page
        back:SetSolidColor(chosen and Theme.WithAlpha(C.accent, 0.12) or (over and C.raised or C.clear))
        Theme.SetVisible(bar, chosen)
        local color = chosen and C.accent or (over and C.text or C.muted)
        Theme.SetColor(text, color)
        icon:SetIcon(iconName, color)
    end
    Theme.HitArea(item, function(self, event)
        if event.Type == 'MouseEnter' then
            Theme.HoverSound()
            item:Paint(true)
        elseif event.Type == 'MouseExit' then
            item:Paint(false)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            Theme.ClickSound()
            action()
            return true
        end
        return false
    end)
    return item
end

local function BuildRail(launcher, body)
    local rail = Theme.Rect(body, C.rail)
    rail.Left:Set(body.Left)
    rail.Top:Set(body.Top)
    rail.Bottom:Set(function() return body.Bottom() - Scale(kStatusHeight) end)
    rail.Width:Set(Scale(kRailWidth))
    rail.Height:Set(function() return rail.Bottom() - rail.Top() end)
    rail:DisableHitTest()
    local edge = Theme.Rect(body, C.line)
    edge.Left:Set(rail.Right)
    edge.Top:Set(rail.Top)
    edge.Bottom:Set(rail.Bottom)
    edge.Width:Set(1)
    edge.Height:Set(function() return edge.Bottom() - edge.Top() end)
    edge:DisableHitTest()

    local brand = Theme.Logo(rail, 92, C.accent)
    LayoutHelpers.AtLeftTopIn(brand, rail, 22, 20)
    local subtitle = Theme.Text(rail, 'Forged Alliance Forever', 12, C.muted)
    subtitle.Left:Set(function() return rail.Left() + Scale(24) end)
    subtitle.Top:Set(function() return brand:LogoBottom() + Scale(8) end)
    local versionOk, version = pcall(function() return import('/lua/version.lua').GetVersion() end)
    local versionText = Theme.Text(rail, 'Game version ' .. (versionOk and tostring(version) or '?'), 11, C.subtle)
    versionText.Left:Set(subtitle.Left)
    versionText.Top:Set(function() return subtitle.Bottom() + Scale(2) end)

    local entries = {
        'Online',
        { 'play', 'Multiplayer', function() launcher:ShowPage('online') end, 'online' },
        'Offline',
        { 'flag', 'Skirmish', function() launcher:Skirmish() end },
        { 'book', 'Campaign', function() launcher:Campaign() end },
        { 'users', 'LAN', function() launcher:Lan() end },
        'Library',
        { 'replays', 'Replays', function() launcher:Replays() end },
        { 'mods', 'Mods', function() launcher:Mods() end },
        'Game',
        { 'settings', 'Options', function() launcher:Options() end },
        { 'home', 'FAF main menu', function() launcher:FafMenu() end },
        { 'logout', 'Exit', function() launcher:Exit() end },
    }
    launcher.navItems = {}
    local top = 112
    for _, entry in entries do
        if type(entry) == 'string' then
            local caption = Theme.Caption(rail, entry)
            LayoutHelpers.AtLeftTopIn(caption, rail, 24, top + 8)
            top = top + 28
        else
            local item = NavItem(launcher, rail, entry[1], entry[2], entry[3], entry[4])
            LayoutHelpers.AtLeftTopIn(item, rail, 0, top)
            item.Right:Set(rail.Right)
            item.Width:Set(function() return item.Right() - item.Left() end)
            table.insert(launcher.navItems, item)
            top = top + 38
        end
    end
    return rail
end

--- The line along the bottom: what this game is, and whether FAF and our servers are reached.
local function BuildStatusBar(launcher, body)
    local bar = Theme.Rect(body, C.rail)
    bar.Left:Set(body.Left)
    bar.Right:Set(body.Right)
    bar.Bottom:Set(body.Bottom)
    bar.Height:Set(Scale(kStatusHeight))
    bar.Width:Set(function() return bar.Right() - bar.Left() end)
    bar:DisableHitTest()
    local line = Theme.Rect(body, C.line)
    line.Left:Set(bar.Left)
    line.Right:Set(bar.Right)
    line.Top:Set(bar.Top)
    line.Height:Set(1)
    line.Width:Set(function() return line.Right() - line.Left() end)
    line:DisableHitTest()
    local left = Theme.Text(bar, 'faf-re in-game launcher', 11, C.subtle)
    LayoutHelpers.AtLeftIn(left, bar, 16)
    LayoutHelpers.AtVerticalCenterIn(left, bar)
    local function Indicator(after)
        local text = Theme.Text(bar, '', 11, C.muted)
        LayoutHelpers.AtVerticalCenterIn(text, bar)
        if after then
            text.Right:Set(function() return after.Left() - Scale(18) end)
        else
            text.Right:Set(function() return bar.Right() - Scale(16) end)
        end
        local dot = Theme.Dot(bar, 8, C.subtle)
        dot.Right:Set(function() return text.Left() - Scale(6) end)
        LayoutHelpers.AtVerticalCenterIn(dot, bar)
        return { text = text, dot = dot }
    end
    local servers = Indicator(nil)
    local faf = Indicator(servers.dot)
    local status = {}
    status.Update = function(self)
        local s = Online() and launcher.lastStatus or nil
        local mod = s and s.loadedMod ~= '' and ModName(s.loadedMod) or nil
        Theme.SetText(left, 'faf-re in-game launcher' .. (mod and ('  -  game files: ' .. mod) or ''))
        if not s then
            Theme.SetText(faf.text, Online() and 'FAF' or 'FAF: not in this build')
            faf.dot:SetDotColor(C.subtle)
            Theme.SetText(servers.text, '')
            Theme.SetVisible(servers.dot, false)
            return
        end
        local fafState = s.signIn ~= 'signedin' and 'signed out' or (({ off = 'offline', connecting = 'connecting',
            signedin = 'connected', failed = 'failed' })[s.lobby] or s.lobby)
        Theme.SetText(faf.text, 'FAF ' .. fafState)
        faf.dot:SetDotColor(s.lobby == 'signedin' and C.good or (s.lobby == 'failed' and C.bad or
            (s.lobby == 'connecting' and C.warn or C.subtle)))
        local count = s.serverCount or 0
        Theme.SetVisible(servers.dot, count > 0)
        Theme.SetText(servers.text, count > 0 and ('Our servers ' .. (s.servers == 'live' and 'live' or s.servers)) or '')
        servers.dot:SetDotColor(s.servers == 'live' and C.good or (s.servers == 'failed' and C.bad or C.warn))
    end
    return status
end

local function Build(launcher)
    local root = UIUtil.CreateScreenGroup(GetFrame(0), 'Launcher ScreenGroup')
    launcher.root = root
    root.OnDestroy = function()
        launcher:StopSounds()
    end

    Theme.Fill(root, C.page)
    if Prefs.GetOption('mainmenu_bgmovie') then
        local movie = Movie(root)
        movie:Set('/movies/main_menu.sfd')
        LayoutHelpers.AtCenterIn(movie, root)
        movie:Loop(true)
        movie:Play()
        movie.Height:Set(root.Height)
        movie.Width:Set(function() return 1824 * root.Height() / 1024 end)
        movie:DisableHitTest()
        launcher.movie = movie
        -- The game's own space behind the panels, dimmed so the panels read.
        local dim = Theme.Fill(root, 'b8060b10')
        dim.Depth:Set(function() return movie.Depth() + 1 end)
    end

    local body = Group(root, 'launcher body')
    LayoutHelpers.FillParent(body, root)
    body.Depth:Set(function() return root.Depth() + 10 end)
    launcher.body = body

    local rail = BuildRail(launcher, body)
    launcher.status = BuildStatusBar(launcher, body)

    local content = Group(body, 'launcher content')
    content.Left:Set(function() return rail.Right() + Scale(28) end)
    content.Right:Set(function() return body.Right() - Scale(28) end)
    content.Top:Set(function() return body.Top() + Scale(22) end)
    content.Bottom:Set(function() return body.Bottom() - Scale(kStatusHeight + 18) end)

    local onlinePage = Group(content, 'launcher online')
    LayoutHelpers.FillParent(onlinePage, content)
    onlinePage.Width:Set(function() return onlinePage.Right() - onlinePage.Left() end)
    onlinePage.Height:Set(function() return onlinePage.Bottom() - onlinePage.Top() end)
    launcher.pages = { online = onlinePage }
    BuildOnlinePage(launcher, onlinePage)

    -- Updates the page while the launcher shows.
    local ticker = Group(body, 'launcher ticker')
    LayoutHelpers.AtLeftTopIn(ticker, body, 0, 0)
    LayoutHelpers.SetDimensions(ticker, 1, 1)
    ticker:DisableHitTest()
    ticker.elapsed = kRefreshSeconds
    ticker:SetNeedsFrameUpdate(true)
    ticker.OnFrame = function(self, delta)
        self.elapsed = self.elapsed + delta
        if self.elapsed >= kRefreshSeconds then
            self.elapsed = 0
            if not launcher.screen then
                launcher:Refresh()
            end
        end
    end
end

--- Builds the launcher. `buildFafMenu` builds FAF's own main menu (the hook passes it), for its button.
function CreateUI(buildFafMenu)
    UIUtil.SetCurrentSkin('uef')
    import('/lua/ui/game/gamemain.lua').supressExitDialog = false
    -- No profile yet: FAF's profile dialog first, as its main menu does; it comes back through main.lua's CreateUI.
    if not GetPreference('profile.current') then
        import('/lua/ui/dialogs/profile.lua').CreateDialog(function()
            import('/lua/ui/menus/main.lua').CreateUI()
        end)
        return
    end
    Cleanup()
    local launcher = setmetatable({ buildFafMenu = buildFafMenu, page = 'online' }, Launcher)
    current = launcher
    if rawget(_G, 'FafOnline_TakeResume') then
        launcher.resume = FafOnline_TakeResume() or false
        launcher.resumeSince = GetSystemTimeSeconds()
    end
    Build(launcher)
    launcher:ShowPage('online')
    launcher:ShowHome()
    LOG('LAUNCHER: shown')
end

--- The launcher on screen now, or false.
function Current()
    return current
end

-- A join test (FAF_ONLINE_AUTOTEST=join:<seconds>, called by the engine every 2 s until a match starts): picks the
-- first game the online page lists as joinable and presses Join, as a player does. Once per Lua state.
local testJoinDone = false
local testJoinSeen = false
function TestJoin()
    if testJoinDone or not current or current.page ~= 'online' or not current.online or not current.online.grid then
        return
    end
    local view = current.online
    for _, item in view.grid.items do
        if not item.color then
            -- Listed for 14 s first, so the list can be seen (and photographed) as a player sees it; selected after
            -- 2 s, so its details show too.
            if not testJoinSeen then
                testJoinSeen = GetSystemTimeSeconds()
                LOG('LAUNCHER TEST: listed ' .. item.title .. ' (' .. item.uid .. ')')
                return
            elseif GetSystemTimeSeconds() - testJoinSeen < 14 then
                if GetSystemTimeSeconds() - testJoinSeen >= 2 then
                    current:SelectGame(item.key)
                    -- The hover card as the mouse over the first tile shows it, for the screenshot.
                    if view.hover and view.grid.cells[1] and view.grid.cells[1].item then
                        view.hover:Want(view.grid.cells[1].item, view.grid.cells[1])
                    end
                end
                return
            end
            testJoinDone = true
            if view.hover then
                view.hover:Want(nil)
            end
            current:SelectGame(item.key)
            LOG('LAUNCHER TEST: joining ' .. item.title .. ' (' .. item.uid .. ') hosted by ' .. item.host)
            current:JoinSelected()
            return
        end
    end
end

-- A test walk (FAF_ONLINE_AUTOTEST=screens, started by the engine): every screen the launcher opens, opened and
-- closed again, each step logged, then FAF's menu and back, then quit. Once per Lua state.
local testWalkStarted = false
function TestWalk()
    if testWalkStarted or not current then
        return
    end
    testWalkStarted = true
    ForkThread(function()
        local function Step(text)
            LOG('LAUNCHER TEST: ' .. text)
        end
        local function Wait(seconds)
            WaitSeconds(seconds)
        end
        Prefs.SetToCurrentProfile('MenuTutorialPrompt', true)
        Step('home')
        Wait(4)
        -- /launcherreplaytest <file>: a replay of a game version this engine doesn't model is refused with the
        -- switch off and starts with it on (rep_PlayAnyVersion, which the launcher's Replays turns on).
        local replayTest = GetCommandLineArg('/launcherreplaytest', 1)
        if replayTest and replayTest[1] then
            ConExecute('rep_PlayAnyVersion false')
            Step('replay with the switch off: ' .. tostring(LaunchReplaySession(replayTest[1])))
            Wait(1)
            ConExecute('rep_PlayAnyVersion true')
            Step('replay with the switch on: ' .. tostring(LaunchReplaySession(replayTest[1])))
            Wait(6)
            Step('done')
            ExitApplication()
            return
        end
        -- /launchermodtest <mod> <map>: Create game on another featured mod than the loaded one. The game starts
        -- again on that mod's files (with this switch too); the new start hosts the game by itself and quits.
        local modTest = GetCommandLineArg('/launchermodtest', 2)
        if modTest and modTest[2] and Online() then
            -- The restarted game took up the host by itself (the match may already have replaced the launcher).
            local resumed = resumedThisStart
            local status = FafOnline_Status()
            for i = 1, 120 do
                status = FafOnline_Status()
                resumed = resumedThisStart
                if resumed or (status.lobby == 'signedin' and current and not current.resume) then
                    break
                end
                Wait(0.5)
            end
            if resumed then
                Step('after the restart: loaded ' .. status.loadedMod .. ', resumed ' .. resumed)
                for i = 1, 30 do
                    if FafOnline_Status().match ~= 'idle' then
                        break
                    end
                    Wait(0.5)
                end
                Step('match ' .. FafOnline_Status().match .. ' on ' .. FafOnline_Status().loadedMod)
                Wait(3)
                ExitApplication()
                return
            end
            current:ShowPage('online')
            Step('create game on ' .. modTest[1] .. ' from ' .. status.loadedMod)
            local ok, why = current:HostRequest({ title = 'mod switch test', map = modTest[2], mod = modTest[1],
                visibility = 'public', password = '' })
            Step('create game answered ' .. tostring(ok) .. ' ' .. tostring(why))
            Wait(5)
            ExitApplication()
            return
        end
        -- /launchersignintest: Sign in with FAF on the online page; the engine hands the page to the browser, Copy link
        -- puts its address on the clipboard. The test run points the sign-in at a local stand-in (FAF_ONLINE_OAUTH).
        local signInTest = GetCommandLineArg('/launchersignintest', 0)
        if signInTest and Online() then
            current:ShowPage('online')
            local view = current.online
            view.signButton.onClick(view.signButton)
            local status = FafOnline_Status()
            for i = 1, 40 do
                status = FafOnline_Status()
                if status.code ~= '' and status.pageOpen ~= '' and status.pageOpen ~= 'opening' then
                    break
                end
                Wait(0.5)
            end
            Step('sign-in code ' .. status.code .. ', page ' .. status.pageOpen)
            Wait(2)
            Step('sign-in panel shown')
            Wait(3)
            view.copyLink.onClick(view.copyLink)
            Step('copy link pressed')
            Wait(1)
            Step('sign-in panel after copy')
            Wait(2)
            view.openPage.onClick(view.openPage)
            Wait(3)
            Step('page again: ' .. FafOnline_Status().pageOpen)
            FafOnline_CancelSignIn()
            Step('done')
            ExitApplication()
            return
        end
        if Online() and FafOnline_Status().signIn == 'signedin' then
            for i = 1, 20 do
                if FafOnline_Status().lobby == 'signedin' then
                    break
                end
                Wait(1)
            end
            Step('online page, FAF lobby ' .. FafOnline_Status().lobby .. ', ' ..
                table.getn(FafOnline_Games()) .. ' games listed')
            Wait(8)
            Step('online list shown')
            current:OpenHostDialog()
            Wait(2)
            Step(current.hostDialog and 'host dialog open' or 'host dialog did not open')
            if current.hostDialog then
                local panel = current.hostDialog.panel
                local frame = GetFrame(0)
                Step(string.format('host dialog at %d,%d size %dx%d in a %dx%d frame', panel.Left(), panel.Top(),
                    panel.Width(), panel.Height(), frame.Width(), frame.Height()))
                -- Each featured mod: pickable or why not; then FAF Develop picked, when it can be.
                for _, choice in current.hostDialog.modChoices or {} do
                    Step('featured mod ' .. choice.id .. ': ' .. (choice.enabled and 'can be picked' or
                        ('greyed, ' .. tostring(choice.why))))
                    if choice.id == 'fafdevelop' and choice.enabled then
                        choice.onPick(choice)
                    end
                end
                Wait(1)
                Step('featured mod picked')
                -- The mouse over a greyed one: its reason in a tip by it.
                for _, choice in current.hostDialog.modChoices or {} do
                    if not choice.enabled and choice.onDisabledHover then
                        choice.onDisabledHover(true)
                        Wait(1)
                        Step('tip for ' .. choice.id)
                        Wait(2)
                        choice.onDisabledHover(false)
                        break
                    end
                end
            end
            Wait(3)
            if current.hostDialog then
                current.hostDialog:Destroy()
                current.hostDialog = false
                current:SetHomeEscape()
            end
        end
        for _, screen in { 'Skirmish', 'Multiplayer LAN', 'Replays', 'Mods', 'Options' } do
            local launcher = current
            if not launcher then
                Step('the launcher is gone before ' .. screen)
                return
            end
            local open = ({ Skirmish = launcher.Skirmish, ['Multiplayer LAN'] = launcher.Lan,
                Replays = launcher.Replays, Mods = launcher.Mods, Options = launcher.Options })[screen]
            open(launcher)
            Wait(4)
            if screen == 'Skirmish' then
                -- faf-re's lobby screen: what its clicks call, each checked against FAF's lobby state.
                local made, steps = pcall(import('/fafengine/modules/lua/ui/lobby/lobbyview.lua').TestSteps, Step)
                for _, testStep in (made and steps or {}) do
                    local done, why = pcall(testStep)
                    if not done then
                        Step('lobby: step failed: ' .. tostring(why))
                    end
                    Wait(1.5)
                end
                Step('lobby: end state on screen')
                Wait(8)
            end
            Step(screen .. (launcher.screenName == screen and ' open' or ' did not open'))
            if screen == 'Skirmish' then
                -- FAF's own way out of the skirmish lobby (lobby.lua ReturnToMenu, as its Exit button).
                import('/lua/ui/lobby/lobby.lua').ReturnToMenu(false)
            elseif screen == 'Multiplayer LAN' then
                -- Its Back button, which gameselect.lua also binds to Escape.
                import('/lua/ui/uimain.lua').EscapeHandler()
            else
                launcher:CloseScreen()
            end
            Wait(3)
            Step(screen .. (launcher.screen and ' still open' or ' closed, back on the launcher') .. ', open dropdowns ' ..
                Widgets.OpenDropdowns())
            launcher:CloseScreen()
        end
        Step('FAF main menu')
        current:FafMenu()
        Wait(5)
        Step(fafMenuBack and 'FAF main menu open, with the button back' or 'FAF main menu has no button back')
        if fafMenuBack then
            fafMenuBack()
        end
        Wait(3)
        Step(current and 'back on the launcher from FAF\'s main menu' or 'no launcher after FAF\'s main menu')
        Wait(1)
        Step('done')
        ExitApplication()
    end)
end
