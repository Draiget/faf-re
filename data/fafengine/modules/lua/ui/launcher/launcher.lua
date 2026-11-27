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
-- The pages under Play (the top bar's Play tab and its strip of modes).
local kPlayPages = { online = true, matchmaking = true, coop = true, lan = true }
local kVaultPages = { maps = true, mods = true } -- FAF's vault: Maps and Mods, a strip under the top bar like Play's
local kRankPages = { leaderboards = true, tournaments = true } -- Leaderboards and Tournaments, under Leaderboards
local kRefreshSeconds = 0.5

-- One launcher at a time; a new CreateUI replaces it.
local current = false
-- The page shown last: the launcher built again (a UI scale change rebuilds the front end) opens on it.
local lastShownPage = false
-- What a restart on another featured mod took up in this start ('host true', 'join'), for the test walk.
resumedThisStart = false

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

-- ---------------------------------------------------------------------------------------------------------------
-- Profiles. A profile holds the player's options (video, sound, keys, lobby choices), so one is never swapped for a
-- blank one: the FAF login renames the profile in use, or copies it, or switches to the one named after it.

local function Profiles()
    return GetPreference('profile.profiles') or {}
end

local function CurrentProfileIndex()
    local current = GetPreference('profile.current')
    local profiles = Profiles()
    if current and current > 0 and profiles[current] then
        return current
    end
    return nil
end

local function CopyTable(value)
    if type(value) ~= 'table' then
        return value
    end
    local copy = {}
    for key, inner in value do
        copy[key] = CopyTable(inner)
    end
    return copy
end

--- A first start: a profile made at once (FAF's profile dialog asked for a name first). Named after the FAF login
--- once the player signs in.
local function EnsureProfile()
    if CurrentProfileIndex() then
        return
    end
    local profiles = Profiles()
    if table.getn(profiles) > 0 then
        SetPreference('profile.current', 1) -- a damaged current index: the first profile
        LOG('LAUNCHER: profile ' .. tostring(profiles[1].Name) .. ' in use')
        return
    end
    local name = 'Player'
    if Prefs.CreateProfile(name) then
        Prefs.SetToCurrentProfile('fafre_profile_auto', true)
        SavePreferences()
        LOG('LAUNCHER: made the profile ' .. name .. ' (named after the FAF login once signed in)')
    end
end

--- Switches to profile `index` and writes the preferences.
local function UseProfile(index)
    SetPreference('profile.current', index)
    SavePreferences()
    LOG('LAUNCHER: profile ' .. tostring(Profiles()[index] and Profiles()[index].Name) .. ' in use')
end

--- After FAF's sign-in: the profile named after the login in use. One named so already: switched to. Else the profile
--- in use takes the login's name, unless it already belongs to another FAF login; then a copy of it does.
local function ProfileForLogin(login)
    if not login or login == '' then
        return
    end
    local profiles = Profiles()
    local current = CurrentProfileIndex()
    for index, profile in profiles do
        if profile.Name == login then
            if index ~= current then
                UseProfile(index)
            end
            Prefs.SetToCurrentProfile('fafre_profile_login', login)
            return
        end
    end
    if not current then
        if Prefs.CreateProfile(login) then
            Prefs.SetToCurrentProfile('fafre_profile_login', login)
            SavePreferences()
            LOG('LAUNCHER: made the profile ' .. login)
        end
        return
    end
    local profile = profiles[current]
    local owner = profile.fafre_profile_login
    if not owner or owner == login then
        local before = profile.Name
        profile.Name = login
        profile.fafre_profile_login = login
        profile.fafre_profile_auto = nil
        SetPreference('profile.profiles', profiles)
        SavePreferences()
        LOG('LAUNCHER: the profile ' .. tostring(before) .. ' is now ' .. login .. ', named after the FAF login')
        return
    end
    local copy = CopyTable(profile)
    copy.Name = login
    copy.fafre_profile_login = login
    table.insert(profiles, copy)
    SetPreference('profile.profiles', profiles)
    UseProfile(table.getn(profiles))
    LOG('LAUNCHER: made the profile ' .. login .. ' from ' .. tostring(profile.Name) .. ' (that one is ' .. owner .. '\'s)')
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
local Tabs = Widgets.Tabs

local function BuildOnlinePage(launcher, page)
    local view = {}
    launcher.online = view
    -- One list for FAF's games and our servers' games, our servers' first; the heading counts the open ones.
    view.tab = 'all'

    -- Under the top bar's Play strip: the list's own heading, Games with its count (no page title of its own).
    view.tabs = Tabs(page, { { 'all', 'Games' } }, function(key)
        view.grid.top = 1
        launcher:Refresh()
    end)
    view.tabs.Left:Set(page.Left)
    LayoutHelpers.AtTopIn(view.tabs, page, 0)
    view.tabs.Right:Set(page.Right)

    -- The account is in the launcher's top bar.

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
    LayoutHelpers.SetDimensions(signIn, 560, 420)
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
    -- Which FAF server: the main one or FAF's test server, each with a sign-in of its own (FafOnline_SetServer).
    view.serverChoices = {}
    if rawget(_G, 'FafOnline_Server') then
        local servers = FafOnline_Server().servers or {}
        local count = table.getn(servers)
        for i, server in servers do
            local index = i - 1
            local name = server.name
            local choice = Theme.Choice(signIn, name == 'main' and 'Main server' or 'Test server', 150, function()
                launcher:SetServer(name)
            end)
            choice.Left:Set(function()
                return signIn.Left() + math.floor(signIn.Width() / 2) - Scale(count * 80) + Scale(index * 160)
            end)
            LayoutHelpers.AtTopIn(choice, signIn, 292)
            choice.server = name
            table.insert(view.serverChoices, choice)
        end
    end
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
    view.filterList = {}
    local lastFilter = view.search
    -- One row when the button, the search, the filters and the view buttons fit; else the filters go under them.
    local function OneRow()
        local need = view.hostButton.Width() + view.search.Width() + Scale(12 + 18 + 34 + 4 + 34)
        for _, box in view.filterList do
            need = need + box.Width() + Scale(18)
        end
        return need <= games.Width()
    end
    view.toolbarOneRow = OneRow
    for _, entry in { { 'hidePrivate', 'Hide private' }, { 'hideModded', 'Hide sim mods' }, { 'showStarted', 'Show started' } } do
        local key = entry[1]
        local box = Theme.Checkbox(games, entry[2], function(self)
            Prefs.SetToCurrentProfile('fafre_launcher_' .. key, self.on)
            view.grid.top = 1
            launcher:Refresh()
        end)
        box:SetOn(Prefs.GetFromCurrentProfile('fafre_launcher_' .. key) and true or false)
        local after = lastFilter
        local first = after == view.search
        box.Left:Set(function()
            if first and not OneRow() then
                return games.Left()
            end
            return after.Right() + Scale(18)
        end)
        box.Top:Set(function()
            if OneRow() then
                return games.Top() + math.floor((view.hostButton.Height() - box.Height()) / 2)
            end
            return view.hostButton.Bottom() + Scale(12)
        end)
        view.filters[key] = box
        table.insert(view.filterList, box)
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
    listArea.Top:Set(function()
        if OneRow() then
            return view.hostButton.Bottom() + Scale(16)
        end
        return view.filterList[1].Bottom() + Scale(14)
    end)
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

    -- What the list says when it has no games (loading, a failure and why): wrapped and centred, at most 640 wide.
    view.empty = Theme.Paragraph(listArea, 14, C.subtle)
    view.empty.centered = true
    local function Margin()
        return math.max(0, math.floor((listArea.Right() - listArea.Left() - Scale(640)) / 2))
    end
    view.empty.Left:Set(function() return listArea.Left() + Margin() end)
    view.empty.Right:Set(function() return listArea.Right() - Margin() end)
    view.empty.Top:Set(function()
        return listArea.Top() + math.floor((listArea.Bottom() - listArea.Top() - view.empty.Height()) / 2)
    end)
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
    if signedIn and status.login ~= '' and launcher.profileLogin ~= status.login then
        launcher.profileLogin = status.login
        local ok, why = pcall(ProfileForLogin, status.login)
        if not ok then
            WARN('LAUNCHER: the profile for ' .. status.login .. ' failed: ' .. tostring(why))
        end
    end
    local lobbyText = ({ off = 'not connected', connecting = 'connecting', signedin = 'FAF lobby connected',
        failed = 'FAF lobby failed' })[status.lobby] or status.lobby
    if status.server == 'test' then
        lobbyText = string.gsub(lobbyText, 'FAF lobby', 'test server')
    end
    for _, choice in view.serverChoices or {} do
        choice.selected = choice.server == (status.server or 'main')
        choice:Paint(false)
    end

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
        if status.lobbyKicked then
            -- Signed in elsewhere (FAF's own client, another game): Try again takes the session back.
            empty = string.gsub(why, '%.$', '') .. '. Try again takes this game back online.'
        else
            empty = 'No connection to the ' .. (status.server == 'test' and "FAF test server's lobby" or 'FAF lobby') ..
                (why ~= '' and (': ' .. why) or '') .. '.'
            if (status.lobbyRetryIn or 0) > 0 then
                empty = empty .. string.format(' Trying again in %d s.', status.lobbyRetryIn)
            end
        end
    elseif table.getn(items) == 0 then
        if filter ~= '' or hidePrivate or hideModded then
            empty = 'No game matches the search and filters.'
        else
            empty = 'No open games right now. Create one.'
        end
    end
    if view.emptyText ~= empty or view.emptyFailed ~= (status.lobby == 'failed') then
        view.emptyText = empty
        view.emptyFailed = status.lobby == 'failed'
        view.empty:SetText(empty, status.lobby == 'failed' and C.bad or C.subtle)
    end
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
    -- Under the search: how many players, how big, in which order (remembered between dialogs).
    local mapPlayers = Prefs.GetFromCurrentProfile('fafre_host_map_players') or 0
    local mapSize = Prefs.GetFromCurrentProfile('fafre_host_map_size') or 0
    local mapSort = Prefs.GetFromCurrentProfile('fafre_host_map_sort') or 'name'
    local kPlayerChoices = { { 'Any players', 0 }, { '2 players', 2 }, { '4 players', 4 }, { '6 players', 6 },
        { '8 players', 8 }, { '10+ players', 10 } }
    local kSizeChoices = { { 'Any size', 0 }, { '5 km', 5 }, { '10 km', 10 }, { '20 km', 20 }, { '40 km', 40 },
        { '81 km', 81 } }
    local kSortChoices = { { 'By name', 'name' }, { 'By players', 'players' }, { 'By size', 'size' } }
    local function ChoiceText(choices, value)
        for _, choice in choices do
            if choice[2] == value then
                return choice[1]
            end
        end
        return choices[1][1]
    end
    local FillMaps -- below
    local mapList -- below
    local function Selector(choices, get, set, key, index)
        local button
        button = Theme.Button(panel, ChoiceText(choices, get()), function()
            local items = {}
            for _, choice in choices do
                table.insert(items, { choice[1], key = choice[2], color = choice[2] == get() and C.accent or C.text })
            end
            Widgets.Dropdown(button, items, function(item)
                set(item.key)
                Prefs.SetToCurrentProfile(key, item.key)
                button:SetLabel(item[1])
                mapList.top = 1
                FillMaps()
            end, { width = 140 })
        end, 'secondary', { width = 106, icon = 'chevronDown', size = 12 })
        button.Left:Set(function() return mapLeft() + Scale((index - 1) * 112) end)
        button.Top:Set(function() return mapSearch.Bottom() + Scale(8) end)
        return button
    end

    local paths = {}
    for _, path in DiskFindFiles('/maps', '*_scenario.lua') do
        table.insert(paths, path)
    end
    table.sort(paths)
    local last = Prefs.GetFromCurrentProfile('fafre_host_map') or Prefs.GetFromCurrentProfile('LastScenario') or
        UIUtil.defaultScenario
    -- Each map's name, players and size from its scenario, read once per dialog (all of them: the filters need them).
    local names = {}
    local facts = {}
    local function Facts(path)
        if facts[path] == nil then
            local ok, scenario = pcall(import('/lua/ui/maputil.lua').LoadScenario, path)
            local fact = { players = 0, km = 0 }
            if ok and scenario then
                names[path] = scenario.name and LOC(scenario.name) or false
                if scenario.size then
                    fact.km = math.floor(math.max(scenario.size[1], scenario.size[2]) / 51.2 + 0.5)
                end
                local standard = scenario.Configurations and scenario.Configurations.standard
                if standard and standard.teams and standard.teams[1] then
                    fact.players = table.getn(standard.teams[1].armies or {})
                end
            else
                names[path] = false
            end
            facts[path] = fact
        end
        return facts[path]
    end
    local function NameOf(path)
        Facts(path)
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
    mapList = VirtualList(panel, {
        { 'Map', 0.42, function(item) return NameOf(item.path) end },
        { 'Players', 0.18, function(item) return Facts(item.path).players > 0 and tostring(Facts(item.path).players) or '' end,
            C.muted },
        { 'Size', 0.14, function(item) return Facts(item.path).km > 0 and (Facts(item.path).km .. ' km') or '' end,
            C.muted },
        { 'Folder', 0.26, function(item) return item.folder end, C.subtle },
    }, function(item, double)
        ShowMap(item)
    end)
    mapList.Left:Set(mapLeft)
    mapList.Right:Set(right)
    mapList.Top:Set(function() return mapSearch.Bottom() + Scale(8 + 34 + 10) end)
    mapList.Bottom:Set(function() return panel.Bottom() - Scale(76) end)
    mapList.selectedKey = last
    FillMaps = function()
        local filter = string.lower(mapSearch.edit:GetText())
        local items = {}
        for _, path in paths do
            local folder = MapFolder(path)
            local fact = Facts(path)
            local players = mapPlayers == 0 or (mapPlayers >= 10 and fact.players >= 10) or fact.players == mapPlayers
            local size = mapSize == 0 or fact.km == mapSize
            if folder and players and size and (filter == '' or string.find(folder, filter, 1, true) or
                string.find(string.lower(names[path] or ''), filter, 1, true)) then
                table.insert(items, { key = path, path = path, folder = folder, name = string.lower(NameOf(path)),
                    players = fact.players, km = fact.km })
            end
        end
        table.sort(items, function(a, b)
            if mapSort == 'players' and a.players ~= b.players then
                return a.players > b.players
            elseif mapSort == 'size' and a.km ~= b.km then
                return a.km > b.km
            end
            return a.name < b.name
        end)
        mapList:SetItems(items)
    end
    cover.mapList = mapList -- for the test walk
    cover.FilterMaps = function(players, size, sort)
        mapPlayers, mapSize, mapSort = players, size, sort
        FillMaps()
    end
    Selector(kPlayerChoices, function() return mapPlayers end, function(v) mapPlayers = v end, 'fafre_host_map_players', 1)
    Selector(kSizeChoices, function() return mapSize end, function(v) mapSize = v end, 'fafre_host_map_size', 2)
    Selector(kSortChoices, function() return mapSort end, function(v) mapSort = v end, 'fafre_host_map_sort', 3)
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
    -- Only the page on screen: a page's refresh shows its own pieces, and a piece shown under a hidden page still
    -- draws over the one on screen.
    local ok, err = true, nil
    if self.page == 'online' then
        ok, err = pcall(RefreshOnline, self)
    end
    if not ok and not self.refreshFailed then
        self.refreshFailed = true
        WARN('LAUNCHER: the online page failed to update: ' .. tostring(err))
    end
    local pageView = (self.page == 'replays' and self.replaysView) or (self.page == 'mods' and self.modsView) or
        (self.page == 'lan' and self.lanView) or (self.page == 'chat' and self.chatView) or
        (self.page == 'matchmaking' and self.matchView) or (self.page == 'coop' and self.coopView) or
        (self.page == 'maps' and self.mapsView) or (self.page == 'leaderboards' and self.leaderboardsView) or (self.page == 'units' and self.unitsView) or (self.page == 'news' and self.newsView) or (self.page == 'tournaments' and self.tournamentsView) or
        (self.page == 'changelog' and self.changelogView) or (self.page == 'options' and self.optionsView) or nil
    if pageView then
        local done, why = pcall(pageView.Refresh, pageView)
        if not done and not self.pageFailed then
            self.pageFailed = true
            WARN('LAUNCHER: the ' .. self.page .. ' page failed to update: ' .. tostring(why))
        end
    end
    if self.status then
        self.status:Update()
    end
    if self.topBar then
        self.topBar:Update(self.lastStatus)
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
    self:PlaceContent()
    -- Show on the body showed every piece a control keeps hidden (check marks, brackets): each paints itself again.
    Theme.RepaintAll()
    for _, list in { self.navItems or {}, self.utilityItems or {} } do
        for _, item in list do
            item:Paint(false)
        end
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

--- The changelog's game preview of one unit card (changelog.lua): a sandbox skirmish on a small map (no fog, no
--- victory) where the unit as it is now stands beside a copy with the card's changed values put back, both shooting at
--- targets, their ranges drawn on the ground (/fafengine/modules/lua/sim/unitpreview.lua). The game's own Exit, the
--- overlay's Back or Esc come back to the launcher, on the changelog.
local kPreviewMap = '/maps/SCMP_013/SCMP_013_scenario.lua' -- Winter Duel: 5 km, two armies, land in the middle
local kFactionOfLetter = { e = 1, a = 2, r = 3, s = 4 }

function Launcher:PreviewUnit(head, version)
    local ok, why = pcall(function()
        local id = string.lower(head.id or '')
        local scenario = import('/lua/ui/maputil.lua').LoadScenario(kPreviewMap)
        if not scenario then
            error('the map ' .. kPreviewMap .. ' is missing')
        end
        local changes = {}
        for _, stat in (head.stats or {}) do
            table.insert(changes, { label = stat.label, old = stat.old, new = stat.new, oldText = stat.oldText,
                newText = stat.newText })
        end
        scenario.Options = {
            FogOfWar = 'none', NoRushOption = 'Off', PrebuiltUnits = 'Off', Difficulty = 2, DoNotShareUnitCap = true,
            Timeouts = -1, GameSpeed = 'normal', UnitCap = '1000', Victory = 'sandbox', CheatsEnabled = 'true',
            CivilianAlliance = 'enemy', TeamShareOverflow = 'enabled', Share = 'ShareUntilDeath',
            FafrePreview = { unit = id, name = head.name, version = version and tostring(version) or nil, changes = changes },
        }
        local GetDefaultPlayerOptions = import('/lua/ui/lobby/lobbycomm.lua').GetDefaultPlayerOptions
        local playerName = Prefs.GetFromCurrentProfile('Name') or 'Player'
        local player = GetDefaultPlayerOptions(playerName)
        player.PlayerName = playerName
        player.Human = true
        player.ArmyName = 'ARMY_1'
        player.Faction = kFactionOfLetter[string.sub(id, 2, 2)] or 1
        player.PlayerColor = 1
        player.ArmyColor = 1
        local targets = GetDefaultPlayerOptions('Targets')
        targets.PlayerName = 'Targets'
        targets.Human = false
        targets.Civilian = true
        targets.ArmyName = 'ARMY_2'
        targets.PlayerColor = 2
        targets.ArmyColor = 2
        LOG('LAUNCHER: previewing ' .. id .. ' with ' .. table.getn(changes) .. ' changed values')
        LaunchSinglePlayerSession({ playerName = playerName, createReplay = false, scenarioInfo = scenario,
            teamInfo = { player, targets }, scenarioMods = import('/lua/mods.lua').GetCampaignMods(scenario) })
    end)
    if not ok then
        WARN('LAUNCHER: the preview did not start: ' .. tostring(why))
        Message(self.root, 'Preview in game', 'The preview did not start: ' .. tostring(why))
    end
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

--- The LAN page (lanpage.lua): games on this network, hosting, an address. FAF's own LAN screen stays for a build
--- where the page failed to build.
function Launcher:Lan()
    if self.pages.lan then
        self:ShowPage('lan')
        return
    end
    self:OpenScreen('Multiplayer LAN', function(host, back)
        import('/lua/ui/lobby/gameselect.lua').CreateUI(host, back)
    end)
end

--- The Replays page (replays.lua): this computer's replays and FAF's replay vault. FAF's own replay screen is still
--- there for a build without the engine's replay library.
function Launcher:Replays()
    if self.pages.replays then
        self:ShowPage('replays')
        return
    end
    ConExecute('rep_PlayAnyVersion true')
    self:OpenScreen('Replays', function(host, back)
        import('/lua/ui/dialogs/replay.lua').CreateDialog(host, true, back)
    end)
end

--- Plays on FAF's main or test server from now on: the online service starts again on it, signed in with that server's
--- own saved sign-in when there is one (else the sign-in card asks). Refused while a game runs.
function Launcher:SetServer(name)
    local ok, why = FafOnline_SetServer(name)
    if not ok then
        Message(self.root, 'FAF server', 'The server stays as it is: ' .. tostring(why) .. '.')
        return
    end
    LOG('LAUNCHER: playing on the FAF ' .. tostring(name) .. ' server')
    self.profileLogin = nil
    self:ShowPage('online')
end

--- A FAF player's profile over the launcher (profile.lua): ratings, rating history, maps, previous names, clan.
function Launcher:ShowProfile(login)
    local ok, err = pcall(function()
        import('/fafengine/modules/lua/ui/launcher/profile.lua').Open(self, login)
    end)
    if not ok then
        WARN('LAUNCHER: the profile of ' .. tostring(login) .. ' failed to open: ' .. tostring(err))
        Message(self.root, 'Player profile', 'The profile failed to open: ' .. tostring(err))
    end
end

--- The profiles in a menu under `anchor`: the player's own FAF profile, each game profile to switch to (the one in
--- use marked), and FAF's profile manager.
function Launcher:ProfileMenu(anchor)
    local items = {}
    local status = self.lastStatus or {}
    if status.login and status.login ~= '' then
        table.insert(items, { 'My FAF profile', key = 'faf', color = C.accent })
    end
    if rawget(_G, 'FafOnline_SetServer') then
        local other = status.server == 'test' and 'main' or 'test'
        table.insert(items, { other == 'test' and 'Play on the FAF test server' or 'Back to the FAF main server',
            key = 'server:' .. other, color = C.warn })
    end
    local current = CurrentProfileIndex()
    for index, profile in Profiles() do
        table.insert(items, { (index == current and 'Profile: ' or 'Switch to ') .. tostring(profile.Name), key = index,
            color = index == current and C.accent or C.text })
    end
    table.insert(items, { 'Manage profiles...', key = 'manage', color = C.muted })
    local launcher = self
    Widgets.Dropdown(anchor, items, function(item)
        if item.key == 'faf' then
            launcher:ShowProfile(status.login)
        elseif type(item.key) == 'string' and string.sub(item.key, 1, 7) == 'server:' then
            launcher:SetServer(string.sub(item.key, 8))
        elseif item.key == 'manage' then
            launcher:OpenScreen('Profiles', function(host, back)
                import('/lua/ui/dialogs/profile.lua').CreateDialog(function()
                    ForkThread(back)
                end, host)
            end)
        elseif item.key ~= current then
            UseProfile(item.key)
            launcher:Refresh()
        end
    end, { width = 240 })
end

--- Watches a replay file (a FAF replay is decoded first), as FAF's replay screen launches one. False and why when the
--- game can't start it.
function Launcher:WatchReplay(path)
    -- Replays of any FAF game version play, with the engine patches of the nearest version this engine models
    -- (rep_PlayAnyVersion, as /noversioncheck); their own game files at runtime come later.
    ConExecute('rep_PlayAnyVersion true')
    local ok, playable = FafLibrary_PrepareReplay(path)
    if not ok then
        return false, playable
    end
    LOG('LAUNCHER: watching ' .. tostring(playable))
    if LaunchReplaySession(playable) ~= true then
        return false, 'the game couldn\'t start this replay'
    end
    SetFrontEndData('replay_filename', playable)
    self:StopSounds()
    import('/fafengine/modules/lua/ui/uiscale.lua').SetMainMenuVisible(false)
    Cleanup()
    import('/lua/ui/menus/menucommon.lua').MenuCleanup()
    return true
end

--- The Mods page (modspage.lua): installed mods and FAF's mod vault. FAF's own mod manager is still there for a build
--- without the engine's mod library.
function Launcher:Mods()
    if self.pages.mods then
        self:ShowPage('mods')
        return
    end
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

--- The Options page (optionspage.lua); FAF's options dialog for a launcher built without it.
function Launcher:Options()
    if self.pages.options then
        self:ShowPage('options')
        return
    end
    local UiScale = import('/fafengine/modules/lua/ui/uiscale.lua')
    self:OpenScreen('Options', function(host, back)
        UiScale.SetOptionsFromMainMenu(true)
        import('/lua/ui/dialogs/options.lua').CreateDialog(host, function()
            UiScale.SetOptionsFromMainMenu(false)
            back()
        end)
    end)
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

--- Play's strip on Play's pages (custom games, LAN), the content under it; the full height under the bar elsewhere.
function Launcher:PlaceContent()
    local bar, content = self.topBar, self.content
    if not bar or not self.playStrip or not content then
        return
    end
    local shown = nil
    for _, entry in { { self.playStrip, kPlayPages }, { self.vaultStrip, kVaultPages }, { self.rankStrip, kRankPages } } do
        local strip, pages = entry[1], entry[2]
        if strip then
            local mine = pages[self.page or ''] and true or false
            Theme.SetVisible(strip, mine)
            if mine then
                strip.tabs:Set(self.page, {})
                shown = strip
            end
        end
    end
    if kVaultPages[self.page or ''] then
        self.lastVaultPage = self.page
    end
    if kRankPages[self.page or ''] then
        self.lastRankPage = self.page
    end
    if shown then
        content.Top:Set(function() return shown.Bottom() + Scale(14) end)
    else
        content.Top:Set(function() return bar.Bottom() + Scale(22) end)
    end
end

function Launcher:ShowPage(name)
    -- The LAN page listens for games only while it shows.
    if self.page == 'lan' and name ~= 'lan' and self.lanView then
        self.lanView:Stop()
    end
    self.page = name
    lastShownPage = name
    for pageName, page in self.pages do
        Theme.SetVisible(page, pageName == name)
    end
    self:PlaceContent()
    -- The Show showed every piece the page keeps hidden (brackets of disabled buttons, tips, the hover card).
    Theme.RepaintAll()
    for _, list in { self.navItems or {}, self.utilityItems or {} } do
        for _, item in list do
            item:Paint(false)
        end
    end
    self:Refresh()
end

-- ---------------------------------------------------------------------------------------------------------------
-- The bar along the top: the game's name, one tab per part of the launcher (always there, in the same places), and
-- the player's account with Exit at its right. Play's own modes are a strip under it on Play's pages.

local kBarHeight = 64

local function TopTab(launcher, bar, iconName, label, action, pages)
    local item = Group(bar)
    LayoutHelpers.SetHeight(item, kBarHeight)
    item.Top:Set(bar.Top)
    local back = Theme.Fill(item, C.clear)
    back.Depth:Set(function() return item.Depth() end)
    local icon = Theme.Icon(item, iconName, 18, C.muted)
    LayoutHelpers.AtLeftIn(icon, item, 14)
    LayoutHelpers.AtVerticalCenterIn(icon, item)
    local text = Theme.Text(item, string.upper(label), 13, C.muted, true)
    text.Left:Set(function() return icon.Right() + Scale(8) end)
    LayoutHelpers.AtVerticalCenterIn(text, item)
    local underline = Theme.Rect(item, C.accent)
    -- Under the icon and text (the icon alone when compact), the same overhang each side.
    underline.Left:Set(function() return icon.Left() - Scale(6) end)
    underline.Bottom:Set(item.Bottom)
    underline.Height:Set(Scale(3))
    underline.Width:Set(function() return underline.Right() - underline.Left() end)
    underline:DisableHitTest()
    --- Compact: the icon only (its name in a tip on hover), for a bar too narrow for every name.
    item.SetCompact = function(self, compact)
        self.compact = compact and true or false
        if self.compact then
            self.Width:Set(function() return Scale(14 + 18 + 14) end) -- margins and the icon: placed from either edge
            underline.Right:Set(function() return icon.Right() + Scale(6) end)
        else
            self.Width:Set(function() return self:FullWidth() end)
            underline.Right:Set(function() return text.Right() + Scale(6) end)
        end
        self:Paint(false)
    end
    --- The width with its name shown: icon, gap, name and the margins.
    item.FullWidth = function(self)
        return text.Width() + Scale(14 + 18 + 8 + 14)
    end
    item.label = label
    item.Paint = function(self, over)
        local chosen = pages and pages[launcher.page or ''] or false
        back:SetSolidColor(chosen and Theme.WithAlpha(C.accent, 0.08) or (over and C.raised or C.clear))
        Theme.SetVisible(underline, chosen)
        Theme.SetVisible(text, not self.compact)
        local color = chosen and C.accent or (over and C.text or C.muted)
        Theme.SetColor(text, color)
        icon:SetIcon(iconName, color)
    end
    Theme.HitArea(item, function(self, event)
        if event.Type == 'MouseEnter' then
            Theme.HoverSound()
            item:Paint(true)
            if item.compact and launcher.topTip then
                launcher.topTip:Say(label, C.text, item)
            end
        elseif event.Type == 'MouseExit' then
            item:Paint(false)
            if launcher.topTip then
                launcher.topTip:Quiet()
            end
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            Theme.ClickSound()
            action()
            return true
        end
        return false
    end)
    Theme.Paintable(item)
    item:SetCompact(false)
    return item
end

local function BuildTopBar(launcher, body)
    local bar = Theme.Rect(body, C.rail)
    bar.Left:Set(body.Left)
    bar.Right:Set(body.Right)
    bar.Top:Set(body.Top)
    bar.Height:Set(Scale(kBarHeight))
    bar.Width:Set(function() return bar.Right() - bar.Left() end)
    bar:DisableHitTest()
    local line = Theme.Rect(body, C.line)
    line.Left:Set(bar.Left)
    line.Right:Set(bar.Right)
    line.Top:Set(bar.Bottom)
    line.Height:Set(1)
    line.Width:Set(function() return line.Right() - line.Left() end)
    line:DisableHitTest()

    -- The game's name: the emblem, "Forged Alliance" in the title font, what this is under it.
    local brand = Theme.Emblem(bar, 36, C.accent)
    LayoutHelpers.AtLeftIn(brand, bar, 24)
    LayoutHelpers.AtVerticalCenterIn(brand, bar)
    local name = Theme.Title(bar, 'Forged Alliance', 13, C.text)
    name.Left:Set(function() return brand.Right() + Scale(12) end)
    name.Top:Set(function() return bar.Top() + Scale(16) end)
    local versionOk, version = pcall(function() return import('/lua/version.lua').GetVersion() end)
    local subtitle = Theme.Text(bar, 'Reconstructed Engine  -  ' .. (versionOk and tostring(version) or '?'), 11, C.subtle)
    subtitle.Left:Set(name.Left)
    subtitle.Top:Set(function() return name.Bottom() + Scale(4) end)

    local entries = {
        { 'play', 'Play', function() launcher:ShowPage('online') end, kPlayPages },
        { 'chat', 'Chat', function() launcher:ShowPage('chat') end, { chat = true } },
        { 'leaderboard', 'Leaderboards', function()
            launcher:ShowPage(launcher.lastRankPage == 'tournaments' and launcher.pages.tournaments and 'tournaments' or
                'leaderboards')
        end, kRankPages },
        { 'replays', 'Replays', function() launcher:Replays() end, { replays = true } },
        { 'folder', 'Vault', function()
            if launcher.lastVaultPage == 'mods' or not (launcher.pages and launcher.pages.maps) then
                launcher:Mods()
            else
                launcher:ShowPage('maps')
            end
        end, kVaultPages },
        { 'units', 'Units', function() launcher:ShowPage('units') end, { units = true } },
        -- Utilities: icons by the account, their names in a tip.
        { 'news', 'News', function() launcher:ShowPage('news') end, { news = true }, true },
        { 'changelog', 'Changelog', function() launcher:ShowPage('changelog') end, { changelog = true }, true },
        { 'settings', 'Settings', function() launcher:Options() end, { options = true }, true },
    }
    launcher.navItems = {}
    launcher.utilityItems = {}
    local before = nil
    for _, entry in entries do
        if (entry[1] ~= 'chat' or rawget(_G, 'FafChat_Status')) and
            (entry[1] ~= 'leaderboard' or rawget(_G, 'FafLibrary_Api')) and
            (entry[1] ~= 'news' or rawget(_G, 'FafLibrary_News')) then
            local item = TopTab(launcher, bar, entry[1], entry[2], entry[3], entry[4])
            if entry[5] then
                item:SetCompact(true)
                table.insert(launcher.utilityItems, item)
            else
                local after = before
                item.Left:Set(function()
                    return after and after.Right() or math.max(subtitle.Right(), name.Right()) + Scale(36)
                end)
                table.insert(launcher.navItems, item)
                before = item
            end
        end
    end

    -- The account at the right: avatar, name and where the FAF connection stands; a click opens the account menu.
    local exit = Theme.Button(bar, '', function() launcher:Exit() end, 'ghost', { icon = 'logout', width = 40 })
    exit.Right:Set(function() return bar.Right() - Scale(16) end)
    LayoutHelpers.AtVerticalCenterIn(exit, bar)
    local account = Group(bar)
    LayoutHelpers.SetHeight(account, 44)
    account.Right:Set(function() return exit.Left() - Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(account, bar)
    account.Width:Set(Scale(260))
    local avatar = Theme.Avatar(account, '', 32)
    avatar.Right:Set(account.Right)
    LayoutHelpers.AtVerticalCenterIn(avatar, account)
    local who = Theme.Text(account, '', 14, C.text, true)
    who.Right:Set(function() return avatar.Left() - Scale(10) end)
    LayoutHelpers.AtTopIn(who, account, 4)
    local note = Theme.Text(account, '', 11, C.muted)
    note.Right:Set(who.Right)
    LayoutHelpers.AtTopIn(note, account, 24)
    -- The utilities right of the tabs, left of the account's name (which grows with the login).
    local utilities = launcher.utilityItems
    for i = table.getn(utilities), 1, -1 do
        local item = utilities[i]
        local after = utilities[i + 1]
        item.Right:Set(function()
            return after and after.Left() or (math.min(who.Left(), note.Left()) - Scale(20))
        end)
        item.Left:Set(function() return item.Right() - item.Width() end)
    end
    local function TabsEnd()
        return utilities[1] and utilities[1].Left() or math.min(who.Left(), note.Left())
    end
    Theme.HitArea(account, function(self, event)
        if event.Type == 'ButtonPress' and event.Modifiers.Left then
            Theme.ClickSound()
            launcher:ProfileMenu(avatar)
            return true
        end
        return false
    end)
    bar.Update = function(self, status)
        local signedIn = status and status.signIn == 'signedin'
        avatar:SetLogin(signedIn and status.login or '')
        Theme.SetText(who, signedIn and status.login or 'Not signed in')
        local lobby = status and (({ off = 'not connected', connecting = 'connecting', signedin = 'connected',
            failed = 'lobby failed' })[status.lobby] or status.lobby) or ''
        local server = status and status.server == 'test' and 'FAF test server' or 'FAF'
        Theme.SetText(note, signedIn and (server .. ' ' .. lobby) or 'Sign in on Play')
        Theme.SetColor(note, status and status.lobby == 'failed' and C.bad or C.muted)
        -- Every tab's name when they fit between the game's name and the account (whose width follows the login),
        -- else icons only.
        local items = launcher.navItems or {}
        if items[1] then
            local need = 0
            for _, item in items do
                need = need + item:FullWidth()
            end
            local room = TabsEnd() - Scale(24) - items[1].Left()
            local compact = need > room
            if compact ~= launcher.compactTabs then
                launcher.compactTabs = compact
                for _, item in items do
                    item:SetCompact(compact)
                end
                LOG('LAUNCHER: top bar tabs ' .. (compact and 'as icons' or 'with their names') .. ' (' ..
                    math.floor(need) .. ' of ' .. math.floor(room) .. ' px)')
            end
        end
    end
    launcher.topTip = Theme.Tip(bar, 140)
    bar.Update(bar, nil)

    -- Play's modes: custom games (FAF's and our servers'), skirmish, campaign, LAN.
    local strip = Group(body)
    strip.Left:Set(function() return body.Left() + Scale(36) end)
    strip.Right:Set(function() return body.Right() - Scale(36) end)
    strip.Top:Set(function() return bar.Bottom() + Scale(10) end)
    LayoutHelpers.SetHeight(strip, 40)
    strip.Width:Set(function() return strip.Right() - strip.Left() end)
    strip.tabs = Widgets.Tabs(strip, {
        { 'online', 'Custom games' }, { 'matchmaking', 'Matchmaking' }, { 'coop', 'Co-op' }, { 'skirmish', 'Skirmish' },
        { 'campaign', 'Campaign' }, { 'lan', 'LAN' },
    }, function(key)
        if key == 'matchmaking' or key == 'coop' then
            launcher:ShowPage(key)
        elseif key == 'skirmish' then
            launcher:Skirmish()
        elseif key == 'campaign' then
            launcher:Campaign()
        elseif key == 'lan' then
            launcher:Lan()
        else
            launcher:ShowPage('online')
        end
    end)
    strip.tabs.Left:Set(strip.Left)
    strip.tabs.Top:Set(strip.Top)
    strip.tabs.Right:Set(strip.Right)
    launcher.playStrip = strip
    bar.strip = strip

    -- The vault's parts: maps and mods.
    local vault = Group(body)
    vault.Left:Set(strip.Left)
    vault.Right:Set(strip.Right)
    vault.Top:Set(strip.Top)
    LayoutHelpers.SetHeight(vault, 40)
    vault.Width:Set(function() return vault.Right() - vault.Left() end)
    local vaultEntries = {}
    if rawget(_G, 'FafLibrary_InstallMap') then -- the maps page needs the engine's map installs
        table.insert(vaultEntries, { 'maps', 'Maps' })
    end
    table.insert(vaultEntries, { 'mods', 'Mods' })
    vault.tabs = Widgets.Tabs(vault, vaultEntries, function(key)
        if key == 'maps' then
            launcher:ShowPage('maps')
        else
            launcher:Mods()
        end
    end)
    vault.tabs.Left:Set(vault.Left)
    vault.tabs.Top:Set(vault.Top)
    vault.tabs.Right:Set(vault.Right)
    Theme.SetVisible(vault, false)
    launcher.vaultStrip = vault

    -- Rankings: the ladders and FAF's tournaments.
    local rank = Group(body)
    rank.Left:Set(strip.Left)
    rank.Right:Set(strip.Right)
    rank.Top:Set(strip.Top)
    LayoutHelpers.SetHeight(rank, 40)
    rank.Width:Set(function() return rank.Right() - rank.Left() end)
    rank.tabs = Widgets.Tabs(rank, { { 'leaderboards', 'Leaderboards' }, { 'tournaments', 'Tournaments' } }, function(key)
        launcher:ShowPage(key)
    end)
    rank.tabs.Left:Set(rank.Left)
    rank.tabs.Top:Set(rank.Top)
    rank.tabs.Right:Set(rank.Right)
    Theme.SetVisible(rank, false)
    launcher.rankStrip = rank
    return bar
end

-- ---------------------------------------------------------------------------------------------------------------
-- The rail on the left: where everything starts.

local function NavItem(launcher, rail, iconName, label, action, page)
    local item = Group(rail)
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

    -- The emblem, and the game's name under it: "Supreme Commander:" over "Forged Alliance" in the title font, then
    -- what this is and the game version.
    local brand = Theme.Emblem(rail, 52, C.accent)
    LayoutHelpers.AtLeftTopIn(brand, rail, 24, 20)
    local nameTop = Theme.Text(rail, 'Supreme Commander:', 12, C.muted)
    nameTop.Left:Set(function() return rail.Left() + Scale(24) end)
    nameTop.Top:Set(function() return brand.Bottom() + Scale(8) end)
    local name = Theme.Title(rail, 'Forged Alliance', 14, C.text)
    name.Left:Set(nameTop.Left)
    name.Top:Set(function() return nameTop.Bottom() + Scale(2) end)
    local versionOk, version = pcall(function() return import('/lua/version.lua').GetVersion() end)
    local subtitle = Theme.Text(rail, 'Reconstructed Engine', 12, C.accent)
    subtitle.Left:Set(nameTop.Left)
    subtitle.Top:Set(function() return name.Bottom() + Scale(4) end)
    local versionText = Theme.Text(rail, 'Game version ' .. (versionOk and tostring(version) or '?'), 11, C.subtle)
    versionText.Left:Set(nameTop.Left)
    versionText.Top:Set(function() return subtitle.Bottom() + Scale(2) end)

    local entries = {
        'Online',
        { 'play', 'Multiplayer', function() launcher:ShowPage('online') end, 'online' },
        { 'chat', 'Chat', function() launcher:ShowPage('chat') end, 'chat' },
        'Offline',
        { 'flag', 'Skirmish', function() launcher:Skirmish() end },
        { 'book', 'Campaign', function() launcher:Campaign() end },
        { 'users', 'LAN', function() launcher:Lan() end, 'lan' },
        'Library',
        { 'replays', 'Replays', function() launcher:Replays() end, 'replays' },
        { 'mods', 'Mods', function() launcher:Mods() end, 'mods' },
        'Game',
        { 'settings', 'Options', function() launcher:Options() end, 'options' },
        { 'changelog', 'Changelog', function() launcher:ShowPage('changelog') end, 'changelog' },
        { 'logout', 'Exit', function() launcher:Exit() end },
    }
    -- How the rail fits the window's height (unscaled): the full rail, tighter steps, no name under the emblem, no
    -- captions. tops[level][i] is entry i's top.
    local levels = {
        { top = 178, caption = 28, item = 38, name = true, captions = true },
        { top = 178, caption = 22, item = 31, name = true, captions = true },
        { top = 84, caption = 22, item = 30, name = false, captions = true },
        { top = 84, caption = 6, item = 30, name = false, captions = false },
    }
    local tops = {}
    for level, spec in levels do
        tops[level] = {}
        local top = spec.top
        for i, entry in entries do
            tops[level][i] = top
            top = top + (type(entry) == 'string' and spec.caption or spec.item)
        end
        spec.need = top + 8
    end
    local function Level()
        local height = LayoutHelpers.InvScaleNumber(rail.Height())
        for level, spec in levels do
            if height >= spec.need then
                return level
            end
        end
        return table.getn(levels)
    end
    local captions = {}
    launcher.navItems = {}
    for i, entry in entries do
        local index = i
        if type(entry) == 'string' then
            local caption = Theme.Caption(rail, entry)
            caption.Left:Set(function() return rail.Left() + Scale(24) end)
            caption.Top:Set(function() return rail.Top() + Scale(tops[Level()][index] + 8) end)
            table.insert(captions, caption)
        else
            local item = NavItem(launcher, rail, entry[1], entry[2], entry[3], entry[4])
            item.Left:Set(rail.Left)
            item.Top:Set(function() return rail.Top() + Scale(tops[Level()][index]) end)
            item.Height:Set(function() return Scale(levels[Level()].item) end)
            item.Right:Set(rail.Right)
            item.Width:Set(function() return item.Right() - item.Left() end)
            table.insert(launcher.navItems, item)
        end
    end
    -- Visibility follows the level; painted again after a Show on an ancestor and on every refresh.
    rail.Paint = function(self)
        local spec = levels[Level()]
        for _, text in { nameTop, name, subtitle, versionText } do
            Theme.SetVisible(text, spec.name)
        end
        for _, caption in captions do
            Theme.SetVisible(caption, spec.captions)
        end
    end
    Theme.Paintable(rail)
    rail:Paint()
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
    -- The FAF status picks the FAF server: a click lists the main and the test server (FafOnline_SetServer).
    if rawget(_G, 'FafOnline_Server') then
        faf.arrow = Theme.Icon(bar, 'chevronUp', 12, C.subtle)
        faf.arrow.Right:Set(function() return servers.dot.Left() - Scale(18) end)
        LayoutHelpers.AtVerticalCenterIn(faf.arrow, bar)
        faf.text.Right:Set(function() return faf.arrow.Left() - Scale(5) end)
        local area = Group(bar)
        area.Left:Set(function() return faf.dot.Left() - Scale(8) end)
        area.Right:Set(function() return faf.arrow.Right() + Scale(6) end)
        area.Top:Set(bar.Top)
        area.Bottom:Set(bar.Bottom)
        Theme.SizeFromEdges(area)
        status.serverArea = area
        status.OpenServers = function(self)
            local current = (launcher.lastStatus and launcher.lastStatus.server) or FafOnline_Server().name
            local items = {}
            for _, server in FafOnline_Server().servers or {} do
                local chosen = server.name == current
                table.insert(items, { (chosen and 'Playing on ' or 'Switch to ') ..
                    (server.name == 'main' and 'FAF main server' or 'FAF test server (not for regular use)'),
                    key = server.name, color = chosen and C.accent or C.text })
            end
            return Widgets.Dropdown(area, items, function(item)
                if item.key ~= current then
                    launcher:SetServer(item.key)
                end
            end, { width = 360 })
        end
        Theme.HitArea(area, function(control, event)
            if event.Type == 'MouseEnter' then
                Theme.SetColor(faf.text, C.text)
                faf.arrow:SetIcon('chevronUp', C.accent)
            elseif event.Type == 'MouseExit' then
                Theme.SetColor(faf.text, C.muted)
                faf.arrow:SetIcon('chevronUp', C.subtle)
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                Theme.ClickSound()
                status:OpenServers()
                return true
            end
            return false
        end)
    end
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
        Theme.SetText(faf.text, (s.server == 'test' and 'FAF test server ' or 'FAF ') .. fafState)
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

    local bar = BuildTopBar(launcher, body)
    launcher.topBar = bar
    launcher.status = BuildStatusBar(launcher, body)

    -- The pages, the full width under the bar (under Play's strip on Play's pages: Launcher:PlaceContent).
    local content = Group(body, 'launcher content')
    content.Left:Set(function() return body.Left() + Scale(36) end)
    content.Right:Set(function() return body.Right() - Scale(36) end)
    content.Top:Set(function() return bar.Bottom() + Scale(22) end)
    launcher.content = content
    content.Bottom:Set(function() return body.Bottom() - Scale(kStatusHeight + 18) end)

    local onlinePage = Group(content, 'launcher online')
    LayoutHelpers.FillParent(onlinePage, content)
    onlinePage.Width:Set(function() return onlinePage.Right() - onlinePage.Left() end)
    onlinePage.Height:Set(function() return onlinePage.Bottom() - onlinePage.Top() end)
    launcher.pages = { online = onlinePage }
    BuildOnlinePage(launcher, onlinePage)

    -- Replays: this computer's and FAF's vault (replays.lua), with the engine's replay library.
    if rawget(_G, 'FafLibrary_LocalReplays') then
        local replaysPage = Group(content, 'launcher replays')
        LayoutHelpers.FillParent(replaysPage, content)
        replaysPage.Width:Set(function() return replaysPage.Right() - replaysPage.Left() end)
        replaysPage.Height:Set(function() return replaysPage.Bottom() - replaysPage.Top() end)
        launcher.pages.replays = replaysPage
        import('/fafengine/modules/lua/ui/launcher/replays.lua').Build(launcher, replaysPage)
        Theme.SetVisible(replaysPage, false)
    end
    -- Options: FAF's options in the launcher's look (optionspage.lua).
    local optionsPage = Group(content, 'launcher options')
    LayoutHelpers.FillParent(optionsPage, content)
    optionsPage.Width:Set(function() return optionsPage.Right() - optionsPage.Left() end)
    optionsPage.Height:Set(function() return optionsPage.Bottom() - optionsPage.Top() end)
    launcher.pages.options = optionsPage
    import('/fafengine/modules/lua/ui/launcher/optionspage.lua').Build(launcher, optionsPage)
    Theme.SetVisible(optionsPage, false)
    -- Changelog: FAF's patch notes (changelog.lua).
    local changelogPage = Group(content, 'launcher changelog')
    LayoutHelpers.FillParent(changelogPage, content)
    changelogPage.Width:Set(function() return changelogPage.Right() - changelogPage.Left() end)
    changelogPage.Height:Set(function() return changelogPage.Bottom() - changelogPage.Top() end)
    launcher.pages.changelog = changelogPage
    import('/fafengine/modules/lua/ui/launcher/changelog.lua').Build(launcher, changelogPage)
    Theme.SetVisible(changelogPage, false)
    -- Matchmaking: FAF's matchmaker queues (matchpage.lua), with the engine's FafOnline_Queues.
    if rawget(_G, 'FafOnline_Queues') then
        local matchPage = Group(content, 'launcher matchmaking')
        LayoutHelpers.FillParent(matchPage, content)
        matchPage.Width:Set(function() return matchPage.Right() - matchPage.Left() end)
        matchPage.Height:Set(function() return matchPage.Bottom() - matchPage.Top() end)
        local matchBuilt, matchWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/matchpage.lua').Build(launcher, matchPage)
        end)
        if matchBuilt then
            launcher.pages.matchmaking = matchPage
            Theme.SetVisible(matchPage, false)
        else
            WARN('LAUNCHER: the matchmaking page failed to build: ' .. tostring(matchWhy))
            matchPage:Destroy()
        end
    end
    -- Maps: this computer's and FAF's vault (mapspage.lua), with the engine's map installs.
    if rawget(_G, 'FafLibrary_InstallMap') then
        local mapsPage = Group(content, 'launcher maps')
        LayoutHelpers.FillParent(mapsPage, content)
        mapsPage.Width:Set(function() return mapsPage.Right() - mapsPage.Left() end)
        mapsPage.Height:Set(function() return mapsPage.Bottom() - mapsPage.Top() end)
        local mapsBuilt, mapsWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/mapspage.lua').Build(launcher, mapsPage)
        end)
        if mapsBuilt then
            launcher.pages.maps = mapsPage
            Theme.SetVisible(mapsPage, false)
        else
            WARN('LAUNCHER: the maps page failed to build: ' .. tostring(mapsWhy))
            mapsPage:Destroy()
        end
    end
    -- News: FAF's news posts and links (newspage.lua), with the engine's news reader.
    if rawget(_G, 'FafLibrary_News') then
        local newsPage = Group(content, 'launcher news')
        LayoutHelpers.FillParent(newsPage, content)
        newsPage.Width:Set(function() return newsPage.Right() - newsPage.Left() end)
        newsPage.Height:Set(function() return newsPage.Bottom() - newsPage.Top() end)
        local newsBuilt, newsWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/newspage.lua').Build(launcher, newsPage)
        end)
        if newsBuilt then
            launcher.pages.news = newsPage
            Theme.SetVisible(newsPage, false)
        else
            WARN('LAUNCHER: the news page failed to build: ' .. tostring(newsWhy))
            newsPage:Destroy()
        end
    end
    -- Units: every unit's blueprint through FAF's unit analyzer (unitspage.lua).
    do
        local unitsPage = Group(content, 'launcher units')
        LayoutHelpers.FillParent(unitsPage, content)
        unitsPage.Width:Set(function() return unitsPage.Right() - unitsPage.Left() end)
        unitsPage.Height:Set(function() return unitsPage.Bottom() - unitsPage.Top() end)
        local unitsBuilt, unitsWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/unitspage.lua').Build(launcher, unitsPage)
        end)
        if unitsBuilt then
            launcher.pages.units = unitsPage
            Theme.SetVisible(unitsPage, false)
        else
            WARN('LAUNCHER: the units page failed to build: ' .. tostring(unitsWhy))
            unitsPage:Destroy()
        end
    end
    -- Leaderboards: FAF's rating ladders (leaderboards.lua), with the engine's FAF API access.
    if rawget(_G, 'FafLibrary_Api') then
        local boardsPage = Group(content, 'launcher leaderboards')
        LayoutHelpers.FillParent(boardsPage, content)
        boardsPage.Width:Set(function() return boardsPage.Right() - boardsPage.Left() end)
        boardsPage.Height:Set(function() return boardsPage.Bottom() - boardsPage.Top() end)
        local boardsBuilt, boardsWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/leaderboards.lua').Build(launcher, boardsPage)
        end)
        if boardsBuilt then
            launcher.pages.leaderboards = boardsPage
            Theme.SetVisible(boardsPage, false)
        else
            WARN('LAUNCHER: the leaderboards page failed to build: ' .. tostring(boardsWhy))
            boardsPage:Destroy()
        end
    end
    -- Tournaments: FAF's tournaments (tournamentspage.lua), beside the leaderboards.
    if rawget(_G, 'FafLibrary_Api') then
        local tourneyPage = Group(content, 'launcher tournaments')
        LayoutHelpers.FillParent(tourneyPage, content)
        tourneyPage.Width:Set(function() return tourneyPage.Right() - tourneyPage.Left() end)
        tourneyPage.Height:Set(function() return tourneyPage.Bottom() - tourneyPage.Top() end)
        local tourneyBuilt, tourneyWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/tournamentspage.lua').Build(launcher, tourneyPage)
        end)
        if tourneyBuilt then
            launcher.pages.tournaments = tourneyPage
            Theme.SetVisible(tourneyPage, false)
        else
            WARN('LAUNCHER: the tournaments page failed to build: ' .. tostring(tourneyWhy))
            tourneyPage:Destroy()
        end
    end
    -- Co-op: FAF's co-op missions (coop.lua), with the engine's FAF API access.
    if rawget(_G, 'FafLibrary_Api') then
        local coopPage = Group(content, 'launcher coop')
        LayoutHelpers.FillParent(coopPage, content)
        coopPage.Width:Set(function() return coopPage.Right() - coopPage.Left() end)
        coopPage.Height:Set(function() return coopPage.Bottom() - coopPage.Top() end)
        local coopBuilt, coopWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/coop.lua').Build(launcher, coopPage)
        end)
        if coopBuilt then
            launcher.pages.coop = coopPage
            Theme.SetVisible(coopPage, false)
        else
            WARN('LAUNCHER: the co-op page failed to build: ' .. tostring(coopWhy))
            coopPage:Destroy()
        end
    end
    -- Chat: FAF's chat (chatpage.lua), with the engine's chat functions.
    if rawget(_G, 'FafChat_Status') then
        local chatPage = Group(content, 'launcher chat')
        LayoutHelpers.FillParent(chatPage, content)
        chatPage.Width:Set(function() return chatPage.Right() - chatPage.Left() end)
        chatPage.Height:Set(function() return chatPage.Bottom() - chatPage.Top() end)
        local chatBuilt, chatWhy = pcall(function()
            import('/fafengine/modules/lua/ui/launcher/chatpage.lua').Build(launcher, chatPage)
        end)
        if chatBuilt then
            launcher.pages.chat = chatPage
            Theme.SetVisible(chatPage, false)
        else
            WARN('LAUNCHER: the chat page failed to build: ' .. tostring(chatWhy))
            chatPage:Destroy()
        end
    end
    -- LAN: games on this network, hosting one, an address (lanpage.lua).
    local lanPage = Group(content, 'launcher lan')
    LayoutHelpers.FillParent(lanPage, content)
    lanPage.Width:Set(function() return lanPage.Right() - lanPage.Left() end)
    lanPage.Height:Set(function() return lanPage.Bottom() - lanPage.Top() end)
    local lanBuilt, lanWhy = pcall(function()
        import('/fafengine/modules/lua/ui/launcher/lanpage.lua').Build(launcher, lanPage)
    end)
    if lanBuilt then
        launcher.pages.lan = lanPage
    else
        WARN('LAUNCHER: the LAN page failed to build: ' .. tostring(lanWhy))
        lanPage:Destroy()
    end
    if launcher.pages.lan then
        Theme.SetVisible(lanPage, false)
    end
    -- Mods: installed and FAF's vault (modspage.lua), with the engine's mod library.
    if rawget(_G, 'FafLibrary_InstallMod') then
        local modsPage = Group(content, 'launcher mods')
        LayoutHelpers.FillParent(modsPage, content)
        modsPage.Width:Set(function() return modsPage.Right() - modsPage.Left() end)
        modsPage.Height:Set(function() return modsPage.Bottom() - modsPage.Top() end)
        launcher.pages.mods = modsPage
        import('/fafengine/modules/lua/ui/launcher/modspage.lua').Build(launcher, modsPage)
        Theme.SetVisible(modsPage, false)
    end

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

--- Builds the launcher. `buildFafMenu` builds FAF's own main menu (the hook passes it); the launcher no longer opens
--- it, and main.lua falls back to it only when the launcher fails to load.
function CreateUI(buildFafMenu)
    UIUtil.SetCurrentSkin('uef')
    import('/lua/ui/game/gamemain.lua').supressExitDialog = false
    -- No profile yet: one made at once (FAF's main menu asked for a name first), named after the FAF login later.
    EnsureProfile()
    Cleanup()
    local launcher = setmetatable({ buildFafMenu = buildFafMenu, page = 'online' }, Launcher)
    current = launcher
    if rawget(_G, 'FafOnline_TakeResume') then
        launcher.resume = FafOnline_TakeResume() or false
        launcher.resumeSince = GetSystemTimeSeconds()
    end
    Build(launcher)
    -- Back on the page shown before the front end was built again (Options after a UI scale change).
    launcher:ShowPage((lastShownPage and launcher.pages[lastShownPage]) and lastShownPage or 'online')
    -- The preview walk's way back: the launcher is here again; which page it opened on, then the walk ends.
    if Prefs.GetFromCurrentProfile('fafre_preview_test') then
        Prefs.SetToCurrentProfile('fafre_preview_test', nil)
        ForkThread(function()
            WaitSeconds(3)
            LOG('LAUNCHER TEST: preview: back on the launcher, page ' .. tostring(launcher.page))
            WaitSeconds(2)
            ExitApplication()
        end)
    end
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
local testFriendDone = false
function TestJoin()
    if testJoinDone or not current or current.page ~= 'online' or not current.online or not current.online.grid then
        return
    end
    -- /launcherfriend <id>: that FAF player into the friends first (the lobby screen then marks them).
    local friendTest = GetCommandLineArg('/launcherfriend', 1)
    if friendTest and friendTest[1] and not testFriendDone and FafOnline_Status().lobby == 'signedin' then
        testFriendDone = true
        local ok, why = FafOnline_SetFriend(friendTest[1], true)
        LOG('LAUNCHER TEST: friend ' .. friendTest[1] .. ' added: ' .. tostring(ok) .. ' ' .. tostring(why))
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
        -- /launcherpreviewtest: the changelog's game preview of a made-up Titan card (four values the preview puts
        -- back, a cost, one changed again since). The game's overlay walks on by itself and comes back here.
        if GetCommandLineArg('/launcherpreviewtest', 0) then
            current:ShowPage('changelog')
            Wait(3)
            Step('preview: starting from ' .. tostring(current.page))
            Prefs.SetToCurrentProfile('fafre_preview_test', true)
            current:PreviewUnit({ id = 'uel0303', name = 'Titan', stats = {
                { label = 'Range', old = 30, new = 24, oldText = '30', newText = '24' },
                { label = 'Damage', old = 30, new = 45, oldText = '30', newText = '45' },
                { label = 'Speed', old = 3, new = 3.8, oldText = '3', newText = '3.8' },
                { label = 'Health', old = 2000, new = 2400, oldText = '2000', newText = '2400' },
                { label = 'Mass cost', old = 400, new = 480, oldText = '400', newText = '480' },
                { label = 'Rate of fire', old = 1, new = 2, oldText = '1', newText = '2' },
            } }, 'test')
            return
        end
        local watchAtStart = GetCommandLineArg('/launcherreplaywatch', 0)
        local installTest = GetCommandLineArg('/launchermodinstall', 0)
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
            -- /launchertourneytest: the Tournaments page: FAF's tournaments by state, one chosen.
            if GetCommandLineArg('/launchertourneytest', 0) and current.tournamentsView then
                local tourneys = current.tournamentsView
                current:ShowPage('tournaments')
                for i = 1, 20 do
                    current:Refresh()
                    if tourneys.tournaments or tourneys.failure then
                        break
                    end
                    Wait(1)
                end
                Wait(2)
                current:Refresh()
                local states = {}
                for _, item in (tourneys.tournaments or {}) do
                    table.insert(states, item.name .. '=' .. item.state)
                end
                Step('tourneys: ' .. table.getn(tourneys.tournaments or {}) .. ' read: ' .. table.concat(states, ', ') ..
                    ', chosen ' .. tostring(tourneys.chosen and tourneys.chosen.name) .. ', strip ' ..
                    tostring(current.rankStrip and not current.rankStrip:IsHidden()) ..
                    (tourneys.failure and (', failure ' .. tourneys.failure) or ''))
                tourneys.tab = 'signup'
                tourneys:Paint()
                Wait(2)
                Step('tourneys: sign-up open ' .. table.getn(tourneys:Shown()) .. ', chosen ' ..
                    tostring(tourneys.chosen and tourneys.chosen.name) .. ', sign-up page ' ..
                    tostring(tourneys.chosen and tourneys.chosen.signup))
                tourneys.tab = 'all'
                tourneys:Paint()
                Wait(1)
            end
            -- /launchernewstest: the News page: FAF's posts, a category, a post read, the next page.
            if GetCommandLineArg('/launchernewstest', 0) and current.newsView then
                local news = current.newsView
                current:ShowPage('news')
                local function Settle(seconds)
                    for i = 1, seconds do
                        current:Refresh()
                        if not next(news.jobs) and not next(news.thumbJobs) then
                            break
                        end
                        Wait(1)
                    end
                    Wait(1)
                    current:Refresh()
                end
                Settle(20)
                local post = news.chosen
                Step('news: ' .. table.getn(news.posts or {}) .. ' posts, page ' .. news.pageNumber .. ', more ' ..
                    tostring(news.more) .. ', first ' .. tostring(post and post.title) .. ' [' ..
                    tostring(post and table.concat(post.categories, ', ')) .. '], ' .. table.getn(news.document.blocks or {}) ..
                    ' blocks, picture ' .. tostring(post and post.large) .. (news.failure and (', failure ' .. news.failure) or ''))
                Wait(2)
                news.tab = 'tournament'
                news:Paint()
                Step('news: tournaments ' .. table.getn(news:Shown()))
                Wait(2)
                news.tab = 'all'
                news:Load()
                Settle(20)
                Step('news: after Load more: ' .. table.getn(news.posts or {}) .. ' posts, page ' .. news.pageNumber ..
                    ', more ' .. tostring(news.more))
                Wait(1)
            end
            -- /launcherunitstest: the Units page: the blueprints read, a faction's units, a filter, a unit's card.
            if GetCommandLineArg('/launcherunitstest', 0) and current.unitsView then
                local units = current.unitsView
                current:ShowPage('units')
                for i = 1, 60 do
                    current:Refresh()
                    if units.units or units.failure then
                        break
                    end
                    Wait(1)
                end
                Wait(2)
                current:Refresh()
                local counts = {}
                for faction, count in (units.counts or {}) do
                    table.insert(counts, faction .. ' ' .. count)
                end
                table.sort(counts)
                Step('units: ' .. tostring(units.units and table.getn(units.units)) .. ' read (' .. table.concat(counts, ', ') ..
                    '), ' .. units.faction .. ' shows ' .. table.getn(units.shown or {}) .. (units.failure and (', failure ' ..
                    units.failure) or ''))
                -- The UEF T1 land units, then the Percival (uel0303, T3) by its id.
                units.tech = 'T1'
                units.kind = 'LAND'
                units:Filter()
                Wait(1)
                local names = {}
                for _, unit in (units.shown or {}) do
                    table.insert(names, unit.name)
                end
                Step('units: UEF T1 land: ' .. table.concat(names, ', '))
                units.tech = 'all'
                units.kind = 'all'
                units.search.edit:SetText('uel0303')
                units:Filter()
                Wait(2)
                local unit = units.chosen
                local facts = unit and units:Facts(unit)
                Step('units: uel0303: ' .. tostring(unit and unit.name) .. ' / ' .. tostring(unit and unit.role) .. ', ' ..
                    (facts and table.concat(facts.values, ' | ') or 'no facts') .. ', weapons ' ..
                    tostring(facts and table.getn(facts.weapons)) .. ', icon ' .. tostring(unit and unit.icon) .. ', back ' ..
                    tostring(unit and unit.back))
                Wait(2)
                units.search.edit:SetText('')
                units.faction = 'SERAPHIM'
                units:Filter()
                Wait(2)
                local acu = units.chosen
                local acuFacts = acu and units:Facts(acu)
                local acuWeapons = {}
                for _, weapon in (acuFacts and acuFacts.weapons or {}) do
                    table.insert(acuWeapons, weapon.name .. ' ' .. weapon.dps)
                end
                Step('units: Seraphim shows ' .. table.getn(units.shown or {}) .. ', first ' .. tostring(acu and acu.id) ..
                    ' damage/s ' .. tostring(acuFacts and acuFacts.values[8]) .. ' (' .. table.concat(acuWeapons, '; ') .. ')')
                Wait(1)
            end
            -- /launcherboardstest: the Leaderboards page: the 1v1 ranking, the signed-in player's place and the jump to
            -- it, another ladder, a search by name.
            if GetCommandLineArg('/launcherboardstest', 0) and current.leaderboardsView then
                local boards = current.leaderboardsView
                current:ShowPage('leaderboards')
                local function Settle(seconds)
                    for i = 1, seconds do
                        current:Refresh()
                        if not next(boards.jobs) then
                            break
                        end
                        Wait(1)
                    end
                    current:Refresh()
                end
                Settle(15)
                local mine = boards.mine[boards.board .. ':active']
                Step('boards: ' .. boards.board .. ' ' .. table.getn(boards.rows or {}) .. ' rows of ' ..
                    tostring(boards.total) .. ', page ' .. boards.pageNumber .. ' of ' .. tostring(boards.pages) ..
                    ', first ' .. tostring(boards.rows and boards.rows[1] and (boards.rows[1].login .. ' ' ..
                    boards.rows[1].rating)) .. ', mine ' .. tostring(mine and mine.state) .. ' rank ' ..
                    tostring(mine and mine.row and mine.row.rank) .. (boards.failure and (', failure ' .. boards.failure) or '') ..
                    ', compact tabs ' .. tostring(current.compactTabs))
                Wait(2)
                boards:FindMe()
                Settle(15)
                Step('boards: after Show me: page ' .. boards.pageNumber .. ', chosen ' ..
                    tostring(boards.chosen and boards.chosen.login) .. ' rank ' .. tostring(boards.chosen and boards.chosen.rank))
                Wait(2)
                boards:Choose('tmm_2v2')
                Settle(15)
                Step('boards: 2v2 ' .. table.getn(boards.rows or {}) .. ' rows, total ' .. tostring(boards.total))
                boards.search.edit:SetText('dost')
                boards.pageNumber = 1
                boards:Load()
                Settle(15)
                Step('boards: search dost: ' .. table.getn(boards.rows or {}) .. ' rows, first ' ..
                    tostring(boards.rows and boards.rows[1] and boards.rows[1].login) .. ', rank shown ' ..
                    tostring(boards.rows and boards.rows[1] and boards.rows[1].rank))
                boards.search.edit:SetText('')
                Wait(2)
            end
            -- /launchermapstest: the Maps page: this computer's maps, the vault's first page, a map downloaded and removed.
            if GetCommandLineArg('/launchermapstest', 0) and current.mapsView then
                local maps = current.mapsView
                current:ShowPage('maps')
                Wait(2)
                Step('maps: ' .. table.getn(maps:Items()) .. ' on this computer')
                maps.tab = 'vault'
                maps:Search()
                for i = 1, 15 do
                    current:Refresh()
                    if not maps.jobs.search then
                        break
                    end
                    Wait(1)
                end
                maps.chosen = maps.vault[1]
                Wait(3)
                Step('maps: vault ' .. table.getn(maps.vault) .. ' maps, page ' .. maps.vaultPage .. ' of ' ..
                    tostring(maps.vaultPages) .. ', first ' .. tostring(maps.chosen and maps.chosen.name) ..
                    (maps.failure and (', failure ' .. maps.failure) or ''))
                if maps.chosen then
                    maps:Act()
                    for i = 1, 20 do
                        current:Refresh()
                        if not maps.jobs.install then
                            break
                        end
                        Wait(1)
                    end
                    Wait(2)
                    local file = '/maps/' .. maps.chosen.folder .. '/' .. maps.chosen.folder .. '_scenario.lua'
                    local loaded, why = pcall(import('/lua/ui/maputil.lua').LoadScenario, file)
                    Step('maps: after Download: ' .. tostring(maps.statusText) .. ', installed ' ..
                        tostring(maps:Installed(maps.chosen)) .. ', file seen ' .. tostring(DiskGetFileInfo(file) and true) ..
                        ', load ' .. tostring(loaded) .. ' ' .. tostring(loaded and type(why) or why))                    maps:Act()
                    Wait(2)
                    Step('maps: after Remove: ' .. tostring(maps.statusText) .. ', installed ' ..
                        tostring(maps:Installed(maps.chosen)))
                end
            end
            -- /launchercooptest: the Co-op page: FAF's missions, the first one's fastest completions.
            if GetCommandLineArg('/launchercooptest', 0) and current.coopView then
                current:ShowPage('coop')
                for i = 1, 15 do
                    local coop = current.coopView
                    if coop.missions and coop.chosen and coop.results[coop.chosen.id] then
                        break
                    end
                    Wait(1)
                end
                Wait(2)
                local coop = current.coopView
                Step('co-op: ' .. table.getn(coop.missions or {}) .. ' missions, first ' ..
                    tostring(coop.chosen and coop.chosen.name) .. ' (' .. tostring(coop.chosen and coop.chosen.folder) ..
                    '), ' .. table.getn(coop.chosen and coop.results[coop.chosen.id] or {}) .. ' completions' ..
                    (coop.failure and (', failure ' .. coop.failure) or ''))
                Wait(2)
            end
            -- /launchermatchtest: the Matchmaking page: the queues FAF's lobby lists, a search started and stopped.
            if GetCommandLineArg('/launchermatchtest', 0) and current.matchView then
                current:ShowPage('matchmaking')
                Wait(3)
                local queues = FafOnline_Queues().queues or {}
                local names = {}
                for _, queue in queues do
                    table.insert(names, queue.name .. ' ' .. queue.players .. '/' .. queue.popIn .. 's')
                end
                Step('matchmaking: ' .. table.getn(queues) .. ' queues: ' .. table.concat(names, ', '))
                local first = current.matchView.queues and current.matchView.queues[1]
                if first then
                    current.matchView:Toggle(first)
                    Wait(3)
                    current.matchView:Refresh()
                    Step('matchmaking: after Search, state ' .. FafOnline_Queues().state)
                    Wait(2)
                    current.matchView:StopAll()
                    Wait(3)
                    Step('matchmaking: after Stop, state ' .. FafOnline_Queues().state)
                end
            end
            -- /launcherchattest: the Chat page: the chat started, a line said, a second channel joined.
            if GetCommandLineArg('/launcherchattest', 0) and current.chatView then
                current:ShowPage('chat')
                Wait(2)
                Step('chat: intro shown, chat ' .. FafChat_Status().state)
                current.chatView:Start()
                for i = 1, 20 do
                    if FafChat_Status().state == 'joined' and table.getn(FafChat_Status().channels) > 0 then
                        break
                    end
                    Wait(1)
                end
                Wait(2)
                local chat = current.chatView
                local status = FafChat_Status()
                Step('chat: ' .. status.state .. ' as ' .. tostring(status.nick) .. ' in ' ..
                    table.concat(status.channels, ', ') .. ', ' .. table.getn(chat.lines[chat.channel or ''] or {}) ..
                    ' lines in ' .. tostring(chat.channel) .. ', ' .. table.getn(chat.userList.items or {}) .. ' people')
                chat.input.edit:SetText('hello from the walk')
                chat:Send(chat.input.edit:GetText())
                Wait(3)
                local lines = chat.lines[chat.channel] or {}
                local last = lines[table.getn(lines)] or {}
                Step('chat: said a line; the last line now: ' .. tostring(last.from) .. ': ' .. tostring(last.text))
                FafChat_Join('#walk')
                Wait(3)
                Step('chat: channels ' .. table.concat(FafChat_Status().channels, ', '))
                Wait(2)
            end
            -- /launcherservertest: FAF's test server, then the main one again; the service starts again on each.
            if GetCommandLineArg('/launcherservertest', 0) then
                current:SetServer('test')
                Wait(4)
                local onTest = FafOnline_Status()
                Step('server test: on ' .. tostring(onTest.server) .. ' (' .. tostring(onTest.serverTitle) .. '), sign-in ' ..
                    tostring(onTest.signIn))
                if current.status and current.status.OpenServers then
                    local menu = current.status:OpenServers()
                    Step('server test: server menu open')
                    Wait(2)
                    menu.Close()
                end
                Wait(1)
                current:SetServer('main')
                Wait(4)
                local onMain = FafOnline_Status()
                Step('server test: back on ' .. tostring(onMain.server) .. ', sign-in ' .. tostring(onMain.signIn))
            end
            -- /launcherprofiletest [login]: that player's profile (else the signed-in one's), each of its tabs.
            local profileArg = GetCommandLineArg('/launcherprofiletest', 1)
            local profileLogin = (profileArg and profileArg[1] and string.sub(profileArg[1], 1, 1) ~= '/' and profileArg[1]) or
                FafOnline_Status().login
            if GetCommandLineArg('/launcherprofiletest', 0) and profileLogin ~= '' then
                current:ShowProfile(profileLogin)
                local profile = import('/fafengine/modules/lua/ui/launcher/profile.lua').Current()
                for i = 1, 15 do
                    if profile and profile.boards then
                        break
                    end
                    Wait(1)
                end
                for _, tab in { 'overview', 'history', 'maps', 'names', 'clan' } do
                    if profile then
                        profile:ShowTab(tab)
                        for i = 1, 10 do
                            local busy = false
                            for _ in profile.jobs do
                                busy = true
                            end
                            if not busy then
                                break
                            end
                            Wait(1)
                        end
                        -- The chart zoomed to games 101-250 with the mouse on game 180, as a wheel and a hover do.
                        local chart = tab == 'history' and profile.pages.history.chart
                        if chart and table.getn(chart.points) >= 250 then
                            chart:ShowRange(101, 250)
                            chart:ShowOver(180)
                            Step('profile chart: games ' .. chart.first .. '-' .. chart.last .. ', over ' ..
                                tostring(chart.overIndex))
                        end
                        local errors = {}
                        for key, why in profile.errors do
                            table.insert(errors, key .. ': ' .. tostring(why))
                        end
                        Step('profile tab ' .. tab .. ': player ' .. tostring(profile.player and profile.player.id) ..
                            ', ' .. table.getn(profile.boards or {}) .. ' leaderboards, ' ..
                            table.getn(profile.maps or {}) .. ' maps, ' .. table.getn(profile.names or {}) ..
                            ' names, clan ' .. tostring(profile.clan and profile.clan.tag) ..
                            (table.getn(errors) > 0 and (', errors ' .. table.concat(errors, '; ')) or ''))
                        Wait(2)
                    end
                end
                if profile then
                    profile:Close()
                end
                Step('profile closed')
            end
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
                local dialog = current.hostDialog
                Step('map list: ' .. table.getn(dialog.mapList.items) .. ' maps shown')
                dialog.FilterMaps(8, 0, 'size')
                local items = dialog.mapList.items
                local first, last = items[1], items[table.getn(items)]
                Step('map list, 8 players by size: ' .. table.getn(items) .. ' maps, first ' ..
                    tostring(first and first.folder) .. ' (' .. tostring(first and first.km) .. ' km), last ' ..
                    tostring(last and last.folder) .. ' (' .. tostring(last and last.km) .. ' km)')
                Wait(1)
                dialog.FilterMaps(0, 0, 'name')
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
        -- The Replays page: this computer's replays, the first one's details, then the vault's first page.
        if current and current.replaysView then
            current:ShowPage('replays')
            Wait(2)
            local replays = current.replaysView
            Step('replays page: ' .. table.getn(replays.localItems or {}) .. ' on this computer')
            -- Every control of the page has its edges (a layout cycle shows as a control whose edges fail).
            for name, control in replays do
                if type(control) == 'table' and control.Left and control.Right and control.Top then
                    local fine = pcall(function() return control.Left() + control.Right() + control.Top() end)
                    if not fine then
                        Step('replays page: the edges of ' .. tostring(name) .. ' fail')
                    end
                end
            end
            -- The first FAF replay (its teams, and its ratings and results from the vault by its game id).
            local first = replays.localList.items[1]
            for _, item in replays.localList.items do
                if string.find(string.lower(item.file), '%.fafreplay$') then
                    first = item
                    break
                end
            end
            if first then
                replays.localList.selectedKey = first.key
                replays.selected = first
                replays:ShowDetails()
                local info = replays:Info(first)
                Step('first replay: ' .. tostring(first.file) .. ', map ' .. tostring(info and info.map) .. ', ' ..
                    table.getn(info and info.players or {}) .. ' players')
                for i = 1, 20 do
                    if not replays.lookupJob then
                        break
                    end
                    Wait(0.5)
                end
                replays:ShowDetails()
                Step('local replay details: ' .. replays:TeamsText(first) .. ', game time ' ..
                    tostring(replays:GameLength(first.path)))
                Wait(1)
            end
            Wait(2)
            replays:SetTab('vault')
            for i = 1, 30 do
                if not replays.searchJob then
                    break
                end
                Wait(0.5)
            end
            Step('replay vault: ' .. table.getn(replays.vaultItems) .. ' games, page ' .. replays.vaultPage .. ' of ' ..
                replays.vaultPages .. (replays.status ~= '' and (', ' .. replays.status) or ''))
            if replays.vaultItems[1] then
                replays.vaultList.selectedKey = replays.vaultItems[1].key
                replays.selected = replays.vaultItems[1]
                replays:ShowDetails()
                Step('vault game details shown')
            end
            Wait(2)
            -- /launcherreplaywatch: Watch on the vault's first game: it downloads, then the replay starts.
            local watchTest = GetCommandLineArg('/launcherreplaywatch', 0)
            Step('watch test: ' .. tostring(watchTest) .. ' (at the start ' .. tostring(watchAtStart) .. '), first game ' ..
                tostring(replays.vaultItems[1]))
            watchTest = watchTest or watchAtStart
            if watchTest and replays.vaultItems[1] then
                local game = replays.vaultItems[1]
                replays.vaultList.selectedKey = game.key
                replays.selected = game
                replays:Watch()
                Step('watch pressed on ' .. game.title .. ': ' .. replays.status)
                for i = 1, 40 do
                    if not replays.downloadJob then
                        break
                    end
                    Wait(0.5)
                end
                Step('after the download: ' .. replays.status)
                return -- the replay runs; the run's time limit ends it
            end
            current:ShowPage('online')
        end
        -- The Mods page: installed mods, the vault's first page; with /launchermodinstall, the vault's first mod
        -- installed, turned on and off, and removed again.
        if current and current.modsView then
            current:ShowPage('mods')
            Wait(2)
            local mods = current.modsView
            local function Count()
                local n = 0
                for _ in mods:Installed() do
                    n = n + 1
                end
                return n
            end
            Step('mods page: ' .. Count() .. ' installed')
            mods:SetTab('vault')
            for i = 1, 30 do
                if not mods.searchJob then
                    break
                end
                Wait(0.5)
            end
            Step('mod vault: ' .. table.getn(mods.vaultItems) .. ' mods, page ' .. mods.vaultPage .. ' of ' ..
                mods.vaultPages .. (mods.status ~= '' and (', ' .. mods.status) or ''))
            local first = mods.vaultItems[1]
            if installTest and first then
                mods.vaultList.selectedKey = first.key
                mods.selected = first
                mods:Act()
                for i = 1, 40 do
                    if not mods.installJob then
                        break
                    end
                    Wait(0.5)
                end
                Wait(1)
                Step('after the install: ' .. mods.status .. ', installed ' .. Count() .. ', ' .. first.uid ..
                    (mods:Installed()[first.uid] and ' is in the game\'s mod list' or ' is NOT in the game\'s mod list'))
                mods:Act()
                Step('turned on: ' .. tostring(mods:IsOn(first.uid)))
                Wait(2)
                mods:Act()
                Step('turned off: ' .. tostring(not mods:IsOn(first.uid)))
                mods:SetTab('local')
                mods.selected = mods:Installed()[first.uid]
                mods:Remove()
                Wait(1)
                Step('after removing: ' .. mods.status .. ', installed ' .. Count() .. ', ' ..
                    (mods:Installed()[first.uid] and 'still listed' or 'gone from the list'))
            end
            Wait(2)
            current:ShowPage('online')
        end
        -- The Options page: each tab's rows; a slider changed, applied and set back.
        if current and current.optionsView then
            current:ShowPage('options')
            Wait(2)
            local options = current.optionsView
            local counts = {}
            for _, key in options.sections do
                options.tab = key
                options:Refresh()
                table.insert(counts, key .. ' ' .. table.getn(options.entries))
            end
            Step('options page: ' .. table.concat(counts, ', '))
            -- The options with no help text of FAF's (for the launcher's own texts).
            local tooltips = import('/lua/ui/help/tooltips.lua').Tooltips
            local missing = {}
            for _, key in options.sections do
                for _, item in options.data[key].items do
                    local info = tooltips['options_' .. tostring(item.key)]
                    if item.type ~= 'header' and not (info and info.description and info.description ~= '') and
                        not item.tip then
                        table.insert(missing, key .. '/' .. tostring(item.key))
                    end
                end
            end
            Step('options without help: ' .. table.getn(missing) .. ' ' .. table.concat(missing, ' '))
            options.tab = 'gameplay'
            options:Refresh()
            Wait(1)
            Step('options gameplay tab shown')
            Wait(1)
            options.tab = 'sound'
            options:Refresh()
            local slider = nil
            for _, entry in options.entries do
                if entry.item and entry.item.type == 'slider' and not slider then
                    slider = entry.item
                end
            end
            if slider then
                local before = options.current[slider.key]
                local custom = slider.custom
                local after = before == custom.min and custom.max or custom.min
                options:Set(slider, after)
                Step('options: ' .. slider.key .. ' ' .. tostring(before) .. ' -> ' .. tostring(after) .. ', ' ..
                    options:Changed() .. ' change pending')
                Wait(2)
                options:Apply()
                local saved = import('/lua/options/optionsLogic.lua').GetCurrent()[slider.key]
                Step('options applied: ' .. slider.key .. ' saved as ' .. tostring(saved))
                options:Set(slider, before)
                options:Apply()
                Step('options set back: ' .. slider.key .. ' ' ..
                    tostring(import('/lua/options/optionsLogic.lua').GetCurrent()[slider.key]))
            end
            options.tab = 'profile'
            options:Refresh()
            Step('options profile tab: ' .. table.getn(options.entries) .. ' rows')
            Wait(2)
            -- Key bindings: FAF's presets, a key pressed for an action, the player's own preset saved, used and
            -- deleted; the profile's bindings as they were at the end.
            local keys = options.keysView
            if keys then
                local KeyMapper = import('/lua/keymap/keymapper.lua')
                local Prefs = import('/lua/user/prefs.lua')
                local before = { name = Prefs.GetFromCurrentProfile('UserKeyMapName'),
                    map = Prefs.GetFromCurrentProfile('UserKeyMap'), debug = Prefs.GetFromCurrentProfile('UserDebugKeyMap') }
                options.tab = 'keys'
                options:Refresh()
                Wait(1)
                local bound = 0
                for _, row in keys.rows do
                    if row.binding then
                        bound = bound + 1
                    end
                end
                Step('keys tab: ' .. table.getn(keys.rows) .. ' actions, ' .. bound .. ' with a key')
                Wait(2)
                keys:UsePreset('hotbuildKeyMap.lua', 'Hotbuild')
                local hotbuild = 0
                for _, row in keys.rows do
                    if row.binding then
                        hotbuild = hotbuild + 1
                    end
                end
                Step('keys: hotbuild preset, ' .. hotbuild .. ' with a key, preset ' .. tostring(KeyMapper.GetDefaultKeyMapName()))
                -- An action outside the orders (their Shift twins follow them), pressed as Ctrl+F9.
                local entry = nil
                for _, row in keys.rows do
                    if row.category ~= 'orders' and not entry then
                        entry = row
                    end
                end
                local f9 = nil
                for code, name in KeyMapper.GetKeyCodeLookup() do
                    if name == 'F9' then
                        f9 = code
                    end
                end
                if entry and f9 then
                    keys.selected = entry
                    keys:AskKey(entry)
                    keys.TakeKey(f9, { Ctrl = true })
                    Step('keys: waiting for a key for ' .. entry.action)
                    Wait(2)
                    keys.keyDialog.Close()
                    keys:Assign(entry, 'Ctrl-F9')
                    Step('keys: ' .. entry.action .. ' on ' .. tostring(KeyMapper.GetCurrentKeyBinding(entry.action)))
                    keys:SavePreset('walk test')
                    keys:UsePreset('defaultKeyMap.lua', 'GPG default')
                    local afterDefault = KeyMapper.GetCurrentKeyBinding(entry.action)
                    keys:LoadPreset('walk test')
                    Step('keys: own preset saved, GPG default gave ' .. tostring(afterDefault) .. ', the preset again gave ' ..
                        tostring(KeyMapper.GetCurrentKeyBinding(entry.action)) .. ', base ' ..
                        tostring(KeyMapper.GetDefaultKeyMapName()))
                    Wait(2)
                    keys:DeletePreset('walk test')
                    Step('keys: own presets left: ' .. table.getsize(Prefs.GetFromCurrentProfile('fafre_key_presets') or {}))
                end
                Prefs.SetToCurrentProfile('UserKeyMapName', before.name)
                Prefs.SetToCurrentProfile('UserKeyMap', before.map)
                Prefs.SetToCurrentProfile('UserDebugKeyMap', before.debug)
            end
            current:ShowPage('online')
        end
        -- The LAN page: listening for games. /launcherlantest host|join: one client hosts a LAN game, the other finds
        -- it in its list and joins it.
        if current and current.lanView then
            current:ShowPage('lan')
            Wait(3)
            local lan = current.lanView
            Step('lan page: listening ' .. tostring(lan.discovery and true or false) .. ', ' ..
                table.getn(lan:Shown()) .. ' games')
            local lanTest = GetCommandLineArg('/launcherlantest', 1)
            if lanTest and lanTest[1] == 'host' then
                lan.name.edit:SetText('lanhost')
                local dialog = lan:OpenHost()
                dialog.gameName.edit:SetText('LAN test game')
                dialog.gameName:Refresh()
                Step('lan: host dialog open')
                Wait(2)
                lan:Host(dialog)
                Wait(3)
                Step('lan: hosting, screen ' .. tostring(current.screenName))
                for i = 1, 60 do
                    local counted, players = pcall(import('/lua/ui/lobby/lobby.lua').GetPlayerCount)
                    players = counted and players or 0
                    if players >= 2 then
                        Step('lan: host sees ' .. players .. ' players in the lobby')
                        break
                    end
                    Wait(1)
                end
                Wait(6)
                import('/lua/ui/lobby/lobby.lua').ReturnToMenu(false)
                Wait(3)
                Step('lan: host left the lobby, page ' .. tostring(current.page) .. ', screen ' ..
                    tostring(current.screenName))
            elseif lanTest and lanTest[1] == 'join' then
                lan.name.edit:SetText('lanjoin')
                local game = nil
                for i = 1, 60 do
                    game = lan:Shown()[1]
                    if game then
                        break
                    end
                    Wait(1)
                end
                Step('lan: found ' .. (game and (tostring(game.GameName) .. ' at ' .. tostring(game.Address)) or 'nothing'))
                if game then
                    Wait(2)
                    lan:Join(game, false)
                    for i = 1, 30 do
                        local counted, players = pcall(import('/lua/ui/lobby/lobby.lua').GetPlayerCount)
                        players = counted and players or 0
                        if players >= 2 then
                            Step('lan: joined, ' .. players .. ' players in the lobby')
                            break
                        end
                        Wait(1)
                    end
                    -- The host leaves a few seconds later; our lobby says so.
                    local lobbyView = nil
                    for i = 1, 40 do
                        lobbyView = import('/fafengine/modules/lua/ui/lobby/lobbyview.lua').Current()
                        if lobbyView and lobbyView.closedText then
                            break
                        end
                        Wait(1)
                    end
                    Step('lan: after the host left, screen ' .. tostring(current.screenName) .. ', our lobby says: ' ..
                        tostring(lobbyView and lobbyView.closedText))
                    Wait(2)
                    if lobbyView and lobbyView.closedLeave then
                        lobbyView.closedLeave()
                    end
                    Wait(3)
                    Step('lan: after its button, page ' .. tostring(current.page) .. ', screen ' ..
                        tostring(current.screenName))
                end
            end
            current:ShowPage('online')
        end
        for _, screen in { 'Skirmish' } do
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
        -- The Changelog page: FAF's patch notes, the newest first.
        if current and current.changelogView then
            current:ShowPage('changelog')
            Wait(2)
            local changelog = current.changelogView
            Step('changelog: ' .. table.getn(changelog.items) .. ' versions, showing ' ..
                tostring(changelog.shown and changelog.shown.key) .. ', ' .. table.getn(changelog.document.lines) ..
                ' lines')
            -- The newest version whose notes name units: their icons under the notes.
            for _, item in changelog.items do
                changelog:Show(item)
                local icons, ids = 0, {}
                for _, line in changelog.document.lines do
                    for _, unit in (line.units or {}) do
                        icons = icons + 1
                        if table.getn(ids) < 8 then
                            table.insert(ids, unit.id .. ' ' .. unit.name)
                        end
                    end
                end
                if icons > 0 then
                    -- No line only repeats the name of the one icon right under it.
                    local doubled = 0
                    for index, line in changelog.document.lines do
                        local next = changelog.document.lines[index + 1]
                        if next and next.units and table.getn(next.units) == 1 and line.text and
                            string.lower(string.gsub(line.text, '[%s:]+$', '')) == string.lower(next.units[1].name) then
                            doubled = doubled + 1
                        end
                    end
                    Step('changelog: name lines doubled by their icon: ' .. doubled)
                    -- Scrolled to the line with the most icons, a few lines above it.
                    local best, most = 1, 0
                    for index, line in changelog.document.lines do
                        if table.getn(line.units or {}) > most then
                            best, most = index, table.getn(line.units)
                        end
                    end
                    changelog.document.top = math.max(1, best - 4)
                    changelog.document:Paint()
                    Step('changelog: version ' .. item.key .. ' shows ' .. icons .. ' unit icons: ' .. table.concat(ids, ', '))
                    break
                end
            end
            Wait(3)
            -- The newest version with a unit card with two stats or more, scrolled to it.
            for _, item in changelog.items do
                changelog:Show(item)
                local found, cards, stats = nil, 0, 0
                for index, line in changelog.document.lines do
                    if line.head then
                        cards = cards + 1
                        if not found and table.getn(line.head.stats or {}) >= 2 then
                            found = index
                        end
                    elseif line.stat then
                        stats = stats + 1
                    end
                end
                if found then
                    local head = changelog.document.lines[found].head
                    local parts = {}
                    for _, stat in head.stats do
                        table.insert(parts, stat.label .. ' ' .. stat.old .. ' > ' .. stat.new)
                    end
                    changelog.document.top = math.max(1, found - 1)
                    changelog.document:Paint()
                    Step('changelog: version ' .. item.key .. ' has ' .. cards .. ' unit cards, ' .. stats ..
                        ' stat rows; card ' .. head.name .. ' (' .. head.kind .. '): ' .. table.concat(parts, ', '))
                    break
                end
            end
            Wait(3)
            current:ShowPage('online')
        end
        Wait(1)
        Step('done')
        ExitApplication()
    end)
end
