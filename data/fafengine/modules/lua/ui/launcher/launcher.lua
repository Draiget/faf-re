-- The in-game launcher: the screen the game opens on instead of FAF's main menu (main.lua's CreateUI, hooked in
-- /fafengine/lua/ui/menus/main.lua). FAF's games online on one side; skirmish, campaign, LAN, replays, mods and
-- options open FAF's own screens as FAF's main menu does (FAF main.lua ButtonSkirmish ... ButtonOptions) and come
-- back here; FAF's own main menu is one button away.
--
-- Built from basic controls only (solid rectangles, text, edits), so a new FAF release can't break its look. Every
-- call into FAF's screens is protected: if one fails to open, the launcher says which and stays. If the launcher
-- itself fails to build, the hook shows FAF's main menu instead.
--
-- The online part talks to the engine through the FafOnline_* functions (src/moho/app/OnlineLauncher.cpp), which
-- only client builds with the online library have. No sign-in data ever reaches Lua.

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Group = import('/lua/maui/group.lua').Group
local Edit = import('/lua/maui/edit.lua').Edit
local Movie = import('/lua/maui/movie.lua').Movie
local Prefs = import('/lua/user/prefs.lua')
local FlatPanel = import('/fafengine/modules/lua/ui/controls/flat_panel.lua')

-- The featured mods a host can pick, as the Rust client offers them (FAForeverRustClient, HostGameModal.tsx).
FeaturedMods = {
    { id = 'faf', name = 'FAF', text = 'Standard game balance' },
    { id = 'fafbeta', name = 'FAF Beta', text = 'Upcoming balance changes' },
    { id = 'fafdevelop', name = 'FAF Develop', text = 'Bleeding-edge development' },
    { id = 'nomads', name = 'Nomads', text = 'Adds the 5th Nomads faction' },
}

local Colors = {
    text = 'ffd8e0e6',
    dim = 'ff7f909b',
    accent = 'ff63c7f0',
    good = 'ff7fd67f',
    warn = 'fff0c060',
    bad = 'fff07070',
    row = '00000000',
    rowOver = 'ff1c2c36',
    rowSelected = 'ff1d4a66',
    button = 'ff1b2a33',
    buttonOver = 'ff27404d',
    primary = 'ff1d5f86',
    primaryOver = 'ff2a7fb0',
    editBack = 'ff0d151b',
}

local kRowHeight = 26
local kRefreshSeconds = 0.5

-- One launcher at a time; a new CreateUI replaces it.
local current = false
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

local function Label(parent, text, size, color, font)
    local label = UIUtil.CreateText(parent, text or '', size or 14, font or UIUtil.bodyFont)
    label:SetColor(color or Colors.text)
    label:DisableHitTest()
    return label
end

--- A label cut at a width: its left and right are set by the caller.
local function Cell(parent, size, color)
    local cell = Label(parent, '', size or 13, color)
    cell:SetClipToWidth(true)
    return cell
end

local function SetTextIfChanged(label, text)
    if label.shownText ~= text then
        label.shownText = text
        label:SetText(text)
    end
end

local function Rect(parent, color)
    local rect = Bitmap(parent)
    rect:SetSolidColor(color)
    return rect
end

--- A rectangle placed by its edges also reports the size between them: a Bitmap's Width and Height otherwise stay
--- its texture's (maui/bitmap.lua ResetLayout), which a solid colour doesn't have, so they read 0.
local function SizeFromEdges(rect)
    rect.Width:Set(function() return rect.Right() - rect.Left() end)
    rect.Height:Set(function() return rect.Bottom() - rect.Top() end)
end

local function ClickSound()
    PlaySound(Sound({ Cue = 'UI_Menu_MouseDown_Sml', Bank = 'Interface' }))
end

--- A flat button: a filled rectangle with its label, lighter under the mouse, grey when off.
local function FlatButton(parent, text, width, onClick, primary)
    local fill = primary and Colors.primary or Colors.button
    local over = primary and Colors.primaryOver or Colors.buttonOver
    local button = Rect(parent, fill)
    button.label = Label(button, text, 14, Colors.text)
    LayoutHelpers.AtCenterIn(button.label, button)
    button.label.Depth:Set(function() return button.Depth() + 2 end)
    LayoutHelpers.SetDimensions(button, width, 30)
    button.enabled = true
    button.SetEnabled = function(self, enabled)
        if self.enabled ~= enabled then
            self.enabled = enabled
            self.label:SetColor(enabled and Colors.text or Colors.dim)
            self:SetSolidColor(enabled and fill or Colors.button)
        end
    end
    button.SetLabel = function(self, label)
        SetTextIfChanged(self.label, label)
    end
    button.HandleEvent = function(self, event)
        if not self.enabled then
            return false
        end
        if event.Type == 'MouseEnter' then
            self:SetSolidColor(over)
        elseif event.Type == 'MouseExit' then
            self:SetSolidColor(fill)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            ClickSound()
            onClick(self)
            return true
        end
        return false
    end
    return button
end

--- A one-line text edit on a dark field.
local function TextEdit(parent, width, maxChars, text)
    local back = Rect(parent, Colors.editBack)
    LayoutHelpers.SetDimensions(back, width, 26)
    LayoutHelpers.AtLeftTopIn(back, parent, 0, 0) -- the caller places it; until then the edit needs some place
    local edit = Edit(back)
    LayoutHelpers.AtLeftIn(edit, back, 6)
    LayoutHelpers.AtRightIn(edit, back, 6)
    LayoutHelpers.AtVerticalCenterIn(edit, back)
    edit.Height:Set(function() return edit:GetFontHeight() end)
    UIUtil.SetupEditStd(edit, Colors.text, '00000000', Colors.text, 'ff3c6f90', UIUtil.bodyFont, 14, maxChars)
    edit:SetText(text or '')
    back.edit = edit
    back.HandleEvent = function(self, event)
        if event.Type == 'ButtonPress' then
            edit:AcquireFocus()
            return true
        end
        return false
    end
    return back
end

--- A choice that stays pressed: `group` keeps one of its buttons selected.
local function ChoiceButton(parent, text, width, onPick)
    local button = Rect(parent, Colors.button)
    button.label = Label(button, text, 13, Colors.text)
    LayoutHelpers.AtCenterIn(button.label, button)
    button.label.Depth:Set(function() return button.Depth() + 2 end)
    LayoutHelpers.SetDimensions(button, width, 28)
    button.selected = false
    button.enabled = true
    button.Paint = function(self, over)
        local color = Colors.button
        if self.selected then
            color = Colors.rowSelected
        elseif over and self.enabled then
            color = Colors.buttonOver
        end
        self:SetSolidColor(color)
        self.label:SetColor(self.enabled and (self.selected and Colors.accent or Colors.text) or Colors.dim)
    end
    button.HandleEvent = function(self, event)
        if event.Type == 'MouseEnter' then
            self:Paint(true)
        elseif event.Type == 'MouseExit' then
            self:Paint(false)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left and self.enabled then
            ClickSound()
            onPick(self)
            return true
        end
        return false
    end
    return button
end

--- A dimmed cover over the whole screen that takes every click, with a panel in its middle.
local function Modal(root, width, height)
    local cover = Rect(root, 'e8000000') -- dark enough that the launcher behind doesn't show through the panel
    LayoutHelpers.FillParent(cover, root)
    SizeFromEdges(cover)
    cover.Depth:Set(function() return root.Depth() + 500 end)
    cover.HandleEvent = function(self, event)
        return true
    end
    local panel = FlatPanel.FlatPanel(cover, 'launcher dialog')
    LayoutHelpers.SetDimensions(panel, width, height)
    LayoutHelpers.AtCenterIn(panel, cover)
    panel.Depth:Set(function() return cover.Depth() + 1 end)
    cover.panel = panel
    return cover
end

local function Message(root, title, text)
    local cover = Modal(root, 520, 200)
    local panel = cover.panel
    local head = Label(panel, title, 18, Colors.accent, UIUtil.titleFont)
    LayoutHelpers.AtLeftTopIn(head, panel, 20, 16)
    local body = Label(panel, text, 14, Colors.text)
    LayoutHelpers.AtLeftTopIn(body, panel, 20, 56)
    body:SetClipToWidth(true)
    LayoutHelpers.AtRightIn(body, panel, 20)
    local ok = FlatButton(panel, 'OK', 120, function() cover:Destroy() end, true)
    LayoutHelpers.AtRightIn(ok, panel, 20)
    LayoutHelpers.AtBottomIn(ok, panel, 16)
    return cover
end

-- ---------------------------------------------------------------------------------------------------------------
-- A list that only has controls for the rows on screen, so 200 games cost what 20 do.

--- `columns`: { {title, width share, field function(item) -> text, color}, ... }. `onPick(item, double)`.
local function VirtualList(parent, columns, onPick)
    local list = Group(parent, 'launcher list')
    list.items = {}
    list.top = 1
    list.rows = {}
    list.selectedKey = false
    list.hoverRow = false

    local header = Group(list)
    LayoutHelpers.AtLeftTopIn(header, list, 0, 0)
    header.Right:Set(list.Right)
    LayoutHelpers.SetHeight(header, 24)
    local body = Group(list)
    body.Left:Set(list.Left)
    body.Right:Set(function() return list.Right() - LayoutHelpers.ScaleNumber(14) end)
    body.Top:Set(function() return header.Bottom() + LayoutHelpers.ScaleNumber(2) end)
    body.Bottom:Set(list.Bottom)
    list.body = body

    local function ColumnLeft(index, of)
        local share = 0
        for i = 1, index - 1 do
            share = share + columns[i][2]
        end
        return function() return of.Left() + math.floor(share * of.Width()) + LayoutHelpers.ScaleNumber(8) end
    end
    local function ColumnRight(index, of)
        local share = 0
        for i = 1, index do
            share = share + columns[i][2]
        end
        return function() return of.Left() + math.floor(share * of.Width()) - LayoutHelpers.ScaleNumber(4) end
    end

    for index, column in columns do
        local title = Cell(header, 12, Colors.dim)
        title.Left:Set(ColumnLeft(index, body))
        title.Right:Set(ColumnRight(index, body))
        LayoutHelpers.AtVerticalCenterIn(title, header)
        title:SetText(column[1])
    end
    local line = Rect(list, FlatPanel.Border)
    line.Left:Set(list.Left)
    line.Right:Set(list.Right)
    line.Top:Set(header.Bottom)
    line.Height:Set(1)

    local function VisibleCount()
        return math.max(1, math.floor(body.Height() / LayoutHelpers.ScaleNumber(kRowHeight)))
    end

    local function MakeRow(index)
        local row = Rect(body, Colors.row)
        row.Left:Set(body.Left)
        row.Right:Set(body.Right)
        row.Top:Set(function() return body.Top() + (index - 1) * LayoutHelpers.ScaleNumber(kRowHeight) end)
        LayoutHelpers.SetHeight(row, kRowHeight)
        row.Width:Set(function() return row.Right() - row.Left() end)
        row.cells = {}
        for c, column in columns do
            local cell = Cell(row, 13, column[4] or Colors.text)
            cell.Left:Set(ColumnLeft(c, body))
            cell.Right:Set(ColumnRight(c, body))
            LayoutHelpers.AtVerticalCenterIn(cell, row)
            cell.Depth:Set(function() return row.Depth() + 1 end)
            row.cells[c] = cell
        end
        row.HandleEvent = function(self, event)
            if event.Type == 'WheelRotation' then
                list:ScrollLines(nil, event.WheelRotation > 0 and -3 or 3)
                return true
            end
            if not self.item then
                return false
            end
            if event.Type == 'MouseEnter' then
                list.hoverRow = self
                list:Paint()
            elseif event.Type == 'MouseExit' then
                if list.hoverRow == self then
                    list.hoverRow = false
                end
                list:Paint()
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                list.selectedKey = self.item.key
                list:Paint()
                onPick(self.item, false)
                return true
            elseif event.Type == 'ButtonDClick' and event.Modifiers.Left then
                list.selectedKey = self.item.key
                list:Paint()
                onPick(self.item, true)
                return true
            end
            return false
        end
        return row
    end

    function list:EnsureRows()
        local wanted = VisibleCount()
        if table.getn(self.rows) == wanted then
            return
        end
        for _, row in self.rows do
            row:Destroy()
        end
        self.rows = {}
        self.hoverRow = false
        for i = 1, wanted do
            self.rows[i] = MakeRow(i)
        end
    end

    function list:SetItems(items)
        self.items = items
        local maxTop = math.max(1, table.getn(items) - VisibleCount() + 1)
        self.top = math.min(self.top, maxTop)
        self:Paint()
    end

    function list:Selected()
        for _, item in self.items do
            if item.key == self.selectedKey then
                return item
            end
        end
        return nil
    end

    function list:Paint()
        self:EnsureRows()
        for i, row in self.rows do
            local item = self.items[self.top + i - 1]
            row.item = item
            if item then
                for c, column in columns do
                    SetTextIfChanged(row.cells[c], column[3](item) or '')
                    local color = item.color or column[4] or Colors.text
                    if row.cells[c].shownColor ~= color then
                        row.cells[c].shownColor = color
                        row.cells[c]:SetColor(color)
                    end
                end
                local fill = Colors.row
                if item.key == self.selectedKey then
                    fill = Colors.rowSelected
                elseif self.hoverRow == row then
                    fill = Colors.rowOver
                end
                row:SetSolidColor(fill)
            else
                for c = 1, table.getn(columns) do
                    SetTextIfChanged(row.cells[c], '')
                end
                row:SetSolidColor(Colors.row)
            end
        end
        if self.OnScrolled then
            self:OnScrolled()
        end
    end

    -- What maui's Scrollbar asks of the control it scrolls.
    function list:GetScrollValues(axis)
        local count = table.getn(self.items)
        return 1, math.max(count, 1), self.top, math.min(self.top + VisibleCount() - 1, math.max(count, 1))
    end

    function list:ScrollLines(axis, delta)
        self:ScrollSetTop(axis, self.top + math.floor(delta))
    end

    function list:ScrollPages(axis, delta)
        self:ScrollSetTop(axis, self.top + math.floor(delta) * VisibleCount())
    end

    function list:ScrollSetTop(axis, top)
        local maxTop = math.max(1, table.getn(self.items) - VisibleCount() + 1)
        top = math.max(1, math.min(math.floor(top), maxTop))
        if top ~= self.top then
            self.top = top
            self:Paint()
        end
    end

    function list:IsScrollable(axis)
        return true
    end

    -- Placed along the rows' right edge; it scrolls the list, which holds the scroll calls.
    local scrollbar = UIUtil.CreateLobbyVertScrollbar(body, 0, 0, 0)
    scrollbar:SetScrollable(list)
    return list
end

-- ---------------------------------------------------------------------------------------------------------------
-- The online page: FAF's games.

local function RatingText(game)
    if not game.ratingMin and not game.ratingMax then
        return ''
    end
    local low = game.ratingMin and tostring(math.floor(game.ratingMin)) or 'any'
    local high = game.ratingMax and tostring(math.floor(game.ratingMax)) or 'any'
    return low .. ' - ' .. high
end

local function ModName(id)
    for _, mod in FeaturedMods do
        if mod.id == id then
            return mod.name
        end
    end
    return id or ''
end

--- Why this build can't play a game right now, or nil.
local function WhyNotJoinable(game, status)
    if game.state ~= 'open' then
        return 'The game has started.'
    end
    if status.loadedMod == '' then
        return 'This game was not started on FAF\'s game files (/init init_faf.lua).'
    end
    if game.featuredMod ~= '' and game.featuredMod ~= status.loadedMod then
        return 'It runs ' .. ModName(game.featuredMod) .. '; this game has ' .. ModName(status.loadedMod) ..
            ' loaded. Switching inside the game comes later; start the game with /init init_' .. game.featuredMod ..
            '.lua for now.'
    end
    if game.players >= game.maxPlayers and game.maxPlayers > 0 then
        return 'The game is full.'
    end
    return nil
end

local function BuildOnlinePage(launcher, page)
    local view = {}
    launcher.online = view

    local title = Label(page, 'ONLINE GAMES', 22, Colors.text, UIUtil.titleFont)
    LayoutHelpers.AtLeftTopIn(title, page, 20, 14)
    view.status = Cell(page, 13, Colors.dim)
    LayoutHelpers.AtLeftTopIn(view.status, page, 20, 46)
    LayoutHelpers.AtRightIn(view.status, page, 340)

    view.signButton = FlatButton(page, 'Sign in', 120, function()
        local status = FafOnline_Status()
        if status.signIn == 'signedin' then
            FafOnline_SignOut()
        elseif status.signIn == 'waiting' or status.signIn == 'working' then
            FafOnline_CancelSignIn()
        else
            FafOnline_SignIn()
        end
        launcher:Refresh()
    end)
    LayoutHelpers.AtRightTopIn(view.signButton, page, 20, 18)
    view.hostButton = FlatButton(page, 'Host game', 140, function()
        launcher:OpenHostDialog()
    end, true)
    LayoutHelpers.LeftOf(view.hostButton, view.signButton, 10)

    if not Online() then
        local text = Label(page, 'Online play is not part of this build of the game.', 16, Colors.dim)
        LayoutHelpers.AtCenterIn(text, page)
        view.signButton:Hide()
        view.hostButton:Hide()
        view.unavailable = true
        return
    end

    -- Signed out or signing in: one box in the middle.
    local signIn = Group(page, 'sign in')
    LayoutHelpers.SetDimensions(signIn, 600, 220)
    LayoutHelpers.AtCenterIn(signIn, page)
    view.signIn = signIn
    view.signHead = Label(signIn, 'Sign in to FAF to see and join its games.', 18, Colors.text)
    LayoutHelpers.AtHorizontalCenterIn(view.signHead, signIn)
    LayoutHelpers.AtTopIn(view.signHead, signIn, 0)
    view.signText = Label(signIn, '', 14, Colors.dim)
    LayoutHelpers.AtHorizontalCenterIn(view.signText, signIn)
    LayoutHelpers.AtTopIn(view.signText, signIn, 36)
    view.signCode = Label(signIn, '', 34, Colors.accent, UIUtil.titleFont)
    LayoutHelpers.AtHorizontalCenterIn(view.signCode, signIn)
    LayoutHelpers.AtTopIn(view.signCode, signIn, 70)
    view.signUrl = Label(signIn, '', 13, Colors.dim)
    LayoutHelpers.AtHorizontalCenterIn(view.signUrl, signIn)
    LayoutHelpers.AtTopIn(view.signUrl, signIn, 124)
    view.openPage = FlatButton(signIn, 'Open the page again', 200, function()
        local status = FafOnline_Status()
        if status.url ~= '' then
            OpenURL(status.url)
        end
    end)
    LayoutHelpers.AtHorizontalCenterIn(view.openPage, signIn)
    LayoutHelpers.AtTopIn(view.openPage, signIn, 160)

    -- Signed in: filters, the list, the selected game and Join.
    local games = Group(page, 'games')
    games.Left:Set(page.Left)
    games.Right:Set(page.Right)
    games.Top:Set(function() return page.Top() + LayoutHelpers.ScaleNumber(72) end)
    games.Bottom:Set(page.Bottom)
    view.games = games

    view.search = TextEdit(games, 280, 40, '')
    LayoutHelpers.AtLeftTopIn(view.search, games, 20, 0)
    view.search.edit.OnTextChanged = function(self, newText, oldText)
        launcher:Refresh()
    end
    view.searchHint = Label(view.search, 'Search title, map or host', 13, Colors.dim)
    LayoutHelpers.AtLeftIn(view.searchHint, view.search, 8)
    LayoutHelpers.AtVerticalCenterIn(view.searchHint, view.search)
    view.searchHint.Depth:Set(function() return view.search.Depth() + 3 end)

    view.showRunning = false
    view.runningButton = ChoiceButton(games, 'Show started games', 170, function(self)
        view.showRunning = not view.showRunning
        self.selected = view.showRunning
        self:Paint(true)
        launcher:Refresh()
    end)
    LayoutHelpers.RightOf(view.runningButton, view.search, 10)
    view.runningButton:Paint(false)

    view.list = VirtualList(games, {
        { 'GAME', 0.31, function(g) return (g.password and '[locked] ' or '') .. g.title end },
        { 'MAP', 0.19, function(g) return g.map end },
        { 'PLAYERS', 0.09, function(g) return string.format('%d / %d', g.players, g.maxPlayers) end },
        { 'MOD', 0.12, function(g) return ModName(g.featuredMod) end },
        { 'RATING', 0.12, function(g) return RatingText(g) end },
        { 'HOST', 0.17, function(g) return g.host end },
    }, function(item, double)
        launcher:Refresh()
        if double then
            launcher:JoinSelected()
        end
    end)
    view.list.Left:Set(function() return games.Left() + LayoutHelpers.ScaleNumber(20) end)
    view.list.Right:Set(function() return games.Right() - LayoutHelpers.ScaleNumber(20) end)
    view.list.Top:Set(function() return view.search.Bottom() + LayoutHelpers.ScaleNumber(12) end)
    view.list.Bottom:Set(function() return games.Bottom() - LayoutHelpers.ScaleNumber(62) end)

    view.footer = Cell(games, 13, Colors.dim)
    view.footer.Left:Set(function() return games.Left() + LayoutHelpers.ScaleNumber(20) end)
    view.footer.Right:Set(function() return games.Right() - LayoutHelpers.ScaleNumber(200) end)
    view.footer.Bottom:Set(function() return games.Bottom() - LayoutHelpers.ScaleNumber(26) end)
    view.joinButton = FlatButton(games, 'Join', 160, function()
        launcher:JoinSelected()
    end, true)
    LayoutHelpers.AtRightIn(view.joinButton, games, 20)
    LayoutHelpers.AtBottomIn(view.joinButton, games, 16)
end

local function SortGames(a, b)
    if (a.state == 'open') ~= (b.state == 'open') then
        return a.state == 'open'
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
    for _, text in { game.title, game.map, game.host } do
        if string.find(string.lower(text or ''), filter, 1, true) then
            return true
        end
    end
    return false
end

local function RefreshOnline(launcher)
    local view = launcher.online
    if not view or view.unavailable then
        return
    end
    local status = FafOnline_Status()
    view.lastStatus = status
    local page = FafOnline_TakePageToOpen()
    if page then
        OpenURL(page)
    end

    local signedIn = status.signIn == 'signedin'
    local waiting = status.signIn == 'waiting' or status.signIn == 'working'
    FlatPanel.SetVisible(view.signIn, not signedIn)
    FlatPanel.SetVisible(view.games, signedIn)
    view.signButton:SetLabel(signedIn and 'Sign out' or (waiting and 'Cancel' or 'Sign in'))
    view.hostButton:SetEnabled(signedIn and status.lobby == 'signedin' and status.match ~= 'preparing' and
        status.match ~= 'running')

    local line
    if signedIn then
        local lobby = ({ off = 'not connected', connecting = 'connecting to FAF', signedin = 'in FAF\'s lobby',
            failed = 'FAF\'s lobby failed' })[status.lobby] or status.lobby
        line = 'Signed in as ' .. status.login .. ' - ' .. lobby
        if status.lobby == 'failed' and status.lobbyMessage ~= '' then
            line = line .. ': ' .. status.lobbyMessage
        end
        if status.loadedMod ~= '' then
            line = line .. ' - game files: ' .. ModName(status.loadedMod)
        end
    elseif waiting then
        line = 'Signing in'
    else
        line = 'Not signed in'
    end
    SetTextIfChanged(view.status, line)

    if not signedIn then
        if waiting and status.code ~= '' then
            SetTextIfChanged(view.signHead, 'Approve the sign-in in your browser')
            SetTextIfChanged(view.signText, 'The page should have opened. Check that it shows this code:')
            SetTextIfChanged(view.signCode, status.code)
            SetTextIfChanged(view.signUrl, string.format('%s   (%d s left)', status.url, status.secondsLeft))
            FlatPanel.SetVisible(view.openPage, true)
        else
            SetTextIfChanged(view.signHead, waiting and 'Asking FAF for a sign-in code' or
                'Sign in to FAF to see and join its games.')
            SetTextIfChanged(view.signText, status.message ~= '' and status.message or
                'Your browser opens FAF\'s page; nothing else is needed.')
            SetTextIfChanged(view.signCode, '')
            SetTextIfChanged(view.signUrl, '')
            FlatPanel.SetVisible(view.openPage, false)
        end
        return
    end

    FlatPanel.SetVisible(view.searchHint, view.search.edit:GetText() == '')
    local filter = string.lower(view.search.edit:GetText())
    local items = {}
    local open = 0
    local all = FafOnline_Games()
    for _, game in all do
        if game.state == 'open' then
            open = open + 1
        end
        if (view.showRunning or game.state == 'open') and Matches(game, filter) then
            game.key = game.uid
            if WhyNotJoinable(game, status) then
                game.color = Colors.dim
            end
            table.insert(items, game)
        end
    end
    table.sort(items, SortGames)
    view.list:SetItems(items)

    local selected = view.list:Selected()
    local footer
    local footerColor = Colors.dim
    if status.match == 'preparing' or status.match == 'running' then
        footer = status.matchMessage ~= '' and status.matchMessage or 'Starting the game'
        footerColor = Colors.accent
    elseif status.match == 'failed' and status.matchMessage ~= '' then
        footer = status.matchMessage
        footerColor = Colors.bad
    elseif launcher.lastError then
        footer = launcher.lastError
        footerColor = Colors.bad
    elseif selected then
        local why = WhyNotJoinable(selected, status)
        footer = why or (selected.title .. ' on ' .. selected.map .. ', hosted by ' .. selected.host)
        footerColor = why and Colors.warn or Colors.text
    else
        footer = string.format('%d open %s, %d shown. Double-click a game to join it.', open,
            open == 1 and 'game' or 'games', table.getn(items))
    end
    SetTextIfChanged(view.footer, footer)
    if view.footer.shownColor ~= footerColor then
        view.footer.shownColor = footerColor
        view.footer:SetColor(footerColor)
    end
    view.joinButton:SetEnabled(selected ~= nil and WhyNotJoinable(selected, status) == nil and
        status.match ~= 'preparing' and status.match ~= 'running')
end

-- ---------------------------------------------------------------------------------------------------------------
-- The host dialog.

local function MapFolder(scenarioPath)
    local _, _, folder = string.find(scenarioPath or '', '^/maps/([^/]+)/')
    return folder and string.lower(folder) or nil
end

local mapNames = {}
local function MapName(path)
    if mapNames[path] == nil then
        local ok, scenario = pcall(import('/lua/ui/maputil.lua').LoadScenario, path)
        mapNames[path] = ok and scenario and scenario.name and LOC(scenario.name) or false
    end
    return mapNames[path] or MapFolder(path) or path
end

--- The frame's size in layout units (pixels over the UI scale).
local function FrameUnits()
    local frame = GetFrame(0)
    return LayoutHelpers.InvScaleNumber(frame.Width()), LayoutHelpers.InvScaleNumber(frame.Height())
end

local function OpenHostDialog(launcher)
    local status = FafOnline_Status()
    local frameWidth, frameHeight = FrameUnits()
    local cover = Modal(launcher.root, math.min(760, frameWidth - 24), math.max(440, math.min(560, frameHeight - 24)))
    local panel = cover.panel
    launcher.hostDialog = cover

    local head = Label(panel, 'HOST A GAME ON FAF', 20, Colors.text, UIUtil.titleFont)
    LayoutHelpers.AtLeftTopIn(head, panel, 24, 18)
    local note = Label(panel, 'Players on FAF\'s own client see it and can join.', 13, Colors.dim)
    LayoutHelpers.AtLeftTopIn(note, panel, 24, 44)

    local function Caption(text, top)
        local caption = Label(panel, text, 13, Colors.dim)
        LayoutHelpers.AtLeftTopIn(caption, panel, 24, top)
        return caption
    end

    Caption('Title', 72)
    local titleEdit = TextEdit(panel, 330, 60, Prefs.GetFromCurrentProfile('fafre_host_title') or
        ((status.login ~= '' and status.login or 'My') .. '\'s game'))
    LayoutHelpers.AtLeftTopIn(titleEdit, panel, 24, 90)

    Caption('Password (empty: none)', 122)
    local passwordEdit = TextEdit(panel, 330, 40, '')
    LayoutHelpers.AtLeftTopIn(passwordEdit, panel, 24, 140)

    Caption('Featured mod', 172)
    local modButtons = {}
    local chosenMod = status.loadedMod ~= '' and status.loadedMod or 'faf'
    local modNote = Label(panel, '', 12, Colors.dim)
    for i, mod in FeaturedMods do
        local id = mod.id
        local button = ChoiceButton(panel, mod.name, 160, function(self)
            chosenMod = id
            for _, other in modButtons do
                other.selected = other.id == id
                other:Paint(false)
            end
        end)
        button.id = id
        button.enabled = id == status.loadedMod
        button.selected = id == chosenMod
        LayoutHelpers.AtLeftTopIn(button, panel, 24 + math.mod(i - 1, 2) * 168, 190 + math.floor((i - 1) / 2) * 32)
        button:Paint(false)
        modButtons[i] = button
    end
    modNote:SetClipToWidth(true)
    LayoutHelpers.AtLeftTopIn(modNote, panel, 24, 256)
    modNote.Right:Set(function() return panel.Left() + LayoutHelpers.ScaleNumber(360) end)
    modNote:SetText('Others: start the game on their files for now.')

    Caption('Who sees it', 278)
    local visibility = 'public'
    local visButtons = {}
    for i, choice in { { 'public', 'Everyone' }, { 'friends', 'Friends only' } } do
        local value = choice[1]
        local button = ChoiceButton(panel, choice[2], 160, function(self)
            visibility = value
            for _, other in visButtons do
                other.selected = other.value == value
                other:Paint(false)
            end
        end)
        button.value = value
        button.selected = value == visibility
        LayoutHelpers.AtLeftTopIn(button, panel, 24 + (i - 1) * 168, 296)
        button:Paint(false)
        visButtons[i] = button
    end

    Caption('Rating range (empty: any)', 332)
    local minEdit = TextEdit(panel, 100, 5, '')
    LayoutHelpers.AtLeftTopIn(minEdit, panel, 24, 350)
    local dash = Label(panel, '-', 14, Colors.dim)
    LayoutHelpers.RightOf(dash, minEdit, 8)
    local maxEdit = TextEdit(panel, 100, 5, '')
    LayoutHelpers.RightOf(maxEdit, dash, 8)
    local enforce = false
    local enforceButton = ChoiceButton(panel, 'Enforce', 90, function(self)
        enforce = not enforce
        self.selected = enforce
        self:Paint(true)
    end)
    LayoutHelpers.RightOf(enforceButton, maxEdit, 10)
    enforceButton:Paint(false)

    -- Maps on this computer, by folder; their names are read only for the rows shown.
    Caption('Map', 72).Left:Set(function() return panel.Left() + LayoutHelpers.ScaleNumber(380) end)
    local mapSearch = TextEdit(panel, 356, 40, '')
    LayoutHelpers.AtLeftTopIn(mapSearch, panel, 380, 90)
    local scenarios = {}
    for _, path in DiskFindFiles('/maps', '*_scenario.lua') do
        table.insert(scenarios, path)
    end
    table.sort(scenarios)
    local last = Prefs.GetFromCurrentProfile('fafre_host_map') or Prefs.GetFromCurrentProfile('LastScenario') or
        UIUtil.defaultScenario
    local mapList = VirtualList(panel, {
        { 'MAP', 0.62, function(item) return MapName(item.path) end },
        { 'FOLDER', 0.38, function(item) return item.folder end, Colors.dim },
    }, function(item, double) end)
    mapList.Left:Set(function() return panel.Left() + LayoutHelpers.ScaleNumber(380) end)
    mapList.Right:Set(function() return panel.Right() - LayoutHelpers.ScaleNumber(24) end)
    mapList.Top:Set(function() return mapSearch.Bottom() + LayoutHelpers.ScaleNumber(8) end)
    mapList.Bottom:Set(function() return panel.Bottom() - LayoutHelpers.ScaleNumber(70) end)
    mapList.selectedKey = last
    local function FillMaps()
        local filter = string.lower(mapSearch.edit:GetText())
        local items = {}
        for _, path in scenarios do
            local folder = MapFolder(path)
            if folder and (filter == '' or string.find(folder, filter, 1, true)) then
                table.insert(items, { key = path, path = path, folder = folder })
            end
        end
        mapList:SetItems(items)
    end
    mapSearch.Right:Set(function() return panel.Right() - LayoutHelpers.ScaleNumber(24) end)
    mapSearch.Width:Set(function() return mapSearch.Right() - mapSearch.Left() end)
    mapSearch.edit.OnTextChanged = function(self, newText, oldText)
        mapList.top = 1
        FillMaps()
    end
    FillMaps()
    for index, item in mapList.items do
        if item.key == last then
            mapList:ScrollSetTop(nil, index - 3)
        end
    end

    local errorText = Cell(panel, 13, Colors.bad)
    errorText.Left:Set(function() return panel.Left() + LayoutHelpers.ScaleNumber(24) end)
    errorText.Right:Set(function() return panel.Right() - LayoutHelpers.ScaleNumber(300) end)
    errorText.Bottom:Set(function() return panel.Bottom() - LayoutHelpers.ScaleNumber(24) end)

    local function Close()
        launcher.hostDialog = false
        cover:Destroy()
    end
    local cancel = FlatButton(panel, 'Cancel', 120, Close)
    LayoutHelpers.AtRightIn(cancel, panel, 24)
    LayoutHelpers.AtBottomIn(cancel, panel, 18)
    local host = FlatButton(panel, 'Host', 140, function()
        local map = mapList:Selected()
        if not map then
            errorText:SetText('Pick a map.')
            return
        end
        local request = {
            title = titleEdit.edit:GetText(),
            map = map.folder,
            mod = chosenMod,
            visibility = visibility,
            password = passwordEdit.edit:GetText(),
            ratingMin = tonumber(minEdit.edit:GetText()),
            ratingMax = tonumber(maxEdit.edit:GetText()),
            enforceRating = enforce,
        }
        if request.title == '' then
            errorText:SetText('The game needs a title.')
            return
        end
        local ok, why = FafOnline_Host(request)
        if not ok then
            errorText:SetText('FAF refused: ' .. tostring(why))
            return
        end
        Prefs.SetToCurrentProfile('fafre_host_title', request.title)
        Prefs.SetToCurrentProfile('fafre_host_map', map.path)
        LOG('LAUNCHER: hosting ' .. request.map .. ' on ' .. request.mod)
        Close()
        launcher:Refresh()
    end, true)
    LayoutHelpers.LeftOf(host, cancel, 10)

    import('/lua/ui/uimain.lua').SetEscapeHandler(function()
        Close()
        launcher:SetHomeEscape()
    end)
    return cover
end

local function AskPassword(launcher, game)
    local cover = Modal(launcher.root, 460, 190)
    local panel = cover.panel
    local head = Label(panel, 'PASSWORD', 18, Colors.text, UIUtil.titleFont)
    LayoutHelpers.AtLeftTopIn(head, panel, 20, 16)
    local text = Cell(panel, 13, Colors.dim)
    LayoutHelpers.AtLeftTopIn(text, panel, 20, 48)
    LayoutHelpers.AtRightIn(text, panel, 20)
    text:SetText(game.title .. ' needs a password.')
    local edit = TextEdit(panel, 420, 40, '')
    LayoutHelpers.AtLeftTopIn(edit, panel, 20, 80)
    edit.edit:AcquireFocus()
    local function Join()
        local password = edit.edit:GetText()
        cover:Destroy()
        launcher:Join(game, password)
    end
    edit.edit.OnEnterPressed = function(self, value)
        Join()
        return true
    end
    local cancel = FlatButton(panel, 'Cancel', 110, function() cover:Destroy() end)
    LayoutHelpers.AtRightIn(cancel, panel, 20)
    LayoutHelpers.AtBottomIn(cancel, panel, 16)
    local join = FlatButton(panel, 'Join', 110, Join, true)
    LayoutHelpers.LeftOf(join, cancel, 10)
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
    if self.page == 'online' then
        local ok, err = pcall(RefreshOnline, self)
        if not ok and not self.refreshFailed then
            self.refreshFailed = true
            WARN('LAUNCHER: the online page failed to update: ' .. tostring(err))
        end
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
        Message(self.root, 'Host game', 'The host dialog failed to open: ' .. tostring(err))
    end
end

function Launcher:Join(game, password)
    local ok, why = FafOnline_Join(game.uid, password)
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
    if not view or not view.list then
        return
    end
    local game = view.list:Selected()
    if not game or WhyNotJoinable(game, view.lastStatus or FafOnline_Status()) then
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
        FlatPanel.SetVisible(page, name == self.page)
    end
    for _, button in self.navButtons do
        button:Paint(false)
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
        local back = FlatButton(captured, '< Launcher', 130, function() fafMenuBack() end)
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
    Prefs.SetToCurrentProfile('fafre_launcher_page', name)
    for pageName, page in self.pages do
        FlatPanel.SetVisible(page, pageName == name)
    end
    for _, button in self.navButtons do
        button:Paint(false)
    end
    self:Refresh()
end

local kNavStep = 36
local kNavSeparator = 14

local function NavButton(launcher, parent, text, action, page)
    local button = Rect(parent, '00000000')
    LayoutHelpers.SetHeight(button, kNavStep - 2)
    button.label = Label(button, text, 16, Colors.text, UIUtil.bodyFont)
    LayoutHelpers.AtLeftIn(button.label, button, 22)
    LayoutHelpers.AtVerticalCenterIn(button.label, button)
    button.label.Depth:Set(function() return button.Depth() + 2 end)
    button.bar = Rect(button, Colors.accent)
    LayoutHelpers.AtLeftTopIn(button.bar, button, 0, 5)
    LayoutHelpers.SetDimensions(button.bar, 3, kNavStep - 12)
    button.bar.Depth:Set(function() return button.Depth() + 1 end)
    button.bar:DisableHitTest()
    button.Paint = function(self, over)
        local selected = page ~= nil and launcher.page == page -- a boolean: SetVisible compares it with IsHidden()
        self:SetSolidColor(selected and 'ff163242' or (over and 'ff142229' or '00000000'))
        self.label:SetColor(selected and Colors.accent or (over and 'ffffffff' or Colors.text))
        FlatPanel.SetVisible(self.bar, selected)
    end
    button.HandleEvent = function(self, event)
        if event.Type == 'MouseEnter' then
            PlaySound(Sound({ Cue = 'UI_Menu_Rollover_Sml', Bank = 'Interface' }))
            self:Paint(true)
        elseif event.Type == 'MouseExit' then
            self:Paint(false)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            ClickSound()
            action()
            return true
        end
        return false
    end
    button.page = page
    return button
end

local function Build(launcher)
    local root = UIUtil.CreateScreenGroup(GetFrame(0), 'Launcher ScreenGroup')
    launcher.root = root
    root.OnDestroy = function()
        launcher:StopSounds()
    end

    local back = Rect(root, 'ff05090c')
    LayoutHelpers.FillParent(back, root)
    SizeFromEdges(back)
    if Prefs.GetOption('mainmenu_bgmovie') then
        local movie = Movie(root)
        movie:Set('/movies/main_menu.sfd')
        LayoutHelpers.AtCenterIn(movie, root)
        movie:Loop(true)
        movie:Play()
        movie.Height:Set(root.Height)
        movie.Width:Set(function() return 1824 * root.Height() / 1024 end)
        movie.Depth:Set(function() return back.Depth() + 1 end)
        launcher.movie = movie
        local dim = Rect(root, '90000000')
        LayoutHelpers.FillParent(dim, root)
        SizeFromEdges(dim)
        dim.Depth:Set(function() return movie.Depth() + 1 end)
        dim:DisableHitTest()
    end

    local body = Group(root, 'launcher body')
    LayoutHelpers.FillParent(body, root)
    body.Depth:Set(function() return root.Depth() + 10 end)
    launcher.body = body

    local title = Label(body, 'FORGED ALLIANCE', 26, Colors.text, UIUtil.titleFont)
    LayoutHelpers.AtLeftTopIn(title, body, 26, 12)
    local versionOk, version = pcall(function() return import('/lua/version.lua').GetVersion() end)
    local sub = Label(body, 'Forged Alliance Forever' .. (versionOk and version and (' ' .. tostring(version)) or ''),
        13, Colors.dim)
    LayoutHelpers.Below(sub, title, 2)

    local nav = FlatPanel.FlatPanel(body, 'launcher nav')
    LayoutHelpers.AtLeftTopIn(nav, body, 20, 72)
    LayoutHelpers.SetWidth(nav, 220)
    nav.Bottom:Set(function() return body.Bottom() - LayoutHelpers.ScaleNumber(16) end)

    local content = Group(body, 'launcher content')
    content.Left:Set(function() return nav.Right() + LayoutHelpers.ScaleNumber(16) end)
    content.Right:Set(function() return body.Right() - LayoutHelpers.ScaleNumber(20) end)
    content.Top:Set(nav.Top)
    content.Bottom:Set(nav.Bottom)

    local onlinePage = FlatPanel.FlatPanel(content, 'launcher online')
    LayoutHelpers.FillParent(onlinePage, content)
    launcher.pages = { online = onlinePage }
    BuildOnlinePage(launcher, onlinePage)

    local entries = {
        { 'Online games', function() launcher:ShowPage('online') end, 'online' },
        false,
        { 'Skirmish', function() launcher:Skirmish() end },
        { 'Campaign', function() launcher:Campaign() end },
        { 'Multiplayer LAN', function() launcher:Lan() end },
        { 'Replays', function() launcher:Replays() end },
        { 'Mods', function() launcher:Mods() end },
        { 'Options', function() launcher:Options() end },
        false,
        { 'FAF main menu', function() launcher:FafMenu() end },
        { 'Exit', function() launcher:Exit() end },
    }
    launcher.navButtons = {}
    local top = 10
    for _, entry in entries do
        if entry then
            local button = NavButton(launcher, nav, entry[1], entry[2], entry[3])
            LayoutHelpers.AtLeftTopIn(button, nav, 1, top)
            button.Right:Set(function() return nav.Right() - 1 end)
            button.Width:Set(function() return button.Right() - button.Left() end)
            button.Depth:Set(function() return nav.Depth() + 5 end)
            table.insert(launcher.navButtons, button)
            top = top + kNavStep
        else
            local line = Rect(nav, FlatPanel.Border)
            LayoutHelpers.AtLeftTopIn(line, nav, 16, top + kNavSeparator / 2 - 1)
            line.Right:Set(function() return nav.Right() - LayoutHelpers.ScaleNumber(16) end)
            line.Height:Set(1)
            line.Depth:Set(function() return nav.Depth() + 5 end)
            top = top + kNavSeparator
        end
    end

    -- Updates the online page while the launcher shows.
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
    if testJoinDone or not current or current.page ~= 'online' or not current.online or not current.online.list then
        return
    end
    local view = current.online
    for _, item in view.list.items do
        if not item.color then
            -- Listed for 6 s first, so the list can be seen (and photographed) as a player sees it.
            if not testJoinSeen then
                testJoinSeen = GetSystemTimeSeconds()
                LOG('LAUNCHER TEST: listed ' .. item.title .. ' (' .. item.uid .. ')')
                return
            elseif GetSystemTimeSeconds() - testJoinSeen < 6 then
                return
            end
            testJoinDone = true
            view.list.selectedKey = item.key
            view.list:Paint()
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
        if Online() and FafOnline_Status().signIn == 'signedin' then
            for i = 1, 20 do
                if FafOnline_Status().lobby == 'signedin' then
                    break
                end
                Wait(1)
            end
            Step('online page, FAF lobby ' .. FafOnline_Status().lobby .. ', ' ..
                table.getn(FafOnline_Games()) .. ' games listed')
            current:OpenHostDialog()
            Wait(2)
            Step(current.hostDialog and 'host dialog open' or 'host dialog did not open')
            if current.hostDialog then
                local panel = current.hostDialog.panel
                local frame = GetFrame(0)
                Step(string.format('host dialog at %d,%d size %dx%d in a %dx%d frame', panel.Left(), panel.Top(),
                    panel.Width(), panel.Height(), frame.Width(), frame.Height()))
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
            Step(screen .. (launcher.screen and ' still open' or ' closed, back on the launcher'))
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
