-- The launcher's Tournaments page (beside Leaderboards): FAF's tournaments as the FAF client reads them (FAF's API,
-- /challonge/v1/tournaments.json, Challonge's records), by state: sign-up open, upcoming, running, finished. The
-- chosen one's description, start, type and players, with its bracket and sign-up pages a click away (browser).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kTabs = { { 'all', 'All' }, { 'signup', 'Sign-up open' }, { 'upcoming', 'Upcoming' }, { 'running', 'Running' },
    { 'finished', 'Finished' } }
local kStateNames = { signup = 'Sign-up open', upcoming = 'Upcoming', running = 'Running', finished = 'Finished' }
local kStateColors = { signup = C.good, upcoming = C.accent, running = C.warn, finished = C.subtle }
local kStateOrder = { running = 1, signup = 2, upcoming = 3, finished = 4 }

local function Plain(html)
    local text = string.gsub(html or '', '<[bB][rR][^>]*>', '\n')
    text = string.gsub(text, '</[pP]>', '\n\n')
    text = string.gsub(text, '<[^>]*>', '')
    text = string.gsub(text, '&nbsp;', ' ')
    text = string.gsub(text, '&amp;', '&')
    text = string.gsub(text, '&quot;', '"')
    text = string.gsub(text, '&#39;', "'")
    text = string.gsub(text, '&lt;', '<')
    text = string.gsub(text, '&gt;', '>')
    text = string.gsub(text, '[ \t]+', ' ')
    text = string.gsub(text, '\n%s*\n%s*\n+', '\n\n')
    return (string.gsub(string.gsub(text, '^%s+', ''), '%s+$', ''))
end

local function Day(iso)
    return type(iso) == 'string' and string.sub(iso, 1, 10) or ''
end

local function When(iso)
    if type(iso) ~= 'string' or iso == '' then
        return ''
    end
    return rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(iso) or Day(iso)
end

local function TypeName(kind)
    kind = tostring(kind or '')
    return (string.gsub(string.gsub(kind, '^%l', string.upper), ' (%l)', function(c) return ' ' .. c end))
end

--- One tournament from Challonge's record ({tournament = {...}}), with its state against today (UTC).
local function Tournament(raw, today)
    local t = type(raw) == 'table' and (raw.tournament or raw) or {}
    local state
    if type(t.completed_at) == 'string' and t.completed_at ~= '' then
        state = 'finished'
    elseif type(t.start_at) == 'string' and t.start_at ~= '' and Day(t.start_at) > today then
        state = t.open_signup and 'signup' or 'upcoming'
    elseif type(t.start_at) == 'string' and t.start_at ~= '' then
        state = 'running'
    else
        state = t.open_signup and 'signup' or 'upcoming'
    end
    return {
        key = tostring(t.id or t.name), name = tostring(t.name or '?'), state = state, stateName = kStateNames[state],
        start = t.start_at, completed = t.completed_at, kind = TypeName(t.tournament_type),
        players = tonumber(t.participants_count) or 0, description = Plain(t.description),
        bracket = type(t.full_challonge_url) == 'string' and t.full_challonge_url ~= '' and t.full_challonge_url or nil,
        signup = t.open_signup and type(t.sign_up_url) == 'string' and t.sign_up_url ~= '' and t.sign_up_url or nil,
    }
end

function Build(launcher, page)
    local view = { tab = 'all', jobs = {} }
    launcher.tournamentsView = view

    local title = Theme.Title(page, 'Tournaments', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, kTabs, function(key)
        view.tab = key
        view:Paint()
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

    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Right:Set(page.Right)
    detail.Top:Set(function() return divider.Bottom() + Scale(18) end)
    detail.Bottom:Set(page.Bottom)
    LayoutHelpers.SetWidth(detail, 520)
    detail.Left:Set(function() return detail.Right() - detail.Width() end)
    detail.Height:Set(function() return detail.Bottom() - detail.Top() end)
    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(function() return detail.Left() - Scale(24) end)
    area.Top:Set(detail.Top)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    view.list = Widgets.VirtualList(area, {
        { 'Tournament', 0.42, function(item) return item.name end },
        { 'State', 0.16, function(item) return item.stateName end, C.accent },
        { 'Starts', 0.16, function(item) return Day(item.start) end, C.muted },
        { 'Type', 0.16, function(item) return item.kind end, C.muted },
        { 'Players', 0.1, function(item) return tostring(item.players) end, C.muted },
    }, function(item, double)
        view.chosen = item
        if double and item.bracket then
            OpenURL(item.bracket)
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

    local x = 24
    view.name = Theme.Text(detail, '', 20, C.text, true)
    LayoutHelpers.AtLeftTopIn(view.name, detail, x, 24)
    view.state = Theme.Tag(detail, '', C.accent)
    view.state.Left:Set(view.name.Left)
    view.state.Top:Set(function() return view.name.Bottom() + Scale(10) end)
    view.facts = {}
    local labels = { 'Starts', 'Finished', 'Type', 'Players' }
    for i, label in labels do
        local column = math.mod(i - 1, 2)
        local line = math.floor((i - 1) / 2)
        local key = Theme.Text(detail, string.upper(label), 10, C.subtle, true)
        key.Left:Set(function() return detail.Left() + Scale(x) + math.floor((detail.Width() - Scale(2 * x)) * column / 2) end)
        key.Top:Set(function() return view.state.Bottom() + Scale(18 + line * 46) end)
        local value = Theme.Text(detail, '', 15, C.text, true)
        value.Left:Set(key.Left)
        value.Top:Set(function() return key.Bottom() + Scale(4) end)
        view.facts[i] = value
    end
    local lastFact = view.facts[4]
    view.bracket = Theme.Button(detail, 'Open bracket', function()
        if view.chosen and view.chosen.bracket then
            LOG('LAUNCHER: tournaments: opening ' .. view.chosen.bracket)
            OpenURL(view.chosen.bracket)
        end
    end, 'primary', { icon = 'external', width = 200 })
    view.bracket.Right:Set(function() return detail.Right() - Scale(x) end)
    view.bracket.Bottom:Set(function() return detail.Bottom() - Scale(18) end)
    view.signupButton = Theme.Button(detail, 'Sign up', function()
        if view.chosen and view.chosen.signup then
            LOG('LAUNCHER: tournaments: opening ' .. view.chosen.signup)
            OpenURL(view.chosen.signup)
        end
    end, 'secondary', { icon = 'userCheck', width = 160 })
    view.signupButton.Right:Set(function() return view.bracket.Left() - Scale(10) end)
    view.signupButton.Bottom:Set(view.bracket.Bottom)
    view.description = Widgets.TextView(detail)
    view.description.Left:Set(function() return detail.Left() + Scale(x) end)
    view.description.Right:Set(function() return detail.Right() - Scale(16) end)
    view.description.Top:Set(function() return lastFact.Bottom() + Scale(20) end)
    view.description.Bottom:Set(function() return view.bracket.Top() - Scale(14) end)
    view.description.Width:Set(function() return view.description.Right() - view.description.Left() end)
    view.description.Height:Set(function() return view.description.Bottom() - view.description.Top() end)

    ----------------------------------------------------------------------------------------------------------------

    function view:Load()
        if not rawget(_G, 'FafLibrary_Api') then
            self.failure = 'This build has no FAF API access.'
            return
        end
        local id, why = FafLibrary_Api('/challonge/v1/tournaments.json', { ['page[size]'] = '100', ['page[number]'] = '1' })
        if not id then
            self.failure = tostring(why)
            return
        end
        self.failure = nil
        self.jobs.list = { id = id, done = function(data)
            local today = rawget(_G, 'FafLibrary_UtcDate') and string.sub(FafLibrary_UtcDate(0), 1, 10) or ''
            local list = {}
            for _, raw in (data or {}) do
                if type(raw) == 'table' then
                    table.insert(list, Tournament(raw, today))
                end
            end
            -- Running first, then open sign-ups and upcoming by their start, then finished, latest first.
            table.sort(list, function(a, b)
                local oa, ob = kStateOrder[a.state], kStateOrder[b.state]
                if oa ~= ob then
                    return oa < ob
                end
                if a.state == 'finished' then
                    return tostring(a.completed or '') > tostring(b.completed or '')
                end
                return tostring(a.start or '') < tostring(b.start or '')
            end)
            view.tournaments = list
            if not view.chosen and list[1] then
                view.chosen = list[1]
            end
            LOG('LAUNCHER: tournaments: ' .. table.getn(list) .. ' read')
        end }
    end

    function view:Shown()
        local shown = {}
        for _, item in (self.tournaments or {}) do
            if self.tab == 'all' or item.state == self.tab then
                table.insert(shown, item)
            end
        end
        return shown
    end

    function view:Poll()
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if not state or state.state ~= 'working' then
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: tournaments: ' .. tostring(err))
                    end
                else
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                end
            end
        end
    end

    function view:Paint()
        local counts = {}
        for _, item in (self.tournaments or {}) do
            counts.all = (counts.all or 0) + 1
            counts[item.state] = (counts[item.state] or 0) + 1
        end
        self.tabs:Set(self.tab, counts)
        Theme.SetVisible(self.loader, self.tournaments == nil and not self.failure)
        local shown = self:Shown()
        local note = ''
        if self.failure then
            note = 'The tournaments didn\'t load: ' .. self.failure
        elseif self.tournaments and table.getn(shown) == 0 then
            note = 'No tournament in this state.'
        end
        self.note:SetText(note, self.failure and C.bad or C.subtle)
        if self.list.items ~= shown and (self.shownTab ~= self.tab or self.shownFrom ~= self.tournaments) then
            self.shownTab = self.tab
            self.shownFrom = self.tournaments
            self.list.top = 1
            self.list:SetItems(shown)
            -- The chosen one stays while the tab shows it.
            local still = false
            for _, item in shown do
                still = still or item == self.chosen
            end
            if not still then
                self.chosen = shown[1]
            end
        end
        self.list.selectedKey = self.chosen and self.chosen.key or false
        self.list:Paint()

        local item = self.chosen
        Theme.SetText(self.name, item and item.name or '')
        Theme.SetVisible(self.state, item ~= nil)
        if item then
            self.state:SetTag(item.stateName, kStateColors[item.state] or C.accent)
        end
        local values = {
            item and When(item.start) or '', item and When(item.completed) or '', item and item.kind or '',
            item and tostring(item.players) or '',
        }
        for i, value in values do
            Theme.SetText(self.facts[i], value ~= '' and value or '-')
        end
        if self.describedFor ~= item then
            self.describedFor = item
            local blocks = {}
            for paragraph in string.gfind((item and item.description or '') .. '\n\n', '(.-)\n\n') do
                if paragraph ~= '' then
                    table.insert(blocks, { style = 'text', text = string.gsub(paragraph, '\n', ' ') })
                    table.insert(blocks, { style = 'gap', text = '' })
                end
            end
            if item and table.getn(blocks) == 0 then
                blocks = { { style = 'text', text = 'No description.' } }
            end
            self.description:SetBlocks(blocks)
        end
        self.bracket:SetEnabled(item ~= nil and item.bracket ~= nil)
        self.signupButton:SetEnabled(item ~= nil and item.signup ~= nil)
    end

    function view:Refresh()
        if not self.tournaments and not self.jobs.list and not self.failure then
            self:Load()
        end
        self:Poll()
        self:Paint()
    end

    return view
end
