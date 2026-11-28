-- Report a player, over the launcher: a report to FAF's moderators (FafLibrary_Report: FAF's API moderationReport, as
-- the FAF clients send it) with what happened, and the replay and the time in it when it happened in a game; and the
-- player's earlier reports with how each stands (FAF's API, /data/moderationReport filtered on the reporter). The
-- FAF Rust client's report dialog (ui/src/features/reporting at 70c88a5) is the model: one report per incident,
-- 10 to 4000 characters, a game's time needed with its replay id.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kMaxText = 4000
local current = false

-- FAF's report states (the API's reportStatus) as players read them, with a colour.
local kStatus = {
    AWAITING = { 'Waiting', C.gold },
    PROCESSING = { 'Being looked at', C.accent },
    COMPLETED = { 'Done', C.good },
    DISCARDED = { 'Closed', C.subtle },
}

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

local function Trim(text)
    return (string.gsub(string.gsub(text or '', '^%s+', ''), '%s+$', ''))
end

local apiId = false -- the signed-in player's id from FAF's API (/me), when the lobby hasn't listed them

--- The signed-in player's FAF id, or nil: from the lobby's player list, else from FAF's API.
function MyId(launcher)
    local login = (launcher.lastStatus or {}).login
    local me = login and login ~= '' and rawget(_G, 'FafOnline_Player') and FafOnline_Player(login)
    return (me and me.id) or apiId or nil
end

--- Asks FAF's API who is signed in (for a report sent while the lobby is away); `then` runs when it answers.
local function AskMe(view)
    if apiId or view.jobs.me or not rawget(_G, 'FafLibrary_Api') then
        return
    end
    local id = FafLibrary_Api('/me')
    if id then
        view.jobs.me = { id = id, done = function(doc)
            local data = doc and doc.data
            apiId = data and (data.id or (data.attributes and data.attributes.userId)) or false
            if apiId then
                apiId = tostring(apiId)
            end
        end }
    end
end

--- What's wrong with a report before it goes, or nil: the same checks as the engine's, said for the player.
function Check(text, game, time)
    local length = string.len(Trim(text))
    if length < 10 then
        return 'Describe what happened in 10 characters at least.'
    elseif length > kMaxText then
        return 'The description can be 4000 characters at most.'
    elseif game ~= '' and not string.find(game, '^%d+$') then
        return 'A replay id is a whole number (the number in the replay\'s name).'
    elseif game ~= '' and time == '' then
        return 'Give the time in the game it happened at, as near as you know it.'
    end
    return nil
end

--- Opens the report of `subject` = { id = FAF id, login, game = replay id (optional) }.
function Open(launcher, subject)
    if current then
        current:Close()
    end
    local width, height = Widgets.FrameUnits()
    local cover = Widgets.Modal(launcher.root, 860, math.min(580, height - 60))
    local panel = cover.panel
    local view = { launcher = launcher, subject = subject, cover = cover, jobs = {}, tab = 'new' }
    current = view

    local x = 26
    local title = Theme.Title(panel, 'Report ' .. tostring(subject.login or subject.id), 18, C.text)
    LayoutHelpers.AtLeftTopIn(title, panel, x, 22)
    local close = Theme.Button(panel, '', function() view:Close() end, 'ghost', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(close, panel, 16, 16)
    view.tabs = Widgets.Tabs(panel, { { 'new', 'New report' }, { 'history', 'Your reports' } }, function(key)
        view.tab = key
        if key == 'history' and not view.history and not view.jobs.history then
            view:LoadHistory()
        end
        view:Paint()
    end)
    view.tabs.Left:Set(title.Left)
    view.tabs.Top:Set(function() return title.Bottom() + Scale(14) end)
    view.tabs.Right:Set(function() return panel.Right() - Scale(x) end)

    -- New report.
    local form = Group(panel)
    form.Left:Set(title.Left)
    form.Right:Set(function() return panel.Right() - Scale(x) end)
    form.Top:Set(function() return view.tabs.Bottom() + Scale(16) end)
    form.Bottom:Set(function() return panel.Bottom() - Scale(20) end)
    Theme.SizeFromEdges(form)
    form:DisableHitTest()
    view.form = form
    local intro = Theme.Paragraph(form, 13, C.muted)
    intro.Left:Set(form.Left)
    intro.Right:Set(form.Right)
    intro.Top:Set(form.Top)
    intro:SetText('Reports go to FAF\'s moderators. Say what happened as plainly as you can, with the replay when it ' ..
        'was in a game, and send one report per incident.', C.muted)
    local what = Theme.Text(form, 'WHAT HAPPENED', 10, C.accent, true)
    what.Left:Set(form.Left)
    what.Top:Set(function() return intro.Bottom() + Scale(18) end)
    view.count = Theme.Text(form, '', 11, C.subtle)
    view.count.Right:Set(form.Right)
    LayoutHelpers.AtVerticalCenterIn(view.count, what)
    view.text = Theme.TextField(form, 808, 'What the player did, and when', 'edit', kMaxText)
    view.text.Left:Set(form.Left)
    view.text.Top:Set(function() return what.Bottom() + Scale(8) end)
    -- The whole text, wrapped, under the one-line field: what the moderators will read.
    view.preview = Theme.Paragraph(form, 12, C.text)
    view.preview.Left:Set(function() return form.Left() + Scale(2) end)
    view.preview.Right:Set(form.Right)
    view.preview.Top:Set(function() return view.text.Bottom() + Scale(8) end)
    local gameCaption = Theme.Text(form, 'IN A GAME?  (OPTIONAL)', 10, C.accent, true)
    gameCaption.Left:Set(form.Left)
    view.game = Theme.TextField(form, 240, 'Replay id', 'replays', 12)
    view.game.Left:Set(form.Left)
    view.time = Theme.TextField(form, 240, 'Time in the game (12:30)', 'clock', 40)
    view.time.Left:Set(function() return view.game.Right() + Scale(12) end)
    view.time.Top:Set(view.game.Top)
    local gameHint = Theme.Cell(form, 11, C.subtle)
    gameHint:SetText("The number in the replay's name.")
    gameHint.Right:Set(form.Right)
    gameHint.Left:Set(function() return view.time.Right() + Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(gameHint, view.game)
    view.status = Theme.Cell(form, 12, C.subtle)
    view.status.Left:Set(form.Left)
    view.status.Right:Set(function() return form.Right() - Scale(330) end)
    view.status.Bottom:Set(form.Bottom)
    view.send = Theme.Button(form, 'Send report', function() view:Send() end, 'danger', { icon = 'flag', width = 170 })
    view.send.Right:Set(form.Right)
    view.send.Bottom:Set(form.Bottom)
    view.cancel = Theme.Button(form, 'Cancel', function() view:Close() end, 'secondary', { width = 120 })
    view.cancel.Right:Set(function() return view.send.Left() - Scale(10) end)
    view.cancel.Bottom:Set(form.Bottom)
    -- Placed by their tops: a text field keeps its own height (Theme.TextField).
    view.game.Top:Set(function() return view.send.Top() - Scale(22 + 34) end)
    gameCaption.Bottom:Set(function() return view.game.Top() - Scale(8) end)
    if subject.game then
        view.game.edit:SetText(tostring(subject.game))
    end

    -- Earlier reports.
    local history = Group(panel)
    history.Left:Set(form.Left)
    history.Right:Set(form.Right)
    history.Top:Set(form.Top)
    history.Bottom:Set(form.Bottom)
    Theme.SizeFromEdges(history)
    history:DisableHitTest()
    view.historyArea = history
    view.historyNote = Theme.Text(history, '', 13, C.muted)
    view.historyNote.Left:Set(history.Left)
    view.historyNote.Top:Set(history.Top)
    view.document = Widgets.TextView(history)
    view.document.Left:Set(history.Left)
    view.document.Right:Set(history.Right)
    view.document.Top:Set(function() return view.historyNote.Bottom() + Scale(12) end)
    view.document.Bottom:Set(history.Bottom)
    view.document.Width:Set(function() return view.document.Right() - view.document.Left() end)
    view.document.Height:Set(function() return view.document.Bottom() - view.document.Top() end)

    ----------------------------------------------------------------------------------------------------------------

    function view:Values()
        return self.text.edit:GetText() or '', Trim(self.game.edit:GetText()), Trim(self.time.edit:GetText())
    end

    function view:Send()
        local text, game, time = self:Values()
        local me = MyId(launcher)
        local why = Check(text, game, time)
        if not me then
            why = 'Connect to FAF to send a report.'
        elseif tostring(me) == tostring(subject.id) then
            why = 'You can\'t report yourself.'
        elseif not rawget(_G, 'FafLibrary_Report') then
            why = 'This build can\'t send reports.'
        end
        if why then
            self.statusText, self.statusBad = why, true
            self:Paint()
            return
        end
        local id, refused = FafLibrary_Report({ reporter = tostring(me), player = tostring(subject.id),
            text = Trim(text), game = game, time = time })
        if not id then
            self.statusText, self.statusBad = 'Not sent: ' .. tostring(refused), true
        else
            LOG('LAUNCHER: report: sending a report on ' .. tostring(subject.login or subject.id))
            self.statusText, self.statusBad = 'Sending your report...', false
            self.jobs.send = { id = id, done = function()
                view.sent = true
                view.statusText, view.statusBad = 'Report sent. The moderators will look at it; you needn\'t report ' ..
                    'this incident again.', false
                view.history = nil
                LOG('LAUNCHER: report: sent')
            end }
        end
        self:Paint()
    end

    function view:LoadHistory()
        local me = MyId(launcher)
        if not me or not rawget(_G, 'FafLibrary_Api') then
            self.historyFailure = 'Connect to FAF to see your reports.'
            return
        end
        local id, why = FafLibrary_Api('/data/moderationReport', { filter = 'reporter.id==' .. me, sort = '-createTime',
            ['page[size]'] = '100', include = 'reportedUsers,lastModerator,game' })
        if not id then
            self.historyFailure = tostring(why)
            return
        end
        self.historyFailure = nil
        self.jobs.history = { id = id, done = function(doc)
            local store = Store(doc)
            local list = {}
            for _, report in (doc.data or {}) do
                local names = {}
                for _, player in (Rel(store, report, 'reportedUsers') or {}) do
                    table.insert(names, Attr(player, 'login') or ('#' .. tostring(player.id)))
                end
                local moderator = Rel(store, report, 'lastModerator')
                local game = Rel(store, report, 'game')
                table.insert(list, { id = report.id, who = table.concat(names, ', '),
                    status = Attr(report, 'reportStatus') or '', text = Attr(report, 'reportDescription') or '',
                    when = Attr(report, 'createTime') or '', notice = Attr(report, 'moderatorNotice') or '',
                    moderator = moderator and Attr(moderator, 'login') or '', game = game and game.id or nil,
                    time = Attr(report, 'gameIncidentTimecode') or '' })
            end
            view.history = list
            view:ShowHistory()
        end }
    end

    function view:ShowHistory()
        local blocks = {}
        for _, report in (self.history or {}) do
            local status = kStatus[report.status] or { report.status ~= '' and report.status or 'Sent', C.muted }
            local when = rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(report.when) or report.when
            table.insert(blocks, { style = 'h3', text = report.who .. '   -   ' .. status[1] .. '   -   ' ..
                string.sub(tostring(when), 1, 16) })
            if report.game then
                table.insert(blocks, { style = 'text', text = 'Replay ' .. report.game ..
                    (report.time ~= '' and (' at ' .. report.time) or '') })
            end
            if report.text ~= '' then
                table.insert(blocks, { style = 'text', text = report.text })
            end
            if report.notice ~= '' then
                table.insert(blocks, { style = 'text', text = 'Moderator' .. (report.moderator ~= '' and
                    (' ' .. report.moderator) or '') .. ': ' .. report.notice })
            end
            table.insert(blocks, { style = 'gap', text = '' })
        end
        self.document:SetBlocks(blocks)
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
                        WARN('LAUNCHER: report: ' .. tostring(err))
                    end
                else
                    local message = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                    if key == 'me' then
                        -- Who is signed in stays unknown: Send says so.
                    elseif key == 'history' then
                        self.historyFailure = message
                    else
                        self.statusText, self.statusBad = 'Not sent: ' .. message, true
                        LOG('LAUNCHER: report: not sent: ' .. message)
                    end
                end
                self:Paint()
                break
            end
        end
    end

    function view:Paint()
        self.tabs:Set(self.tab, {})
        Theme.SetVisible(self.form, self.tab == 'new')
        Theme.SetVisible(self.historyArea, self.tab == 'history')
        local text, game, time = self:Values()
        local length = string.len(Trim(text))
        -- The wrapped copy only when the field can't show it all.
        local long = self.text.edit:GetStringAdvance(text) > self.text.edit.Width() - Scale(8)
        if self.shownText ~= text or self.shownLong ~= long then
            self.shownText = text
            self.shownLong = long
            self.preview:SetText(long and text or '', C.text)
        end
        Theme.SetText(self.count, length .. ' / ' .. kMaxText)
        Theme.SetColor(self.count, (length > 0 and length < 10 or length > kMaxText) and C.bad or C.subtle)
        -- A report goes to FAF's API: signed in to FAF is what counts, not the lobby.
        local signedIn = (launcher.lastStatus or {}).signIn == 'signedin'
        local busy = self.jobs.send ~= nil
        self.send:SetEnabled(signedIn and not busy and not self.sent and Check(text, game, time) == nil)
        self.cancel:SetLabel(self.sent and 'Close' or 'Cancel')
        local status = self.statusText
        if not status then
            status = not signedIn and 'Connect to FAF to send a report.' or (length > 0 and Check(text, game, time)) or ''
        end
        Theme.SetText(self.status, status)
        Theme.SetColor(self.status, (self.statusBad or (not self.statusText and length > 0)) and C.bad or
            (self.sent and C.good or C.subtle))
        local count = self.history and table.getn(self.history) or 0
        Theme.SetText(self.historyNote, self.historyFailure and ('Your reports didn\'t load: ' .. self.historyFailure) or
            (not self.history and 'Asking FAF for your reports...') or
            (count == 0 and 'You haven\'t sent any reports.') or
            (count .. ' report' .. (count == 1 and '' or 's') .. ', newest first.'))
        Theme.SetColor(self.historyNote, self.historyFailure and C.bad or C.muted)
    end

    function view:Close()
        if current == view then
            current = false
        end
        cover:Destroy()
    end

    cover:SetNeedsFrameUpdate(true)
    cover.OnFrame = function(self, delta)
        view:Poll()
    end
    for _, field in { view.text, view.game, view.time } do
        field:OnChange(function()
            view.statusText = nil
            view.statusBad = false
            view:Paint()
        end)
    end
    AskMe(view)
    view:Paint()
    return view
end

--- The report on screen (tests), or false.
function Current()
    return current
end
