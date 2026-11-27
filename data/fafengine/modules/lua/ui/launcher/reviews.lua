-- Reviews of a map or a mod from FAF's vault, over the launcher: every version's reviews (FAF's API,
-- /data/<map|mod>/<id>/versions with the reviews and their players), newest first, with the average; and the signed-in
-- player's own review (a score of 1 to 5 and a text) written, changed or taken off (FafLibrary_SaveReview and
-- FafLibrary_DeleteReview, on the latest version, as the FAF client writes them).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local current = false

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

local function MyId(launcher)
    local login = (launcher.lastStatus or {}).login
    local me = login and login ~= '' and rawget(_G, 'FafOnline_Player') and FafOnline_Player(login)
    return me and me.id or nil
end

--- Opens the reviews of `subject` = {kind = 'map' or 'mod', id = FAF's id, name}.
function Open(launcher, subject)
    if current then
        current.cover:Destroy()
        current = false
    end
    local width, height = Widgets.FrameUnits()
    local cover = Widgets.Modal(launcher.root, 900, math.min(680, height - 60))
    local panel = cover.panel
    local view = { launcher = launcher, subject = subject, cover = cover, jobs = {}, score = 0 }
    current = view

    local x = 26
    local title = Theme.Title(panel, 'Reviews: ' .. tostring(subject.name or subject.id), 18, C.text)
    LayoutHelpers.AtLeftTopIn(title, panel, x, 22)
    view.summary = Theme.Text(panel, '', 13, C.muted)
    view.summary.Left:Set(title.Left)
    view.summary.Top:Set(function() return title.Bottom() + Scale(8) end)
    local close = Theme.Button(panel, '', function() view:Close() end, 'ghost', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(close, panel, 16, 16)

    -- Your review along the bottom: the score, the text, Save and Delete.
    view.status = Theme.Cell(panel, 12, C.subtle)
    view.status.Left:Set(title.Left)
    view.status.Right:Set(function() return panel.Right() - Scale(x) end)
    view.status.Bottom:Set(function() return panel.Bottom() - Scale(16) end)
    view.text = Theme.TextField(panel, 560, 'What you think of it (optional)', 'edit', 2000)
    view.text.Left:Set(title.Left)
    -- Placed by its top: the field keeps its own height (Theme.TextField).
    view.text.Top:Set(function() return view.status.Top() - Scale(10 + 34) end)
    view.save = Theme.Button(panel, 'Save review', function() view:Save() end, 'primary', { icon = 'check', width = 150 })
    view.save.Left:Set(function() return view.text.Right() + Scale(10) end)
    view.save.Top:Set(view.text.Top)
    view.delete = Theme.Button(panel, 'Delete', function() view:Delete() end, 'secondary', { icon = 'trash', width = 120 })
    view.delete.Left:Set(function() return view.save.Right() + Scale(10) end)
    view.delete.Top:Set(view.text.Top)
    view.scores = {}
    local before = nil
    local yours = Theme.Text(panel, 'YOUR REVIEW', 10, C.accent, true)
    yours.Left:Set(title.Left)
    for score = 1, 5 do
        local value = score
        local choice = Theme.Choice(panel, value .. (value == 1 and ' star' or ' stars'), 96, function()
            view.score = value
            view:Paint()
        end)
        choice.score = value
        local after = before
        choice.Left:Set(function() return after and (after.Right() + Scale(6)) or (yours.Right() + Scale(16)) end)
        choice.Bottom:Set(function() return view.text.Top() - Scale(10) end)
        table.insert(view.scores, choice)
        before = choice
    end
    LayoutHelpers.AtVerticalCenterIn(yours, view.scores[1])
    local line = Theme.Rect(panel, C.line)
    line.Left:Set(function() return panel.Left() + Scale(x) end)
    line.Right:Set(function() return panel.Right() - Scale(x) end)
    line.Bottom:Set(function() return view.scores[1].Top() - Scale(14) end)
    line.Height:Set(1)
    line.Width:Set(function() return line.Right() - line.Left() end)

    view.document = Widgets.TextView(panel)
    view.document.Left:Set(title.Left)
    view.document.Right:Set(function() return panel.Right() - Scale(16) end)
    view.document.Top:Set(function() return view.summary.Bottom() + Scale(16) end)
    view.document.Bottom:Set(function() return line.Top() - Scale(10) end)
    view.document.Width:Set(function() return view.document.Right() - view.document.Left() end)
    view.document.Height:Set(function() return view.document.Bottom() - view.document.Top() end)

    ----------------------------------------------------------------------------------------------------------------

    function view:Load()
        if not rawget(_G, 'FafLibrary_Api') then
            self.failure = 'This build has no FAF API access.'
            return
        end
        local id, why = FafLibrary_Api('/data/' .. subject.kind .. '/' .. subject.id .. '/versions', {
            include = 'reviews,reviews.player', ['page[size]'] = '100' })
        if not id then
            self.failure = tostring(why)
            return
        end
        self.reviews = nil
        self.jobs.load = { id = id, done = function(doc)
            local store = Store(doc)
            local reviews = {}
            local latest, latestNumber = nil, -1
            for _, version in (doc.data or {}) do
                local number = tonumber(Attr(version, 'version')) or 0
                if number > latestNumber then
                    latest, latestNumber = version.id, number
                end
                for _, review in (Rel(store, version, 'reviews') or {}) do
                    if review.attributes then
                        local player = Rel(store, review, 'player')
                        table.insert(reviews, { id = review.id, score = tonumber(Attr(review, 'score')) or 0,
                            text = Attr(review, 'text') or '', player = player and player.id,
                            login = player and Attr(player, 'login') or '?', version = number,
                            time = Attr(review, 'updateTime') or Attr(review, 'createTime') or '' })
                    end
                end
            end
            table.sort(reviews, function(a, b) return tostring(a.time) > tostring(b.time) end)
            view.reviews = reviews
            view.latest = latest
            view.latestNumber = latestNumber
            -- The player's own review fills the editor once.
            local me = MyId(launcher)
            view.mine = nil
            for _, review in reviews do
                if me and review.player == me then
                    view.mine = review
                end
            end
            if view.mine and not view.edited then
                view.score = view.mine.score
                view.text.edit:SetText(view.mine.text)
            end
            view:Show()
        end }
    end

    function view:Show()
        local blocks = {}
        for _, review in (self.reviews or {}) do
            local when = rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(review.time) or review.time
            table.insert(blocks, { style = 'h3', text = review.login .. '   ' .. review.score .. ' / 5   -   version ' ..
                review.version .. '   -   ' .. string.sub(tostring(when), 1, 16) })
            if review.text ~= '' then
                table.insert(blocks, { style = 'text', text = review.text })
            end
            table.insert(blocks, { style = 'gap', text = '' })
        end
        if self.reviews and table.getn(self.reviews) == 0 then
            blocks = { { style = 'text', text = 'No reviews yet: yours can be the first.' } }
        end
        self.document:SetBlocks(blocks)
        self:Paint()
    end

    function view:Save()
        local me = MyId(launcher)
        if self.score < 1 then
            self.statusText = 'Choose a score of 1 to 5 stars first.'
        elseif not rawget(_G, 'FafLibrary_SaveReview') then
            self.statusText = 'This build can\'t write reviews.'
        else
            local id, why = FafLibrary_SaveReview({ kind = subject.kind, subject = self.mine and '' or self.latest,
                review = self.mine and self.mine.id or '', player = me or '', score = self.score,
                text = self.text.edit:GetText() or '' })
            if id then
                self.statusText = 'Saving your review...'
                self.jobs.save = { id = id, done = function()
                    view.statusText = 'Your review is saved.'
                    view.edited = false
                    view:Load()
                end }
            else
                self.statusText = 'Not saved: ' .. tostring(why)
            end
        end
        self:Paint()
    end

    function view:Delete()
        if not self.mine or not rawget(_G, 'FafLibrary_DeleteReview') then
            return
        end
        local id, why = FafLibrary_DeleteReview({ kind = subject.kind, review = self.mine.id })
        if id then
            self.statusText = 'Taking your review off...'
            self.jobs.delete = { id = id, done = function()
                view.statusText = 'Your review is taken off.'
                view.score = 0
                view.text.edit:SetText('')
                view.edited = false
                view:Load()
            end }
        else
            self.statusText = 'Not deleted: ' .. tostring(why)
        end
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
                        WARN('LAUNCHER: reviews: ' .. tostring(err))
                    end
                elseif key == 'load' then
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                else
                    self.statusText = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                end
                self:Paint()
                break
            end
        end
    end

    function view:Paint()
        local reviews = self.reviews
        local count = reviews and table.getn(reviews) or 0
        local sum = 0
        for _, review in (reviews or {}) do
            sum = sum + review.score
        end
        Theme.SetText(self.summary, self.failure and ('The reviews didn\'t load: ' .. self.failure) or
            (not reviews and 'Asking FAF for the reviews...') or
            (count == 0 and 'No reviews yet.') or
            string.format('%.1f of 5 from %d review%s%s', sum / count, count, count == 1 and '' or 's',
                self.latestNumber and self.latestNumber >= 0 and ('   -   latest version ' .. self.latestNumber) or ''))
        Theme.SetColor(self.summary, self.failure and C.bad or C.muted)
        for _, choice in self.scores do
            choice.selected = choice.score == self.score
            choice:Paint(false)
        end
        local signedIn = (launcher.lastStatus or {}).lobby == 'signedin' and MyId(launcher) ~= nil
        local busy = self.jobs.save ~= nil or self.jobs.delete ~= nil
        self.save:SetLabel(self.mine and 'Update review' or 'Save review')
        self.save:SetEnabled(signedIn and not busy and reviews ~= nil and (self.mine ~= nil or self.latest ~= nil))
        self.delete:SetEnabled(signedIn and not busy and self.mine ~= nil)
        Theme.SetVisible(self.delete, self.mine ~= nil)
        Theme.SetText(self.status, self.statusText or (signedIn and (self.mine and 'You reviewed it: change it here.' or
            '') or 'Connect to FAF to write a review.'))
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
    view.text:OnChange(function() view.edited = true end)
    view:Load()
    view:Paint()
    return view
end

--- The reviews on screen (tests), or false.
function Current()
    return current
end
