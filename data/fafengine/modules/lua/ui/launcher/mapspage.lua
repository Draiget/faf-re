-- The launcher's Maps page: the maps on this computer and FAF's map vault, as cards with their pictures; the chosen
-- map's details (picture, story, size, players, author, version, rating, games played), Download (into the vault's
-- maps folder, usable at once: FafLibrary_InstallMap), Remove for a downloaded one, and Host a game on it.
-- The vault is searched through FAF's API (FafLibrary_Api: /data/map with its latest version, author and reviews).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kCardWidth = 200
local kCardHeight = 250
local kPageSize = 40
local kSorts = {
    { 'played', 'Most played', '-gamesPlayed' },
    { 'rated', 'Best rated', '-reviewsSummary.lowerBound' },
    { 'new', 'Newest', '-latestVersion.createTime' },
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
    if type(data) ~= 'table' or not data.type then
        return nil
    end
    return store[data.type .. ':' .. data.id]
end

local function Attr(resource, name)
    return resource and resource.attributes and resource.attributes[name]
end

local function Plain(text)
    text = string.gsub(tostring(text or ''), '<br%s*/?>', ' ')
    text = string.gsub(text, '<[^>]->', '')
    return (string.gsub(text, '%s+', ' '))
end

--- "10 km" from a map's size in game units (256 to the 5 km step).
local function Km(units)
    units = tonumber(units) or 0
    if units <= 0 then
        return ''
    end
    return math.floor(units / 51.2 + 0.5) .. ' km'
end

--- The maps on this computer, from FAF's own scenario list.
local function LocalMaps()
    local maps = {}
    local ok, scenarios = pcall(function() return import('/lua/ui/maputil.lua').EnumerateSkirmishScenarios() end)
    for _, scenario in (ok and scenarios or {}) do
        local _, _, folder = string.find(string.lower(scenario.file or ''), '^/maps/([^/]+)/')
        local players = 0
        if scenario.Configurations and scenario.Configurations.standard and scenario.Configurations.standard.teams then
            players = table.getsize(scenario.Configurations.standard.teams[1].armies or {})
        end
        if folder then
            table.insert(maps, { key = 'local:' .. folder, folder = folder, name = LOC(scenario.name or folder),
                size = scenario.size and Km(scenario.size[1]) or '', players = players,
                story = Plain(LOC(scenario.description or '')), version = scenario.map_version, isLocal = true })
        end
    end
    table.sort(maps, function(a, b) return string.lower(a.name) < string.lower(b.name) end)
    return maps
end

function Build(launcher, page)
    local view = { tab = 'local', sort = 'played', vault = {}, vaultPage = 1, vaultPages = 0, jobs = {}, thumbJobs = {},
        cards = {}, top = 0 }
    launcher.mapsView = view

    local title = Theme.Title(page, 'Maps', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, { { 'local', 'On this computer' }, { 'vault', 'FAF vault' } }, function(key)
        view.tab = key
        view.top = 0
        view.chosen = nil
        if key == 'vault' and not view.searched then
            view:Search()
        end
        view:Refresh()
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

    view.search = Theme.TextField(page, 340, 'Search maps by name', 'search', 60)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search:OnChange(function()
        view.top = 0
        if view.tab == 'local' then
            view:Refresh()
        end
    end)
    view.search.edit.OnEnterPressed = function()
        if view.tab == 'vault' then
            view.vaultPage = 1
            view:Search()
        end
        return true
    end
    view.sortChoices = {}
    local before = view.search
    for _, sort in kSorts do
        local key = sort[1]
        local choice = Theme.Choice(page, sort[2], 140, function()
            view.sort = key
            view.vaultPage = 1
            view:Search()
        end)
        choice.key = key
        local after = before
        choice.Left:Set(function() return after.Right() + Scale(after == view.search and 20 or 8) end)
        LayoutHelpers.AtVerticalCenterIn(choice, view.search)
        table.insert(view.sortChoices, choice)
        before = choice
    end
    view.pageText = Theme.Text(page, '', 12, C.subtle)
    view.prev = Theme.Button(page, '', function() view:Turn(-1) end, 'ghost', { icon = 'arrowLeft', width = 36 })
    view.next = Theme.Button(page, '', function() view:Turn(1) end, 'ghost', { icon = 'arrowRight', width = 36 })
    view.next.Right:Set(page.Right)
    view.next.Top:Set(view.search.Top)
    view.prev.Right:Set(function() return view.next.Left() - Scale(4) end)
    view.prev.Top:Set(view.search.Top)
    view.pageText.Right:Set(function() return view.prev.Left() - Scale(10) end)
    LayoutHelpers.AtVerticalCenterIn(view.pageText, view.search)

    -- The cards on the left, the chosen map on the right.
    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Right:Set(page.Right)
    detail.Top:Set(function() return view.search.Bottom() + Scale(18) end)
    detail.Bottom:Set(page.Bottom)
    LayoutHelpers.SetWidth(detail, 430)
    detail.Left:Set(function() return detail.Right() - detail.Width() end)
    detail.Height:Set(function() return detail.Bottom() - detail.Top() end)
    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(function() return detail.Left() - Scale(20) end)
    area.Top:Set(detail.Top)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    view.area = area
    view.note = Theme.Paragraph(area, 14, C.subtle)
    view.note.Left:Set(area.Left)
    view.note.Right:Set(function() return area.Left() + math.min(area.Width(), Scale(600)) end)
    view.note.Top:Set(function() return area.Top() + Scale(8) end)
    view.loader = Theme.Loader(area)
    LayoutHelpers.AtCenterIn(view.loader, area)
    Theme.HitArea(area, function(self, event)
        if event.Type == 'WheelRotation' then
            view.top = math.max(0, view.top + (event.WheelRotation > 0 and -1 or 1))
            view:Paint()
            return true
        end
        return false
    end).Depth:Set(function() return area.Depth() - 1 end)

    -- Details.
    view.bigFrame = Theme.Panel(detail, 'ff08121a', C.line)
    -- A square as wide as the panel, smaller when the panel is short, so the name, facts, story and buttons under it
    -- keep their room (about 270 px at scale 1).
    local function PictureSide()
        return math.max(Scale(120), math.min(detail.Width() - Scale(48), detail.Height() - Scale(24) - Scale(290)))
    end
    view.bigFrame.Top:Set(function() return detail.Top() + Scale(24) end)
    view.bigFrame.Height:Set(PictureSide)
    view.bigFrame.Width:Set(PictureSide)
    view.bigFrame.Left:Set(function() return detail.Left() + math.floor((detail.Width() - view.bigFrame.Width()) / 2) end)
    view.text = Group(detail) -- the text column: the panel's width, whatever the picture's
    view.text.Left:Set(function() return detail.Left() + Scale(24) end)
    view.text.Right:Set(function() return detail.Right() - Scale(24) end)
    view.text.Top:Set(view.bigFrame.Bottom)
    view.text.Height:Set(1)
    view.text.Width:Set(function() return view.text.Right() - view.text.Left() end)
    view.text:DisableHitTest()
    Widgets.MapPicture(view.bigFrame)
    view.bigThumb = Bitmap(view.bigFrame)
    view.bigThumb:DisableHitTest()
    LayoutHelpers.FillParentFixedBorder(view.bigThumb, view.bigFrame, 1)
    view.bigThumb.Depth:Set(function() return view.bigFrame.Depth() + 3 end)
    view.name = Theme.Text(detail, '', 18, C.text, true)
    view.name.Left:Set(view.text.Left)
    view.name.Top:Set(function() return view.bigFrame.Bottom() + Scale(14) end)
    view.facts = Theme.Cell(detail, 13, C.muted)
    view.facts.Left:Set(view.text.Left)
    view.facts.Right:Set(view.text.Right)
    view.facts.Top:Set(function() return view.name.Bottom() + Scale(6) end)
    view.facts2 = Theme.Cell(detail, 13, C.subtle)
    view.facts2.Left:Set(view.text.Left)
    view.facts2.Right:Set(view.text.Right)
    view.facts2.Top:Set(function() return view.facts.Bottom() + Scale(4) end)
    view.story = Theme.Paragraph(detail, 12, C.muted)
    view.story.Left:Set(view.text.Left)
    view.story.Right:Set(view.text.Right)
    view.story.Top:Set(function() return view.facts2.Bottom() + Scale(10) end)
    view.action = Theme.Button(detail, 'Download', function() view:Act() end, 'primary', { width = 180, icon = 'download' })
    view.action.Right:Set(view.text.Right)
    LayoutHelpers.AtBottomIn(view.action, detail, 20)
    view.host = Theme.Button(detail, 'Host a game', function() view:Host() end, 'secondary', { width = 160, icon = 'play' })
    view.host.Left:Set(view.text.Left)
    LayoutHelpers.AtBottomIn(view.host, detail, 20)
    -- FAF's reviews of a vault map, and the player's own (reviews.lua).
    view.reviewsButton = Theme.Button(detail, 'Reviews', function()
        if view.chosen and view.chosen.id then
            import('/fafengine/modules/lua/ui/launcher/reviews.lua').Open(launcher, { kind = 'map', id = view.chosen.id,
                name = view.chosen.name })
        end
    end, 'ghost', { icon = 'star', width = 150, height = 30 })
    view.reviewsButton.Right:Set(view.text.Right)
    view.reviewsButton.Bottom:Set(function() return view.action.Top() - Scale(44) end)
    -- A map of the vault's own folder up to FAF's vault (upload.lua), where Reviews is for FAF's maps.
    view.uploadButton = Theme.Button(detail, 'Upload to FAF', function()
        if view.chosen then
            import('/fafengine/modules/lua/ui/launcher/upload.lua').Open(launcher, { kind = 'map',
                folder = view.chosen.folder, name = view.chosen.name })
        end
    end, 'ghost', { icon = 'upload', width = 190, height = 30 })
    view.uploadButton.Right:Set(view.text.Right)
    view.uploadButton.Bottom:Set(view.reviewsButton.Bottom)
    view.status = Theme.Cell(detail, 12, C.muted)
    view.status.Left:Set(view.text.Left)
    view.status.Right:Set(view.text.Right)
    view.status.Bottom:Set(function() return view.action.Top() - Scale(10) end)

    local function Card(index)
        local card = view.cards[index]
        if card then
            return card
        end
        card = Theme.Panel(area, 'ff0d1c27', C.line)
        LayoutHelpers.SetDimensions(card, kCardWidth, kCardHeight)
        card.frame = Theme.Panel(card, 'ff08121a', C.line)
        card.frame.Left:Set(function() return card.Left() + Scale(10) end)
        card.frame.Right:Set(function() return card.Right() - Scale(10) end)
        card.frame.Top:Set(function() return card.Top() + Scale(10) end)
        card.frame.Height:Set(function() return card.frame.Right() - card.frame.Left() end)
        card.frame.Width:Set(function() return card.frame.Right() - card.frame.Left() end)
        Widgets.MapPicture(card.frame)
        card.thumb = Bitmap(card.frame)
        card.thumb:DisableHitTest()
        LayoutHelpers.FillParentFixedBorder(card.thumb, card.frame, 1)
        card.thumb.Depth:Set(function() return card.frame.Depth() + 3 end)
        card.name = Theme.Cell(card, 14, C.text, true)
        card.name.Left:Set(function() return card.Left() + Scale(12) end)
        card.name.Right:Set(function() return card.Right() - Scale(12) end)
        card.name.Top:Set(function() return card.frame.Bottom() + Scale(10) end)
        card.facts = Theme.Cell(card, 12, C.muted)
        card.facts.Left:Set(card.name.Left)
        card.facts.Right:Set(card.name.Right)
        card.facts.Top:Set(function() return card.name.Bottom() + Scale(4) end)
        card.badge = Theme.Tag(card, 'Installed', C.good)
        card.badge.Right:Set(function() return card.frame.Right() - Scale(6) end)
        card.badge.Top:Set(function() return card.frame.Top() + Scale(6) end)
        card.badge.Depth:Set(function() return card.thumb.Depth() + 2 end)
        Theme.HitArea(card, function(self, event)
            if event.Type == 'ButtonPress' and event.Modifiers.Left and card.map then
                Theme.ClickSound()
                view.chosen = card.map
                view:Paint()
                return true
            elseif event.Type == 'WheelRotation' then
                view.top = math.max(0, view.top + (event.WheelRotation > 0 and -1 or 1))
                view:Paint()
                return true
            end
            return false
        end)
        view.cards[index] = card
        return card
    end

    ----------------------------------------------------------------------------------------------------------------

    function view:Search()
        if not rawget(_G, 'FafLibrary_Api') then
            self.failure = 'This build has no FAF API access.'
            return
        end
        local text = self.search.edit:GetText()
        local filter = 'latestVersion.hidden==false'
        if text ~= '' then
            filter = filter .. ';displayName=="*' .. string.gsub(text, '"', '') .. '*"'
        end
        local sort = kSorts[1][3]
        for _, entry in kSorts do
            if entry[1] == self.sort then
                sort = entry[3]
            end
        end
        local id, why = FafLibrary_Api('/data/map', { filter = filter, sort = sort, include = 'latestVersion,author,reviewsSummary',
            ['page[size]'] = tostring(kPageSize), ['page[number]'] = tostring(self.vaultPage), ['page[totals]'] = '' })
        self.searched = true
        self.failure = nil
        if not id then
            self.failure = tostring(why)
            return
        end
        self.jobs.search = { id = id, done = function(doc)
            local store = Store(doc)
            local maps = {}
            for _, map in (doc.data or {}) do
                local version = Rel(store, map, 'latestVersion')
                local author = Rel(store, map, 'author')
                local reviews = Rel(store, map, 'reviewsSummary')
                local folder = Attr(version, 'folderName') or ''
                table.insert(maps, {
                    key = 'vault:' .. map.id, id = map.id, folder = folder, name = Attr(map, 'displayName') or folder,
                    size = Km(Attr(version, 'width')), players = Attr(version, 'maxPlayers') or 0,
                    story = Plain(Attr(version, 'description')), version = Attr(version, 'version'),
                    author = Attr(author, 'login') or '', played = Attr(map, 'gamesPlayed') or 0,
                    score = Attr(reviews, 'averageScore'), reviews = Attr(reviews, 'reviews') or 0,
                    url = Attr(version, 'downloadUrl'), thumbnail = Attr(version, 'thumbnailUrlLarge') or
                        Attr(version, 'thumbnailUrlSmall'), ranked = Attr(version, 'ranked'),
                })
            end
            view.vault = maps
            local meta = doc.meta and doc.meta.page or {}
            view.vaultPages = meta.totalPages or 1
            view.vaultTotal = meta.totalRecords or table.getn(maps)
            view.top = 0
        end }
    end

    function view:Turn(by)
        if self.tab ~= 'vault' then
            return
        end
        local wanted = math.max(1, math.min(self.vaultPages or 1, self.vaultPage + by))
        if wanted ~= self.vaultPage then
            self.vaultPage = wanted
            self:Search()
            self:Paint()
        end
    end

    --- A map is on this computer when FAF's game files or the vault have its folder.
    function view:Installed(map)
        return map.folder ~= '' and Widgets.LocalScenario(map.folder) and true or false
    end

    function view:Act()
        local map = self.chosen
        if not map then
            return
        end
        if map.isLocal or self:Installed(map) then
            if not rawget(_G, 'FafLibrary_RemoveMap') then
                return
            end
            local ok, why = FafLibrary_RemoveMap(map.folder)
            self.statusText = ok and (map.name .. ' is removed.') or ('Not removed: ' .. tostring(why))
            Widgets.ForgetScenario(map.folder)
            if ok then
                self.localMaps = nil
            end
        elseif map.url then
            local id, why = FafLibrary_InstallMap({ url = map.url })
            if id then
                self.jobs.install = { id = id, map = map, done = function()
                    Widgets.ForgetScenario(map.folder)
                    view.localMaps = nil
                    view.statusText = map.name .. ' is downloaded and ready to play.'
                end }
                self.statusText = 'Downloading ' .. map.name .. '...'
            else
                self.statusText = 'Not downloaded: ' .. tostring(why)
            end
        end
        self:Paint()
    end

    function view:Host()
        local map = self.chosen
        if not map then
            return
        end
        local status = launcher.lastStatus or {}
        local ok, why = launcher:HostRequest({ title = (status.login ~= '' and status.login or 'My') .. '\'s game on ' ..
            map.name, map = map.folder, visibility = 'public' })
        self.statusText = ok and ('Hosting a game on ' .. map.name .. '...') or tostring(why)
        self:Paint()
    end

    function view:Poll()
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if state and state.state == 'working' then
                if key == 'install' and state.total and state.total > 0 then
                    self.statusText = string.format('Downloading %s... %d%%', job.map.name,
                        math.floor(state.received * 100 / state.total))
                end
            else
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: maps: ' .. key .. ': ' .. tostring(err))
                    end
                elseif key == 'install' then
                    self.statusText = 'Not downloaded: ' .. tostring(state and state.message)
                else
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                end
                break
            end
        end
    end

    --- A picture from FAF's content server, downloaded once and mounted with the next batch; nil until then.
    function view:Thumbnail(url)
        if not url or not rawget(_G, 'FafLibrary_Thumbnail') then
            return nil
        end
        local path, job = FafLibrary_Thumbnail(url)
        if not path and job and job > 0 then
            self.thumbJobs[job] = true
        elseif not path and job == 0 then
            self.mountWanted = true
        end
        return path
    end

    function view:Items()
        if self.tab == 'local' then
            self.localMaps = self.localMaps or LocalMaps()
            local filter = string.lower(self.search.edit:GetText())
            if filter == '' then
                return self.localMaps
            end
            local shown = {}
            for _, map in self.localMaps do
                if string.find(string.lower(map.name), filter, 1, true) then
                    table.insert(shown, map)
                end
            end
            return shown
        end
        return self.vault
    end

    function view:Paint()
        local items = self:Items()
        local perRow = math.max(1, math.floor((self.area.Width() + Scale(16)) / Scale(kCardWidth + 16)))
        local rows = math.max(1, math.floor((self.area.Height() + Scale(16)) / Scale(kCardHeight + 16)))
        local maxTop = math.max(0, math.ceil(table.getn(items) / perRow) - rows)
        self.top = math.min(self.top, maxTop)
        local first = self.top * perRow
        for i = 1, perRow * rows do
            local card = Card(i)
            local map = items[first + i]
            card.map = map
            Theme.SetVisible(card, map ~= nil)
            if map then
                local slot = i - 1
                card.Left:Set(function() return self.area.Left() + math.mod(slot, perRow) * Scale(kCardWidth + 16) end)
                card.Top:Set(function() return self.area.Top() + math.floor(slot / perRow) * Scale(kCardHeight + 16) end)
                local installed = map.isLocal or self:Installed(map)
                card.frame:SetMap(installed and map.folder or nil)
                local thumb = not installed and self:Thumbnail(map.thumbnail) or nil
                if thumb and card.shownThumb ~= thumb then
                    card.shownThumb = thumb
                    card.thumb:SetTexture(thumb)
                end
                Theme.SetVisible(card.thumb, thumb ~= nil)
                Theme.SetText(card.name, map.name)
                Theme.SetText(card.facts, (map.size ~= '' and (map.size .. '  -  ') or '') .. map.players .. ' players')
                Theme.SetVisible(card.badge, (not map.isLocal) and installed)
                local chosen = self.chosen and self.chosen.key == map.key
                card:SetColors(chosen and 'ff123145' or 'ff0d1c27', chosen and C.accent or C.line)
            end
        end
        for i = perRow * rows + 1, table.getn(self.cards) do
            Theme.SetVisible(self.cards[i], false)
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
        -- The tabs, the sort and the pages.
        -- A download or removal drops the local list; it is read again here so its count stays right on the vault tab.
        self.localMaps = self.localMaps or LocalMaps()
        self.tabs:Set(self.tab, { ['local'] = table.getn(self.localMaps), vault = self.vaultTotal })
        for _, choice in self.sortChoices do
            choice.selected = choice.key == self.sort
            choice:Paint(false)
            Theme.SetVisible(choice, self.tab == 'vault')
        end
        local vault = self.tab == 'vault'
        Theme.SetVisible(self.prev, vault)
        Theme.SetVisible(self.next, vault)
        Theme.SetText(self.pageText, vault and self.vaultPages > 0 and ('Page ' .. self.vaultPage .. ' of ' ..
            self.vaultPages) or (table.getn(items) .. ' maps'))
        Theme.SetVisible(self.loader, vault and self.jobs.search ~= nil)
        local note = ''
        if self.failure and vault then
            note = 'The vault didn\'t answer: ' .. self.failure
        elseif table.getn(items) == 0 and not self.jobs.search then
            note = vault and 'No maps found.' or 'No maps on this computer match.'
        end
        self.note:SetText(note, self.failure and C.bad or C.subtle)
        -- The chosen map.
        local map = self.chosen
        Theme.SetText(self.name, map and map.name or 'Pick a map')
        Theme.SetText(self.facts, map and ((map.size ~= '' and (map.size .. '  -  ') or '') .. map.players ..
            ' players' .. (map.version and ('  -  version ' .. map.version) or '')) or '')
        Theme.SetText(self.facts2, map and not map.isLocal and ((map.author ~= '' and ('by ' .. map.author .. '  -  ') or '') ..
            (map.score and string.format('%.1f stars from %d reviews', map.score, map.reviews) or 'no reviews') ..
            '  -  ' .. map.played .. ' games') or '')
        if self.storyFor ~= map then
            self.storyFor = map
            self.story:SetText(map and map.story or '', C.muted)
        end
        local installed = map and (map.isLocal or self:Installed(map))
        self.bigFrame:SetMap(installed and map.folder or nil)
        local thumb = map and not installed and self:Thumbnail(map.thumbnail) or nil
        if thumb and self.shownBig ~= thumb then
            self.shownBig = thumb
            self.bigThumb:SetTexture(thumb)
        end
        Theme.SetVisible(self.bigThumb, thumb ~= nil)
        self.action:SetLabel(installed and 'Remove' or 'Download')
        self.action:SetEnabled(map ~= nil and (installed or map.url ~= nil) and not self.jobs.install)
        Theme.SetVisible(self.action, map ~= nil and not (map.isLocal and not self:FromVault(map)))
        Theme.SetVisible(self.reviewsButton, map ~= nil and not map.isLocal and map.id ~= nil)
        Theme.SetVisible(self.uploadButton, map ~= nil and map.isLocal and self:FromVault(map) and
            rawget(_G, 'FafLibrary_Upload') ~= nil)
        local status = launcher.lastStatus or {}
        self.host:SetEnabled(map ~= nil and installed and status.lobby == 'signedin')
        Theme.SetText(self.status, self.statusText or '')
    end

    --- A map that can be removed: not one of the game's own (their folders start scmp_ and x1mp_).
    function view:FromVault(map)
        local folder = string.lower(map.folder or '')
        return folder ~= '' and not string.find(folder, '^scmp_') and not string.find(folder, '^x1mp_')
    end

    function view:Refresh()
        self:Poll()
        self:Paint()
    end

    return view
end
