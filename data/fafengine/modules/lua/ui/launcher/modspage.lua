-- The launcher's Mods page: the mods on this computer and FAF's mod vault, in the launcher's look. A mod from the
-- vault downloads into the vault's mods folder and is usable at once (the engine mounts it: FafLibrary_InstallMod);
-- turning a mod on or off is FAF's own choice of mods (/lua/mods.lua SetSelectedMods, the active_mods preference),
-- which the next game uses. Removing takes it out of the game and off the disk.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kPageSize = 36

local function Mods()
    return import('/lua/mods.lua')
end

local function Available()
    return rawget(_G, 'FafLibrary_InstallMod') ~= nil
end

local function LocalTime(when)
    if not when or when == '' or not rawget(_G, 'FafLibrary_LocalTime') then
        return ''
    end
    return FafLibrary_LocalTime(when)
end

local function Contains(text, filter)
    return text and string.find(string.lower(text), filter, 1, true) ~= nil
end

--- The folder of an installed mod under /mods/, or nil.
local function FolderOf(mod)
    local _, _, folder = string.find(mod.location or '', '^/mods/([^/]+)/?$')
    return folder
end

--- The page. Returns its view; view:Refresh() runs while the page shows.
function Build(launcher, page)
    local view = { tab = 'local', vaultItems = {}, vaultPage = 1, vaultPages = 0, vaultTotal = 0, vaultType = '',
        status = '', statusColor = C.subtle }
    launcher.modsView = view

    local title = Theme.Title(page, 'Mods', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, { { 'local', 'Installed' }, { 'vault', 'FAF vault' } }, function(key)
        view:SetTab(key)
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

    -- The toolbar: the search, then (vault) UI / Sim / both, recommended only and Search.
    view.search = Theme.TextField(page, 300, 'Search mods by name', 'search', 60)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search:OnChange(function()
        if view.tab == 'local' then
            view.localList.top = 1
            view:Refresh()
        end
    end)
    view.search.edit.OnEnterPressed = function()
        if view.tab == 'vault' then
            view:SearchVault(1)
        end
        return true
    end
    view.types = {}
    local lastType = view.search
    for _, entry in { { '', 'All' }, { 'UI', 'UI' }, { 'SIM', 'Sim' } } do
        local value = entry[1]
        local choice = Theme.Choice(page, entry[2], 80, function()
            view.vaultType = value
            for _, other in view.types do
                other.selected = other.value == value
                other:Paint(false)
            end
        end)
        choice.value = value
        choice.selected = value == ''
        choice:Paint(false)
        local after = lastType
        choice.Left:Set(function() return after.Right() + Scale(after == view.search and 12 or 6) end)
        choice.Top:Set(function() return view.search.Top() + Scale(1) end)
        table.insert(view.types, choice)
        lastType = choice
    end
    view.recommended = Theme.Checkbox(page, 'Recommended', function() end)
    view.recommended.Left:Set(function() return lastType.Right() + Scale(18) end)
    view.recommended.Top:Set(view.search.Top)
    view.searchButton = Theme.Button(page, 'Search', function()
        view:SearchVault(1)
    end, 'secondary', { icon = 'search', width = 120 })
    view.searchButton.Left:Set(function() return view.recommended.Right() + Scale(18) end)
    view.searchButton.Top:Set(view.search.Top)

    -- The list on the left, the details on the right.
    local details = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(details, C.accent)
    details.Right:Set(page.Right)
    details.Top:Set(function() return view.search.Bottom() + Scale(16) end)
    details.Bottom:Set(page.Bottom)
    details.Width:Set(Scale(400))
    view.details = details
    local listArea = Group(page)
    listArea.Left:Set(page.Left)
    listArea.Right:Set(function() return details.Left() - Scale(20) end)
    listArea.Top:Set(details.Top)
    listArea.Bottom:Set(function() return page.Bottom() - Scale(34) end)
    listArea.Width:Set(function() return listArea.Right() - listArea.Left() end)
    listArea.Height:Set(function() return listArea.Bottom() - listArea.Top() end)

    local function Pick(item, double)
        view.selected = item
        view:ShowDetails()
        if double then
            view:Act()
        end
    end
    view.localList = Widgets.VirtualList(listArea, {
        { 'Name', 0.42, function(item) return item.name end },
        { 'Type', 0.10, function(item) return item.ui_only and 'UI' or 'Sim' end, C.muted },
        { 'Version', 0.12, function(item) return tostring(item.version or '') end, C.muted },
        { 'Author', 0.22, function(item) return item.author or '' end, C.subtle },
        { 'On', 0.14, function(item) return view:IsOn(item.uid) and 'On' or '' end, C.good },
    }, Pick)
    LayoutHelpers.FillParent(view.localList, listArea)
    view.vaultList = Widgets.VirtualList(listArea, {
        { 'Name', 0.38, function(item) return item.name end },
        { 'Type', 0.08, function(item) return item.type == 'UI' and 'UI' or 'Sim' end, C.muted },
        { 'Author', 0.20, function(item) return item.author ~= '' and item.author or item.uploader end, C.subtle },
        { 'Reviews', 0.14, function(item)
            return item.reviews > 0 and string.format('%.1f (%d)', item.reviewScore, item.reviews) or ''
        end, C.muted },
        { 'Status', 0.20, function(item) return view:VaultStatus(item) end, C.good },
    }, Pick)
    LayoutHelpers.FillParent(view.vaultList, listArea)
    view.empty = Theme.Text(listArea, '', 14, C.subtle)
    LayoutHelpers.AtCenterIn(view.empty, listArea)
    view.loader = Theme.Loader(listArea)
    LayoutHelpers.AtHorizontalCenterIn(view.loader, listArea)
    view.loader.Bottom:Set(function() return view.empty.Top() - Scale(14) end)

    view.footer = Theme.Cell(page, 12, C.subtle)
    view.footer.Left:Set(page.Left)
    view.footer.Right:Set(function() return listArea.Right() - Scale(240) end)
    view.footer.Bottom:Set(function() return page.Bottom() - Scale(6) end)
    view.next = Theme.Button(page, '', function()
        view:SearchVault(view.vaultPage + 1)
    end, 'ghost', { icon = 'chevronRight', width = 34, height = 26 })
    view.next.Right:Set(listArea.Right)
    view.next.Bottom:Set(page.Bottom)
    view.pageText = Theme.Text(page, '', 12, C.muted)
    view.pageText.Right:Set(function() return view.next.Left() - Scale(8) end)
    LayoutHelpers.AtVerticalCenterIn(view.pageText, view.next)
    view.previous = Theme.Button(page, '', function()
        view:SearchVault(view.vaultPage - 1)
    end, 'ghost', { icon = 'arrowLeft', width = 34, height = 26 })
    view.previous.Right:Set(function() return view.pageText.Left() - Scale(8) end)
    view.previous.Bottom:Set(page.Bottom)

    -- The details: name, who made it, kind, version, reviews, what it does; the next step for it.
    local textLeft = function() return details.Left() + Scale(18) end
    local textRight = function() return details.Right() - Scale(18) end
    view.detailTitle = Theme.Paragraph(details, 16, C.text)
    view.detailTitle.Left:Set(textLeft)
    view.detailTitle.Right:Set(textRight)
    view.detailTitle.Top:Set(function() return details.Top() + Scale(18) end)
    view.detailLines = Theme.Paragraph(details, 12, C.muted)
    view.detailLines.Left:Set(textLeft)
    view.detailLines.Right:Set(textRight)
    view.detailLines.Top:Set(function() return view.detailTitle.Bottom() + Scale(8) end)
    view.description = Theme.Paragraph(details, 13, C.text)
    view.description.Left:Set(textLeft)
    view.description.Right:Set(textRight)
    view.description.Top:Set(function() return view.detailLines.Bottom() + Scale(16) end)
    view.action = Theme.Button(details, 'Install', function()
        view:Act()
    end, 'primary', { icon = 'download', height = 38 })
    view.action.Left:Set(textLeft)
    view.action.Right:Set(textRight)
    view.action.Width:Set(function() return view.action.Right() - view.action.Left() end)
    view.action.Bottom:Set(function() return details.Bottom() - Scale(18) end)
    view.remove = Theme.Button(details, 'Remove', function()
        view:Remove()
    end, 'danger', { icon = 'trash', height = 32 })
    view.remove.Left:Set(textLeft)
    view.remove.Right:Set(textRight)
    view.remove.Width:Set(function() return view.remove.Right() - view.remove.Left() end)
    view.remove.Bottom:Set(function() return view.action.Top() - Scale(10) end)
    -- FAF's reviews of a vault mod, and the player's own (reviews.lua).
    view.reviewsButton = Theme.Button(details, 'Reviews', function()
        local item = view.selected
        if item and item.id and item.id ~= '' then
            import('/fafengine/modules/lua/ui/launcher/reviews.lua').Open(launcher, { kind = 'mod', id = item.id,
                name = item.name })
        end
    end, 'ghost', { icon = 'star', height = 30 })
    view.reviewsButton.Left:Set(textLeft)
    view.reviewsButton.Right:Set(textRight)
    view.reviewsButton.Width:Set(function() return view.reviewsButton.Right() - view.reviewsButton.Left() end)
    view.reviewsButton.Bottom:Set(function() return view.remove.Top() - Scale(10) end)
    view.detailNote = Theme.Paragraph(details, 12, C.muted)
    view.detailNote.Left:Set(textLeft)
    view.detailNote.Right:Set(textRight)
    view.detailNote.Top:Set(function() return view.reviewsButton.Top() - Scale(56) end)

    -- -------------------------------------------------------------------------------------------------------------

    function view:Selected()
        local ok, selected = pcall(Mods().GetSelectedMods)
        return ok and selected or {}
    end

    function view:IsOn(uid)
        return uid ~= nil and self:Selected()[uid] and true or false
    end

    --- The installed mods by uid (FAF's list, read again after an install or removal).
    function view:Installed()
        local ok, all = pcall(Mods().AllMods)
        return ok and all or {}
    end

    function view:VaultStatus(item)
        if self.installing and self.installing.uid == item.uid then
            return 'Installing...'
        end
        local installed = self:Installed()[item.uid]
        if installed then
            return self:IsOn(item.uid) and 'On' or 'Installed'
        end
        return ''
    end

    function view:SetOn(uid, on)
        local selected = {}
        for key, value in self:Selected() do
            selected[key] = value
        end
        selected[uid] = on and true or nil
        Mods().SetSelectedMods(selected)
        if rawget(_G, 'SavePreferences') then
            SavePreferences()
        end
        LOG('LAUNCHER: mod ' .. uid .. (on and ' on' or ' off'))
    end

    function view:SetTab(key)
        self.tab = key
        self.selected = nil
        if key == 'vault' and not self.vaultSearched then
            self:SearchVault(1)
        end
        self:Refresh()
    end

    function view:SearchVault(number)
        if number < 1 or (self.vaultPages > 0 and number > self.vaultPages) or self.searchJob or not Available() then
            return
        end
        self.vaultSearched = true
        self.searchJob = FafLibrary_SearchMods({
            name = self.search.edit:GetText(), type = self.vaultType,
            recommended = self.recommended.on and true or false, page = number, pageSize = kPageSize,
        })
        self.searchPage = number
        self.status, self.statusColor = 'Searching FAF\'s mod vault...', C.accent
        self:Refresh()
    end

    --- The selected mod's next step: install it (vault), or turn it on or off.
    function view:Act()
        local item = self.selected
        if not item then
            return
        end
        local installed = self:Installed()[item.uid]
        if self.tab == 'vault' and not installed then
            if self.installJob then
                return
            end
            local job, why = FafLibrary_InstallMod({ url = item.downloadUrl, uid = item.uid })
            if not job then
                self.status, self.statusColor = 'Can\'t install it: ' .. tostring(why), C.bad
            else
                self.installJob = job
                self.installing = item
                self.status, self.statusColor = 'Downloading ' .. item.name .. '...', C.accent
            end
            self:Refresh()
            return
        end
        if installed then
            self:SetOn(item.uid, not self:IsOn(item.uid))
            self:Refresh()
        end
    end

    function view:Remove()
        local item = self.selected
        local mod = item and self:Installed()[item.uid]
        local folder = mod and FolderOf(mod)
        if not folder then
            return
        end
        local ok, why = FafLibrary_RemoveMod(folder)
        if ok then
            if self:IsOn(item.uid) then
                self:SetOn(item.uid, false)
            end
            pcall(Mods().ClearCache)
            self.status, self.statusColor = 'Removed ' .. (mod.name or folder) .. '.', C.good
            if self.tab == 'local' then
                self.selected = nil
            end
        else
            self.status, self.statusColor = 'Can\'t remove it: ' .. tostring(why), C.bad
        end
        self:Refresh()
    end

    function view:Poll()
        if self.searchJob then
            local job = FafLibrary_Job(self.searchJob)
            if not job or job.state ~= 'working' then
                self.searchJob = nil
                if job and job.state == 'done' then
                    for _, item in job.items do
                        item.key = item.uid ~= '' and item.uid or item.id
                    end
                    self.vaultItems = job.items
                    self.vaultPage = self.searchPage
                    self.vaultPages = job.totalPages or 0
                    self.vaultTotal = job.totalRecords or 0
                    self.vaultList.top = 1
                    self.status, self.statusColor = '', C.subtle
                    LOG('LAUNCHER: mod vault page ' .. self.vaultPage .. ' of ' .. self.vaultPages .. ', ' ..
                        table.getn(job.items) .. ' mods')
                else
                    self.status = 'The search failed: ' .. tostring(job and job.message or 'no answer')
                    self.statusColor = C.bad
                    WARN('LAUNCHER: ' .. self.status)
                end
            end
        end
        if self.installJob then
            local job = FafLibrary_Job(self.installJob)
            if job and job.state == 'working' then
                if job.total > 0 then
                    self.status = string.format('Downloading %s... %d%%', self.installing.name,
                        math.floor(job.received * 100 / job.total))
                end
            else
                local item = self.installing
                self.installJob = nil
                self.installing = nil
                if job and job.state == 'done' then
                    pcall(Mods().ClearCache)
                    self.status, self.statusColor = 'Installed ' .. item.name .. '. Turn it on to use it in your next game.',
                        C.good
                    LOG('LAUNCHER: mod installed: ' .. item.name .. ' in ' .. tostring(job.path))
                else
                    self.status = 'The install failed: ' .. tostring(job and job.message or 'no answer')
                    self.statusColor = C.bad
                    WARN('LAUNCHER: ' .. self.status)
                end
            end
        end
    end

    function view:ShowDetails()
        local item = self.selected
        if not item then
            self.detailTitle:SetText('Pick a mod to see what it does.', C.subtle)
            self.detailLines:SetText('')
            self.description:SetText('')
            self.detailNote:SetText('')
            self.action:SetEnabled(false)
            self.action:SetLabel('Install')
            Theme.SetVisible(self.remove, false)
            Theme.SetVisible(self.reviewsButton, false)
            return
        end
        Theme.SetVisible(self.reviewsButton, item.id ~= nil and item.id ~= '' and self.tab == 'vault')
        local installed = self:Installed()[item.uid]
        local on = self:IsOn(item.uid)
        local lines = {}
        local description
        if self.tab == 'local' then
            table.insert(lines, (item.ui_only and 'UI mod' or 'Sim mod') .. '  -  version ' .. tostring(item.version or ''))
            if item.author and item.author ~= '' then
                table.insert(lines, 'By ' .. item.author)
            end
            table.insert(lines, (item.location or '') .. '  -  ' .. tostring(item.uid))
            description = item.description or ''
        else
            table.insert(lines, (item.type == 'UI' and 'UI mod' or 'Sim mod') .. '  -  version ' .. item.version ..
                (item.ranked and ', ranked' or ''))
            table.insert(lines, 'By ' .. (item.author ~= '' and item.author or item.uploader) ..
                (item.uploader ~= '' and item.uploader ~= item.author and (', uploaded by ' .. item.uploader) or ''))
            if item.reviews > 0 then
                table.insert(lines, string.format('Reviews: %.1f of 5 (%d)', item.reviewScore, item.reviews))
            end
            if item.updateTime ~= '' then
                table.insert(lines, 'Updated ' .. LocalTime(item.updateTime))
            end
            description = item.description
        end
        self.detailTitle:SetText(item.name or '', C.text)
        self.detailLines:SetText(table.concat(lines, '\n'), C.muted)
        self.description:SetText(description or '', C.text)

        local note = ''
        if not installed then
            self.action:SetLabel(self.installing and self.installing.uid == item.uid and 'Installing...' or 'Install')
            self.action:SetIconName('download')
            self.action:SetEnabled(self.tab == 'vault' and not self.installJob and item.downloadUrl ~= '')
            note = 'Downloads into ' .. (rawget(_G, 'FafLibrary_ModsFolder') and FafLibrary_ModsFolder() or 'the mods folder')
        else
            self.action:SetLabel(on and 'Turn off' or 'Turn on')
            self.action:SetIconName(on and 'minus' or 'plus')
            self.action:SetEnabled(true)
            if on then
                note = (installed.ui_only and 'On: your next game has it.' or
                    'On: games you host have it.')
            else
                note = 'Installed, off.'
            end
        end
        Theme.SetVisible(self.remove, installed ~= nil and FolderOf(installed) ~= nil)
        self.detailNote:SetText(note, C.muted)
    end

    function view:Refresh()
        self:Poll()
        local vault = self.tab == 'vault'
        local installed = self:Installed()
        local localItems = {}
        local filter = string.lower(self.search.edit:GetText())
        for uid, mod in installed do
            if vault or filter == '' or Contains(mod.name, filter) or Contains(mod.author, filter) then
                mod.key = uid
                table.insert(localItems, mod)
            end
        end
        table.sort(localItems, function(a, b) return string.lower(a.name or '') < string.lower(b.name or '') end)
        local installedCount = 0
        for _ in installed do
            installedCount = installedCount + 1
        end
        self.tabs:Set(self.tab, { ['local'] = installedCount,
            vault = vault and self.vaultTotal > 0 and self.vaultTotal or nil })
        for _, choice in self.types do
            Theme.SetVisible(choice, vault)
        end
        Theme.SetVisible(self.recommended, vault)
        Theme.SetVisible(self.searchButton, vault)
        Theme.SetVisible(self.localList, not vault)
        Theme.SetVisible(self.vaultList, vault)
        Theme.SetVisible(self.previous, vault)
        Theme.SetVisible(self.next, vault)
        Theme.SetVisible(self.pageText, vault)
        self.search:Refresh()

        local empty = ''
        local loading = false
        if not Available() then
            empty = 'This build of the game has no mod library.'
        elseif vault then
            if self.searchJob and table.getn(self.vaultItems) == 0 then
                empty, loading = 'Searching FAF\'s mod vault...', true
            elseif table.getn(self.vaultItems) == 0 and self.vaultSearched and not self.searchJob then
                empty = 'No mod matches.'
            end
            self.vaultList:SetItems(self.vaultItems)
            Theme.SetText(self.pageText, self.vaultPages > 0 and
                string.format('Page %d of %d', self.vaultPage, self.vaultPages) or '')
            self.previous:SetEnabled(self.vaultPage > 1 and not self.searchJob)
            self.next:SetEnabled(self.vaultPage < self.vaultPages and not self.searchJob)
        else
            if table.getn(localItems) == 0 then
                empty = filter ~= '' and 'No mod matches the search.' or 'No mods installed yet. The FAF vault has many.'
            end
            self.localList:SetItems(localItems)
        end
        Theme.SetText(self.empty, empty)
        Theme.SetVisible(self.loader, loading)
        Theme.SetText(self.footer, self.status ~= '' and self.status or (vault and
            'Pick a mod, then Install. Installed mods are usable at once.' or
            'Double-click a mod to turn it on or off. Your next game uses the mods that are on.'))
        Theme.SetColor(self.footer, self.statusColor)
        self:ShowDetails()
    end

    return view
end
