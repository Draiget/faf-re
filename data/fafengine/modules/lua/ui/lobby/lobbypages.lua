-- faf-re's lobby screen, two pages over it in the launcher's look:
-- - Game options: every option FAF's lobby has (lobbyoptions.lua's global, team and AI options, and the map's own),
--   grouped, with FAF's help for each, a search and "only changed"; the host picks values (the same SetOption FAF's
--   lobby uses), everyone else reads them.
-- - Mods: the mods on this computer, the game's (sim) mods and the player's interface (UI) mods. The host picks the
--   game's mods, each player their own UI mods; a game mod someone in the lobby doesn't have can't be picked, as in
--   FAF's mod manager. Apply hands the choice to FAF's lobby (OnModsChanged), which sends it to everyone.
-- Both reach FAF's lobby only through FafReLobbyApi (lobby.lua's hook).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kRow = 58

local function Strip(text)
    return (string.gsub(LOC(text or ''), '%s+$', ''))
end

--- An option value's key: its `key` field (which may be false, as Allow Observers' No), else the value itself.
local function ValueKey(value)
    if type(value) == 'table' and value.key ~= nil then
        return value.key
    end
    return value
end

--- An option value's text as FAF's lobby shows it: some are a format with the value's key in it ("%s").
local function ValueText(text, key)
    text = LOC(text or '')
    if string.find(text, '%%s') then
        return string.format(text, tostring(key))
    end
    if text == '' then
        return tostring(key)
    end
    return text
end

--- A page over the lobby: a panel nearly the screen's size with a title, a close button and a body (returned).
local function Page(root, title, subtitle)
    local frameW, frameH = Widgets.FrameUnits()
    local cover = Widgets.Modal(root, math.min(1100, frameW - 60), frameH - 60)
    local panel = cover.panel
    local head = Theme.Title(panel, title, 20, C.text)
    LayoutHelpers.AtLeftTopIn(head, panel, 28, 24)
    local note = Theme.Text(panel, subtitle or '', 13, C.subtle)
    note.Left:Set(function() return head.Right() + Scale(20) end)
    note.Bottom:Set(function() return head.Bottom() - Scale(2) end)
    cover.note = note
    cover.close = Theme.Button(panel, '', function() cover:Destroy() end, 'secondary', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(cover.close, panel, 24, 20)
    local body = Group(panel)
    body.Left:Set(function() return panel.Left() + Scale(28) end)
    body.Right:Set(function() return panel.Right() - Scale(28) end)
    body.Top:Set(function() return panel.Top() + Scale(76) end)
    body.Bottom:Set(function() return panel.Bottom() - Scale(24) end)
    Theme.SizeFromEdges(body)
    cover.body = body
    return cover
end

--- Rows of the same height under `top()`, as many as fit, the wheel moving through `page.items`; `paint(row, item)`
--- fills one and `build(row)` makes one's pieces.
local function Rows(page, area, build, paint)
    page.rows = {}
    page.top = 1
    local function Visible()
        return math.max(1, math.floor(area.Height() / Scale(kRow)))
    end
    for i = 1, 16 do
        local offset = (i - 1) * kRow
        local row = Group(area)
        row.Left:Set(area.Left)
        row.Right:Set(area.Right)
        row.Top:Set(function() return area.Top() + Scale(offset) end)
        LayoutHelpers.SetHeight(row, kRow)
        row.Width:Set(function() return row.Right() - row.Left() end)
        local line = Theme.Rect(row, C.line)
        line.Left:Set(row.Left)
        line.Right:Set(row.Right)
        line.Bottom:Set(row.Bottom)
        line.Height:Set(1)
        line.Width:Set(function() return line.Right() - line.Left() end)
        line:DisableHitTest()
        build(row)
        page.rows[i] = row
    end
    function page:PaintRows()
        local items = self.items or {}
        local visible = Visible()
        self.top = math.max(1, math.min(self.top, table.getn(items) - visible + 1))
        for i, row in self.rows do
            local item = (i <= visible) and items[self.top + i - 1] or nil
            row.item = item
            Theme.SetVisible(row, item ~= nil)
            if item then
                paint(row, item)
            end
        end
    end
    Theme.HitArea(area, function(self, event)
        if event.Type == 'WheelRotation' then
            page.top = page.top + (event.WheelRotation > 0 and -3 or 3)
            page:PaintRows()
            return true
        end
        return false
    end).Depth:Set(function() return area.Depth() - 1 end)
end

------------------------------------------------------------------------------------------------------------------------
-- Game options.

--- Every option the lobby shows, in FAF's sections: {section, key, label, help, value, isDefault, option}.
local function OptionItems(view)
    local api = view.api
    local info = api.GameInfo()
    local options = import('/lua/ui/lobby/lobbyoptions.lua')
    local items = {}
    local function Add(section, definitions)
        for _, option in definitions or {} do
            if not (option.mponly and api.IsSinglePlayer()) and option.values and table.getn(option.values) > 1 then
                local current = info.GameOptions[option.key]
                local text, isDefault = '', false
                for index, value in option.values do
                    local key = ValueKey(value)
                    if key == current or tostring(key) == tostring(current) then
                        text = ValueText(value.text or option.value_text, key)
                        isDefault = index == option.default
                    end
                end
                table.insert(items, { section = section, key = option.key, label = Strip(option.label),
                    help = Strip(option.help), value = text, isDefault = isDefault, option = option })
            end
        end
    end
    Add('Game', options.globalOpts)
    Add('Teams', options.teamOptions)
    Add('AI', options.AIOpts)
    if view.scenario and view.scenario.options then
        Add('This map', view.scenario.options)
    end
    return items
end

function OpenOptions(view)
    local api = view.api
    local host = api.IsHost()
    local page = Page(view.root, 'Game options', host and 'Pick a value to change it for everyone' or
        'The host sets these')
    page.onlyChanged = false
    local body = page.body
    page.search = Theme.TextField(body, 320, 'Search the options', 'search', 40)
    LayoutHelpers.AtLeftTopIn(page.search, body, 0, 0)
    page.search:OnChange(function()
        page.top = 1
        page:Refresh()
    end)
    page.onlyBox = Theme.Checkbox(body, 'Only changed', function(box)
        page.onlyChanged = box.on
        page.top = 1
        page:Refresh()
    end)
    page.onlyBox.Left:Set(function() return page.search.Right() + Scale(20) end)
    LayoutHelpers.AtVerticalCenterIn(page.onlyBox, page.search)
    page.defaults = Theme.Button(body, 'All to defaults', function() page:Defaults() end, 'ghost',
        { width = 170, icon = 'refresh' })
    page.defaults.Right:Set(body.Right)
    page.defaults.Top:Set(page.search.Top)
    Theme.SetVisible(page.defaults, host)
    -- FAF's own dialog stays one click away (presets, the map dialog's own pages).
    page.faf = Theme.Button(body, 'FAF\'s dialog', function()
        page:Destroy()
        api.OpenAdvanced()
    end, 'ghost', { width = 150, icon = 'external' })
    page.faf.Right:Set(function() return page.defaults.Left() - Scale(10) end)
    page.faf.Top:Set(page.search.Top)
    Theme.SetVisible(page.faf, host)

    local area = Group(body)
    area.Left:Set(body.Left)
    area.Right:Set(body.Right)
    area.Top:Set(function() return page.search.Bottom() + Scale(16) end)
    area.Bottom:Set(body.Bottom)
    Theme.SizeFromEdges(area)
    Rows(page, area, function(row)
        row.section = Theme.Text(row, '', 11, C.accent, true)
        LayoutHelpers.AtLeftTopIn(row.section, row, 0, 4)
        row.label = Theme.Cell(row, 14, C.text)
        row.label.Left:Set(function() return row.Left() + Scale(110) end)
        row.label.Right:Set(function() return row.Right() - Scale(320) end)
        row.label.Top:Set(function() return row.Top() + Scale(8) end)
        row.help = Theme.Cell(row, 12, C.subtle)
        row.help.Left:Set(row.label.Left)
        row.help.Right:Set(row.label.Right)
        row.help.Top:Set(function() return row.Top() + Scale(30) end)
        -- Made with a text: a button made without one has no label to set later.
        row.value = Theme.Button(row, 'value', function()
            if row.item and host then
                view:OpenOption(row.item, row.value)
            end
        end, 'secondary', { width = 290, icon = 'chevronDown' })
        row.value.Right:Set(row.Right)
        LayoutHelpers.AtVerticalCenterIn(row.value, row)
    end, function(row, item)
        Theme.SetText(row.section, item.firstOfSection and string.upper(item.section) or '')
        Theme.SetText(row.label, item.label)
        Theme.SetColor(row.label, item.isDefault and C.text or C.accent)
        Theme.SetText(row.help, item.help)
        row.value:SetLabel(item.value)
        row.value:SetEnabled(host)
    end)

    function page:Refresh()
        local filter = string.lower(self.search.edit:GetText())
        local items = {}
        local changed = 0
        local lastSection = nil
        for _, item in OptionItems(view) do
            if not item.isDefault then
                changed = changed + 1
            end
            if (not self.onlyChanged or not item.isDefault) and (filter == '' or
                string.find(string.lower(item.label), filter, 1, true) or
                string.find(string.lower(item.help), filter, 1, true) or
                string.find(string.lower(item.value), filter, 1, true)) then
                item.firstOfSection = item.section ~= lastSection
                lastSection = item.section
                table.insert(items, item)
            end
        end
        self.items = items
        self.changed = changed
        Theme.SetText(self.note, (host and 'Pick a value to change it for everyone' or 'The host sets these') ..
            '  -  ' .. changed .. ' changed from the defaults')
        self:PaintRows()
    end

    --- Every option the host changed back to its default (one SetOption each, as FAF's lobby sends them).
    function page:Defaults()
        for _, item in OptionItems(view) do
            if not item.isDefault and item.option.default and item.option.values[item.option.default] then
                api.SetOption(item.key, ValueKey(item.option.values[item.option.default]))
            end
        end
        self:Refresh()
    end

    -- The lobby's own refresh paints it again (another player's change, a value just picked).
    page:SetNeedsFrameUpdate(true)
    page.since = 0
    page.OnFrame = function(self, delta)
        self.since = self.since + delta
        if self.since > 0.5 then
            self.since = 0
            self:Refresh()
        end
    end
    page:Refresh()
    view.optionsPage = page
    return page
end

------------------------------------------------------------------------------------------------------------------------
-- Mods.

--- The mods on this computer for this lobby: {uid, name, version, author, description, icon, ui, on, why}; `why` says
--- why one can't be picked (blocked by its own file, someone lacks it, a mod it needs is missing).
local function ModItems(api, chosen)
    local items = {}
    for uid, mod in api.AllMods() do
        local item = { uid = uid, name = tostring(mod.name or uid), version = mod.version and tostring(mod.version) or '',
            author = tostring(mod.author or ''), description = tostring(mod.description or ''), ui = mod.ui_only and true or false,
            icon = mod.icon, on = chosen[uid] and true or false }
        if mod.enabled == false then
            item.why = 'turned off by its own files'
        elseif not item.ui and not api.EveryoneHasMod(uid) then
            item.why = 'someone in the lobby doesn\'t have it'
        elseif api.ModMissingDependencies(uid) then
            item.why = 'needs a mod that isn\'t installed'
        end
        table.insert(items, item)
    end
    table.sort(items, function(a, b)
        if a.on ~= b.on then
            return a.on
        end
        return string.lower(a.name) < string.lower(b.name)
    end)
    return items
end

function OpenMods(view)
    local api = view.api
    local host = api.IsHost()
    local page = Page(view.root, 'Mods', '')
    page.kind = 'game'
    -- The choice being made, from the lobby's: uid -> true.
    page.chosen = {}
    for uid in api.SelectedMods() do
        page.chosen[uid] = true
    end
    local body = page.body
    page.tabs = Widgets.Tabs(body, { { 'game', 'Game mods' }, { 'ui', 'Interface mods' } }, function(key)
        page.kind = key
        page.top = 1
        page:Refresh()
    end)
    LayoutHelpers.AtLeftTopIn(page.tabs, body, 0, 0)
    page.tabs.Right:Set(function() return body.Right() - Scale(300) end)
    page.apply = Theme.Button(body, 'Apply', function() page:Apply() end, 'primary', { width = 140, icon = 'check' })
    page.apply.Right:Set(body.Right)
    page.apply.Top:Set(page.tabs.Top)
    page.faf = Theme.Button(body, 'FAF\'s manager', function()
        page:Destroy()
        api.OpenMods()
    end, 'ghost', { width = 150, icon = 'external' })
    page.faf.Right:Set(function() return page.apply.Left() - Scale(10) end)
    page.faf.Top:Set(page.tabs.Top)
    page.say = Theme.Paragraph(body, 13, C.muted)
    page.say.Left:Set(body.Left)
    page.say.Right:Set(body.Right)
    page.say.Top:Set(function() return page.tabs.Bottom() + Scale(10) end)

    local area = Group(body)
    area.Left:Set(body.Left)
    area.Right:Set(body.Right)
    area.Top:Set(function() return page.tabs.Bottom() + Scale(44) end)
    area.Bottom:Set(body.Bottom)
    Theme.SizeFromEdges(area)
    Rows(page, area, function(row)
        row.frame = Theme.Panel(row, 'ff08121a', C.line)
        LayoutHelpers.SetDimensions(row.frame, 44, 44)
        LayoutHelpers.AtLeftIn(row.frame, row, 0)
        LayoutHelpers.AtVerticalCenterIn(row.frame, row)
        row.icon = Bitmap(row.frame)
        row.icon:DisableHitTest()
        LayoutHelpers.FillParentFixedBorder(row.icon, row.frame, 1)
        row.icon.Depth:Set(function() return row.frame.Depth() + 2 end)
        row.placeholder = Theme.Icon(row.frame, 'mods', 22, C.subtle)
        LayoutHelpers.AtCenterIn(row.placeholder, row.frame)
        row.name = Theme.Cell(row, 14, C.text)
        row.name.Left:Set(function() return row.frame.Right() + Scale(14) end)
        row.name.Right:Set(function() return row.Right() - Scale(200) end)
        row.name.Top:Set(function() return row.Top() + Scale(8) end)
        row.about = Theme.Cell(row, 12, C.subtle)
        row.about.Left:Set(row.name.Left)
        row.about.Right:Set(row.name.Right)
        row.about.Top:Set(function() return row.Top() + Scale(30) end)
        row.box = Theme.Checkbox(row, 'On', function(box)
            if row.item then
                page.chosen[row.item.uid] = box.on or nil
                page:Refresh()
            end
        end)
        row.box.Right:Set(row.Right)
        LayoutHelpers.AtVerticalCenterIn(row.box, row)
        row.why = Theme.Text(row, '', 11, C.warn)
        row.why.Right:Set(row.Right)
        LayoutHelpers.AtVerticalCenterIn(row.why, row)
    end, function(row, item)
        local icon = item.icon and item.icon ~= '' and DiskGetFileInfo(item.icon) and item.icon or nil
        if icon and row.shownIcon ~= icon then
            row.shownIcon = icon
            row.icon:SetTexture(icon)
        end
        Theme.SetVisible(row.icon, icon ~= nil)
        Theme.SetVisible(row.placeholder, icon == nil)
        Theme.SetText(row.name, item.name .. (item.version ~= '' and ('  v' .. item.version) or ''))
        Theme.SetColor(row.name, page.chosen[item.uid] and C.accent or C.text)
        Theme.SetText(row.about, (item.author ~= '' and (item.author .. '  -  ') or '') .. item.description)
        local canPick = not item.why and (item.ui or host)
        Theme.SetVisible(row.box, canPick)
        Theme.SetVisible(row.why, not canPick)
        Theme.SetText(row.why, item.why or 'the host picks game mods')
        row.box:SetOn(page.chosen[item.uid] and true or false)
    end)

    function page:Refresh()
        local items = {}
        local games, uis, gameOn, uiOn = 0, 0, 0, 0
        for _, item in ModItems(api, self.chosen) do
            if item.ui then
                uis = uis + 1
                uiOn = uiOn + (self.chosen[item.uid] and 1 or 0)
            else
                games = games + 1
                gameOn = gameOn + (self.chosen[item.uid] and 1 or 0)
            end
            if item.ui == (self.kind == 'ui') then
                table.insert(items, item)
            end
        end
        self.items = items
        self.counts = { game = games, ui = uis, gameOn = gameOn, uiOn = uiOn }
        self.tabs:Set(self.kind, { game = gameOn .. '/' .. games, ui = uiOn .. '/' .. uis })
        local text
        if self.kind == 'game' then
            text = host and 'Game mods change the game for everyone in it; each player needs them installed.' or
                'Game mods change the game for everyone; the host picks them.'
        else
            text = 'Interface mods change only your own screen; nobody else needs them.'
        end
        if table.getn(items) == 0 then
            text = text .. '  No mods of this kind are installed; the launcher\'s Mods page gets them from FAF\'s vault.'
        end
        self.say:SetText(text, C.muted)
        self:PaintRows()
    end

    --- Hands the choice to FAF's lobby: the host's game mods go to everyone; UI mods are the player's own.
    function page:Apply()
        local sim, ui = {}, {}
        for uid in self.chosen do
            local mod = api.AllMods()[uid]
            if mod then
                if mod.ui_only then
                    ui[uid] = true
                elseif host then
                    sim[uid] = true
                end
            end
        end
        if not host then
            -- A player keeps the host's game mods; only their interface mods are theirs to change.
            for uid in api.SelectedMods() do
                local mod = api.AllMods()[uid]
                if mod and not mod.ui_only then
                    sim[uid] = true
                end
            end
        end
        api.SetMods(sim, ui)
        LOG('faf-re lobby: mods applied: ' .. table.getsize(sim) .. ' game, ' .. table.getsize(ui) .. ' interface')
        self:Destroy()
        view:Refresh()
    end

    page:Refresh()
    view.modsPage = page
    return page
end
