-- The launcher's Options page: FAF's options (/lua/options/options.lua, with the engine's own merged in by
-- fafengine's hook), drawn in the launcher's look. A tab per section and a search over all of them; toggles as
-- dropdowns of their states, sliders with their value. Changes wait for Apply, which goes through FAF's options logic
-- (optionsLogic.SetCurrent), so an option that needs a restart or a check ("keep these settings?") asks as in FAF's own
-- screen. A Profile tab switches profiles (each profile has its own options).

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kRowHeight = 58 -- a title and a line of help under it

local function Logic()
    return import('/lua/options/optionsLogic.lua')
end

local function CopyTable(source)
    local copy = {}
    for key, value in source or {} do
        copy[key] = value
    end
    return copy
end

local function Text(value)
    return LOC(value or '')
end

--- An option's help in the player's language: FAF's tooltip (options_<key>, translated by the game's own LOC), else
--- its tip, else the launcher's own text for options FAF has none for (optionhelp.lua, per language).
local function Help(item)
    local ok, tooltips = pcall(import, '/lua/ui/help/tooltips.lua')
    local info = ok and tooltips and tooltips.Tooltips and tooltips.Tooltips['options_' .. tostring(item.key)]
    if info and info.description and info.description ~= '' then
        return Text(info.description)
    end
    if item.tip then
        return Text(item.tip)
    end
    local helpOk, own = pcall(import, '/fafengine/modules/lua/ui/launcher/optionhelp.lua')
    return helpOk and own.Help(item.key) or ''
end

--- A slider's value as text: whole numbers unless its step is a fraction.
local function SliderText(item, value)
    local inc = item.custom and item.custom.inc or 1
    if inc < 1 then
        return string.format('%.2f', value or 0)
    end
    return tostring(math.floor((value or 0) + 0.5))
end

--- A toggle's state text for `value`.
local function StateText(item, value)
    for _, state in item.custom and item.custom.states or {} do
        if state.key == value then
            return Text(state.text)
        end
    end
    return tostring(value)
end

function Build(launcher, page)
    local view = { tab = nil, rows = {}, top = 1, entries = {} }
    launcher.optionsView = view

    local title = Theme.Title(page, 'Options', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.sections = {}
    local tabs = {}
    local ok, data = pcall(Logic().GetOptionsData)
    view.data = ok and data or {}
    local ordered = import('/lua/options/options.lua').optionsOrder or {}
    for _, key in ordered do
        if view.data[key] then
            table.insert(tabs, { key, Text(view.data[key].title) })
            table.insert(view.sections, key)
        end
    end
    table.insert(tabs, { 'profile', 'Profile' })
    view.tab = view.sections[1] or 'profile'
    view.tabs = Widgets.Tabs(page, tabs, function(key)
        view.tab = key
        view.top = 1
        view.search.edit:SetText('')
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

    view.search = Theme.TextField(page, 320, 'Search all options', 'search', 60)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search:OnChange(function()
        view.top = 1
        view:Refresh()
    end)

    -- Apply, Revert and Defaults at the top right; what changed beside them.
    view.apply = Theme.Button(page, 'Apply', function() view:Apply() end, 'primary', { width = 140, icon = 'check' })
    view.apply.Right:Set(page.Right)
    view.apply.Top:Set(view.search.Top)
    view.revert = Theme.Button(page, 'Revert', function() view:Revert() end, 'secondary', { width = 120 })
    view.revert.Right:Set(function() return view.apply.Left() - Scale(10) end)
    view.revert.Top:Set(view.search.Top)
    view.defaults = Theme.Button(page, 'Defaults', function() view:Defaults() end, 'ghost', { width = 120 })
    view.defaults.Right:Set(function() return view.revert.Left() - Scale(10) end)
    view.defaults.Top:Set(view.search.Top)
    view.changes = Theme.Text(page, '', 12, C.accent)
    view.changes.Right:Set(function() return view.defaults.Left() - Scale(16) end)
    LayoutHelpers.AtVerticalCenterIn(view.changes, view.apply)

    -- The rows, and the help of the one under the mouse below them.
    local panel = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(panel, C.accent)
    panel.Left:Set(page.Left)
    panel.Right:Set(page.Right)
    panel.Top:Set(function() return view.search.Bottom() + Scale(16) end)
    panel.Bottom:Set(function() return page.Bottom() - Scale(70) end)
    view.panel = panel
    local area = Group(panel)
    area.Left:Set(function() return panel.Left() + Scale(24) end)
    area.Right:Set(function() return panel.Right() - Scale(20) end)
    area.Top:Set(function() return panel.Top() + Scale(10) end)
    area.Bottom:Set(function() return panel.Bottom() - Scale(10) end)
    area.Width:Set(function() return area.Right() - area.Left() end)
    area.Height:Set(function() return area.Bottom() - area.Top() end)
    view.area = area
    view.mark = Widgets.ScrollMark(area, view)
    Theme.HitArea(area, function(self, event)
        if event.Type == 'WheelRotation' then
            local step = event.WheelRotation > 0 and -3 or 3
            view.top = math.max(1, math.min(view.top + step, math.max(1, table.getn(view.entries) - view:Shown() + 1)))
            view:Paint()
            return true
        end
        return false
    end).Depth:Set(function() return area.Depth() - 1 end) -- under the rows' own controls
    view.help = Theme.Paragraph(page, 13, C.muted)
    view.help.Left:Set(page.Left)
    view.help.Right:Set(page.Right)
    view.help.Top:Set(function() return panel.Bottom() + Scale(12) end)

    -- -------------------------------------------------------------------------------------------------------------

    function view:Shown()
        return math.max(1, math.floor((self.area.Bottom() - self.area.Top()) / Scale(kRowHeight)))
    end

    function view:Scrolled()
        return self.top, self:Shown(), table.getn(self.entries)
    end

    --- The values as they are saved, and the ones being edited.
    function view:Load()
        local ok, current = pcall(Logic().GetCurrent)
        self.current = ok and CopyTable(current) or {}
        self.pending = CopyTable(self.current)
        pcall(Logic().Repopulate) -- lists that depend on the machine (displays, resolutions)
        for _, section in self.data do
            for _, item in section.items do
                if item.init then
                    pcall(item.init)
                end
                -- What FAF's logic calls to show a value it set (a verify undo, a restart cancel) on the control.
                local this = item
                this.control = this.control or true
                this.change = function(control, value)
                    view.pending[this.key] = value
                    view:Paint()
                end
            end
        end
    end

    function view:Changed()
        local count = 0
        for key, value in self.pending do
            if self.current[key] ~= value then
                count = count + 1
            end
        end
        return count
    end

    function view:Set(item, value)
        self.pending[item.key] = value
        if item.update then
            pcall(item.update, nil, value) -- a live preview (volumes)
        end
        self:Paint()
    end

    function view:Apply()
        local logic = Logic()
        logic.SetSummonRestartDialogCallback(function(proceed, cancel)
            UIUtil.QuickDialog(GetFrame(0), 'Some of these changes take effect only after the game starts again.',
                'Quit the game now', proceed, 'Keep playing', cancel, nil, nil, true,
                { worldCover = true, enterButton = 1, escapeButton = 2 })
        end)
        logic.SetSummonVerifyDialogCallback(function(undo)
            local answered = false
            local dialog = UIUtil.QuickDialog(GetFrame(0), 'Keep these display settings? They go back in 15 seconds.',
                'Keep', function() answered = true end, 'Go back', function()
                    answered = true
                    undo()
                    view:Load()
                    view:Paint()
                end, nil, nil, true, { worldCover = true, enterButton = 1, escapeButton = 2 })
            ForkThread(function()
                WaitSeconds(15)
                if not answered then
                    answered = true
                    if dialog then
                        pcall(dialog.Destroy, dialog)
                    end
                    undo()
                    view:Load()
                    view:Paint()
                end
            end)
        end)
        local changed = self:Changed()
        local done, why = pcall(logic.SetCurrent, CopyTable(self.pending))
        if not done then
            WARN('LAUNCHER: options failed to apply: ' .. tostring(why))
        end
        LOG('LAUNCHER: options applied (' .. changed .. ' changed)')
        self:Load()
        self:Paint()
    end

    function view:Revert()
        for _, section in self.data do
            for _, item in section.items do
                if item.cancel and self.pending[item.key] ~= self.current[item.key] then
                    pcall(item.cancel)
                end
            end
        end
        self.pending = CopyTable(self.current)
        self:Paint()
    end

    --- The tab's options back to their defaults (waiting for Apply).
    function view:Defaults()
        local section = self.data[self.tab]
        for _, item in section and section.items or {} do
            if item.type ~= 'header' and item.default ~= nil then
                self:Set(item, item.default)
            end
        end
    end

    --- The rows: the tab's items, or every item whose title matches the search (with its tab's name).
    function view:Entries()
        local entries = {}
        local filter = string.lower(self.search.edit:GetText())
        if self.tab == 'profile' and filter == '' then
            local profiles = GetPreference('profile.profiles') or {}
            local current = GetPreference('profile.current')
            table.insert(entries, { kind = 'header', title = 'Profiles: each has its own options' })
            for index, profile in profiles do
                table.insert(entries, { kind = 'profile', index = index, title = tostring(profile.Name),
                    current = index == current })
            end
            table.insert(entries, { kind = 'manage', title = 'Create, rename or delete profiles' })
            return entries
        end
        if filter ~= '' then
            for _, key in self.sections do
                local section = self.data[key]
                local header = nil
                for _, item in section.items do
                    if item.type ~= 'header' and string.find(string.lower(Text(item.title)), filter, 1, true) then
                        if not header then
                            header = { kind = 'header', title = Text(section.title) }
                            table.insert(entries, header)
                        end
                        table.insert(entries, { kind = 'item', item = item })
                    end
                end
            end
            return entries
        end
        local section = self.data[self.tab]
        for _, item in section and section.items or {} do
            table.insert(entries, item.type == 'header' and { kind = 'header', title = Text(item.title) } or
                { kind = 'item', item = item })
        end
        return entries
    end

    local function Row(index)
        local row = view.rows[index]
        if row then
            return row
        end
        row = {}
        local top = function() return area.Top() + Scale((index - 1) * kRowHeight) end
        row.back = Theme.Rect(area, C.clear)
        row.back.Left:Set(area.Left)
        row.back.Right:Set(function() return area.Right() - Scale(8) end)
        row.back.Top:Set(top)
        row.back.Height:Set(Scale(kRowHeight - 4))
        row.back.Width:Set(function() return row.back.Right() - row.back.Left() end)
        row.title = Theme.Cell(area, 14, C.text)
        row.title.Left:Set(function() return area.Left() + Scale(12) end)
        row.title.Right:Set(function() return area.Right() - Scale(420) end)
        row.title.Top:Set(function() return top() + Scale(6) end)
        row.about = Theme.Cell(area, 11, C.subtle)
        row.about.Left:Set(row.title.Left)
        row.about.Right:Set(row.title.Right)
        row.about.Top:Set(function() return top() + Scale(28) end)
        row.heading = Theme.Text(area, '', 12, C.accent, true)
        row.heading.Left:Set(area.Left)
        row.heading.Top:Set(function() return top() + Scale(26) end)
        -- A toggle: a dropdown of its states.
        -- Made with a label: a button made without one has no text to change later.
        row.choice = Theme.Button(area, 'Off', function()
            local item = row.entry and row.entry.item
            if not item then
                return
            end
            local items = {}
            for _, state in item.custom and item.custom.states or {} do
                table.insert(items, { Text(state.text), key = state.key,
                    color = state.key == view.pending[item.key] and C.accent or C.text })
            end
            Widgets.Dropdown(row.choice, items, function(picked)
                view:Set(item, picked.key)
            end, { width = 300, maxRows = 14 })
        end, 'secondary', { width = 300, icon = 'chevronDown', caps = false })
        row.choice.Right:Set(function() return area.Right() - Scale(16) end)
        row.choice.Top:Set(function() return top() + Scale(10) end)
        -- A slider: its track (a click sets the value), its fill and its value; the wheel over it steps.
        row.track = Theme.Rect(area, C.line)
        row.track.Right:Set(function() return area.Right() - Scale(90) end)
        row.track.Width:Set(Scale(226))
        row.track.Left:Set(function() return row.track.Right() - row.track.Width() end)
        row.track.Top:Set(function() return top() + Scale(25) end)
        row.track.Height:Set(Scale(4))
        row.fill = Theme.Rect(area, C.accent)
        row.fill.Left:Set(row.track.Left)
        row.fill.Top:Set(row.track.Top)
        row.fill.Height:Set(row.track.Height)
        row.fill:DisableHitTest()
        row.knob = Theme.Rect(area, C.text)
        row.knob.Top:Set(function() return row.track.Top() - Scale(7) end)
        row.knob.Width:Set(Scale(6))
        row.knob.Height:Set(Scale(18))
        row.knob:DisableHitTest()
        row.value = Theme.Text(area, '', 14, C.gold)
        row.value.Right:Set(function() return area.Right() - Scale(16) end)
        row.value.Top:Set(function() return top() + Scale(18) end)
        local sliderArea = Theme.Rect(area, C.clear)
        sliderArea.Left:Set(function() return row.track.Left() - Scale(6) end)
        sliderArea.Right:Set(function() return row.track.Right() + Scale(6) end)
        sliderArea.Top:Set(function() return row.track.Top() - Scale(12) end)
        sliderArea.Bottom:Set(function() return row.track.Bottom() + Scale(12) end)
        Theme.SizeFromEdges(sliderArea)
        row.sliderArea = sliderArea
        local function SliderAt(x)
            local item = row.entry and row.entry.item
            local custom = item and item.custom
            if not custom then
                return
            end
            local share = math.max(0, math.min(1, (x - row.track.Left()) / math.max(1, row.track.Width())))
            local inc = custom.inc or 1
            local value = custom.min + share * (custom.max - custom.min)
            value = custom.min + math.floor((value - custom.min) / inc + 0.5) * inc
            view:Set(item, math.max(custom.min, math.min(custom.max, value)))
        end
        sliderArea.HandleEvent = function(self, event)
            local item = row.entry and row.entry.item
            if not item or item.type ~= 'slider' then
                return false
            end
            if event.Type == 'ButtonPress' and event.Modifiers.Left then
                row.dragging = true
                SliderAt(event.MouseX)
                return true
            elseif event.Type == 'MouseMotion' and row.dragging then
                SliderAt(event.MouseX)
                return true
            elseif event.Type == 'ButtonRelease' or event.Type == 'MouseExit' then
                row.dragging = false
            elseif event.Type == 'WheelRotation' then
                local custom = item.custom
                local value = (view.pending[item.key] or custom.min) + (event.WheelRotation > 0 and 1 or -1) * (custom.inc or 1)
                view:Set(item, math.max(custom.min, math.min(custom.max, value)))
                return true
            end
            return false
        end
        -- A profile: Use; the manager: FAF's profile dialog.
        row.use = Theme.Button(area, 'Use', function()
            local entry = row.entry
            if entry and entry.kind == 'profile' then
                SetPreference('profile.current', entry.index)
                SavePreferences()
                LOG('LAUNCHER: profile ' .. entry.title .. ' in use')
                view:Load()
                view:Refresh()
            elseif entry and entry.kind == 'manage' then
                launcher:OpenScreen('Profiles', function(host, back)
                    import('/lua/ui/dialogs/profile.lua').CreateDialog(function()
                        ForkThread(function()
                            back()
                            view:Load()
                            view:Refresh()
                        end)
                    end)
                end)
            end
        end, 'secondary', { width = 160 })
        row.use.Right:Set(function() return area.Right() - Scale(16) end)
        row.use.Top:Set(function() return top() + Scale(10) end)
        -- The mouse over the row: its help below.
        Theme.HitArea(row.back, function(self, event)
            if event.Type == 'MouseEnter' and row.entry and row.entry.item then
                view.help:SetText(Help(row.entry.item), C.muted)
            end
            return false
        end).Depth:Set(function() return row.back.Depth() + 1 end)
        view.rows[index] = row
        return row
    end

    function view:Paint()
        if not self.pending then
            return
        end
        local shown = self:Shown()
        for i = 1, shown do
            local row = Row(i)
            local entry = self.entries[self.top + i - 1]
            row.entry = entry
            local kind = entry and entry.kind
            local item = entry and entry.item
            Theme.SetVisible(row.back, kind == 'item' or kind == 'profile' or kind == 'manage')
            Theme.SetVisible(row.title, kind == 'item' or kind == 'profile' or kind == 'manage')
            Theme.SetVisible(row.about, kind == 'item')
            Theme.SetVisible(row.heading, kind == 'header')
            local isToggle = kind == 'item' and item.type == 'toggle'
            local isSlider = kind == 'item' and item.type == 'slider'
            Theme.SetVisible(row.choice, isToggle)
            Theme.SetVisible(row.track, isSlider)
            Theme.SetVisible(row.fill, isSlider)
            Theme.SetVisible(row.knob, isSlider)
            Theme.SetVisible(row.value, isSlider)
            Theme.SetVisible(row.sliderArea, isSlider)
            Theme.SetVisible(row.use, kind == 'profile' or kind == 'manage')
            if kind == 'header' then
                Theme.SetText(row.heading, string.upper(entry.title))
            elseif kind == 'item' then
                local value = self.pending[item.key]
                local changed = value ~= self.current[item.key]
                Theme.SetText(row.title, Text(item.title))
                local help = Help(item)
                Theme.SetText(row.about, help ~= '' and help or 'No description yet.')
                Theme.SetColor(row.title, changed and C.accent or C.text)
                row.back:SetSolidColor(changed and Theme.WithAlpha(C.accent, 0.06) or C.clear)
                if isToggle then
                    row.choice:SetLabel(StateText(item, value))
                elseif isSlider then
                    local custom = item.custom or { min = 0, max = 1 }
                    local share = (custom.max > custom.min) and ((value or custom.min) - custom.min) / (custom.max - custom.min) or 0
                    share = math.max(0, math.min(1, share))
                    row.fill.Width:Set(function() return math.floor(row.track.Width() * share) end)
                    row.knob.Left:Set(function() return row.track.Left() + math.floor(row.track.Width() * share) - Scale(3) end)
                    Theme.SetText(row.value, SliderText(item, value))
                end
            elseif kind == 'profile' then
                Theme.SetText(row.title, entry.title .. (entry.current and '   (in use)' or ''))
                Theme.SetColor(row.title, entry.current and C.accent or C.text)
                row.back:SetSolidColor(C.clear)
                row.use:SetLabel('Use')
                row.use:SetEnabled(not entry.current)
            elseif kind == 'manage' then
                Theme.SetText(row.title, entry.title)
                Theme.SetColor(row.title, C.muted)
                row.back:SetSolidColor(C.clear)
                row.use:SetLabel('Manage profiles')
                row.use:SetEnabled(true)
            end
        end
        for i = shown + 1, table.getn(self.rows) do
            local row = self.rows[i]
            row.entry = nil
            for _, control in { row.back, row.title, row.about, row.heading, row.choice, row.track, row.fill, row.knob, row.value,
                row.sliderArea, row.use } do
                Theme.SetVisible(control, false)
            end
        end
        local changed = self:Changed()
        Theme.SetText(self.changes, changed > 0 and (changed .. (changed == 1 and ' change' or ' changes') ..
            ' not applied') or '')
        self.apply:SetEnabled(changed > 0)
        self.revert:SetEnabled(changed > 0)
        self.defaults:SetEnabled(self.data[self.tab] ~= nil)
        self.mark:Update()
    end

    function view:Refresh()
        if not self.pending then
            self:Load()
        end
        self.tabs:Set(self.tab, {})
        self.search:Refresh()
        self.entries = self:Entries()
        self.top = math.min(self.top, math.max(1, table.getn(self.entries) - self:Shown() + 1))
        self:Paint()
    end

    return view
end
