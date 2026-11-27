-- The Options page's Key bindings tab: every action with its key, FAF's three presets (GPG's default, hotbuild,
-- alternative hotbuild), the player's own presets saved by name, and a key changed by pressing it. The bindings are
-- FAF's own (keymapper.lua: UserKeyMapName, UserKeyMap and UserDebugKeyMap in the profile), applied to the game's
-- input as each change is made, as FAF's key binding screen does on its OK.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local KeyMapper = import('/lua/keymap/keymapper.lua')

-- FAF's presets, by the names keymapper.ResetUserKeyMapTo takes.
local kPresets = {
    { 'defaultKeyMap.lua', 'GPG default' },
    { 'hotbuildKeyMap.lua', 'Hotbuild' },
    { 'alternativeKeyMap.lua', 'Alternative hotbuild' },
}
local kOwnPresets = 'fafre_key_presets' -- the player's presets: {name = {base, map, debug}}

local function Lower(text)
    return string.lower(tostring(text or ''))
end

--- A key as people read it: "Ctrl + Shift + F", through FAF's key names.
local function KeyText(key)
    if not key or key == '' then
        return ''
    end
    local ok, text = pcall(function() return import('/lua/ui/dialogs/keybindings.lua').FormatKeyName(key) end)
    return ok and text or key
end

--- The preset the bindings start from: FAF's preset name as the profile keeps it.
local function BaseName()
    local name = Lower(KeyMapper.GetDefaultKeyMapName())
    for _, preset in kPresets do
        if string.find(name, Lower(preset[1]), 1, true) then
            return preset[1]
        end
    end
    return kPresets[1][1]
end

--- Puts the profile's bindings into the game's input (FAF's key screen does this on OK).
local function ApplyToInput()
    KeyMapper.SaveUserKeyMap()
    if rawget(_G, 'IN_ClearKeyMap') and rawget(_G, 'IN_AddKeyMapTable') then
        IN_ClearKeyMap()
        IN_AddKeyMapTable(KeyMapper.GetKeyMappings(true))
    end
end

--- Every action as a row (category, name, key), the categories in FAF's order; `filter` matches any of them.
local function Rows(filter)
    local categories = import('/lua/keymap/keycategories.lua')
    local order = {}
    for index, category in categories.keyCategoryOrder or {} do
        order[Lower(category)] = index
    end
    local lookup = KeyMapper.GetKeyLookup()
    local rows = {}
    for action, info in KeyMapper.GetKeyActions() do
        local category = Lower(info.category or 'none')
        local title = categories.keyCategories[category] or categories.keyCategories[info.category or 'none'] or
            category
        local key = lookup[action]
        local row = {
            key = action, action = action, name = KeyMapper.GetActionName(action) or action,
            category = category, categoryTitle = LOC(title), order = order[category] or 999, binding = key,
            keyText = KeyText(key),
        }
        if filter == '' or string.find(Lower(row.name), filter, 1, true) or
            string.find(Lower(row.keyText), filter, 1, true) or string.find(Lower(row.categoryTitle), filter, 1, true) or
            string.find(Lower(action), filter, 1, true) then
            table.insert(rows, row)
        end
    end
    table.sort(rows, function(a, b)
        if a.order ~= b.order then
            return a.order < b.order
        end
        return Lower(a.name) < Lower(b.name)
    end)
    -- Each category's first row says the category.
    local last = nil
    for _, row in rows do
        row.section = row.category ~= last and string.upper(row.categoryTitle) or ''
        last = row.category
        row.color = (row.binding and row.binding ~= '') and C.text or C.muted
    end
    return rows
end

function Build(launcher, parent, options)
    local view = { rows = {}, selected = nil }
    options.keysView = view

    local root = Group(parent)
    root.Left:Set(parent.Left)
    root.Right:Set(parent.Right)
    root.Top:Set(function() return options.search.Bottom() + Scale(16) end)
    root.Bottom:Set(parent.Bottom)
    Theme.SizeFromEdges(root)
    view.root = root

    -- Presets: FAF's three, and the player's own.
    local presetCaption = Theme.Text(root, 'PRESET', 10, C.muted, true)
    LayoutHelpers.AtLeftTopIn(presetCaption, root, 0, 10)
    view.presetChoices = {}
    local before = nil
    for _, preset in kPresets do
        local name, label = preset[1], preset[2]
        local choice = Theme.Choice(root, label, 170, function()
            view:AskPreset(name, label)
        end)
        choice.preset = name
        if before then
            local after = before
            choice.Left:Set(function() return after.Right() + Scale(8) end)
        else
            choice.Left:Set(function() return presetCaption.Right() + Scale(14) end)
        end
        LayoutHelpers.AtTopIn(choice, root, 0)
        table.insert(view.presetChoices, choice)
        before = choice
    end
    view.saveButton = Theme.Button(root, 'Save as my preset', function() view:AskSave() end, 'secondary',
        { icon = 'plus', width = 200 })
    -- Beside the search field (the options' Apply and Revert are gone on this tab).
    view.saveButton.Right:Set(root.Right)
    view.saveButton.Top:Set(options.search.Top)
    view.mineButton = Theme.Button(root, 'My presets', function() view:OpenMine() end, 'secondary',
        { icon = 'chevronDown', width = 170 })
    view.mineButton.Right:Set(function() return view.saveButton.Left() - Scale(10) end)
    view.mineButton.Top:Set(options.search.Top)

    -- The actions.
    local panel = Theme.Panel(root, C.panel, C.line)
    Theme.Brackets(panel, C.accent)
    panel.Left:Set(root.Left)
    panel.Right:Set(root.Right)
    panel.Top:Set(function() return view.presetChoices[1].Bottom() + Scale(14) end)
    panel.Bottom:Set(function() return root.Bottom() - Scale(56) end)
    view.list = Widgets.VirtualList(panel, {
        { 'Category', 0.2, function(item) return item.section end, C.accent },
        { 'Action', 0.52, function(item) return item.name end },
        { 'Key', 0.28, function(item) return item.keyText ~= '' and item.keyText or 'not bound' end, C.gold },
    }, function(item, double)
        view.selected = item
        view:PaintButtons()
        if double then
            view:AskKey(item)
        end
    end)
    view.list.Left:Set(function() return panel.Left() + Scale(16) end)
    view.list.Right:Set(function() return panel.Right() - Scale(12) end)
    view.list.Top:Set(function() return panel.Top() + Scale(10) end)
    view.list.Bottom:Set(function() return panel.Bottom() - Scale(10) end)
    Theme.SizeFromEdges(view.list)

    -- Under the list: what is chosen, Change key and Clear key.
    view.changeButton = Theme.Button(root, 'Change key', function() view:AskKey(view.selected) end, 'primary',
        { icon = 'keyboard', width = 180 })
    view.changeButton.Right:Set(root.Right)
    LayoutHelpers.AtBottomIn(view.changeButton, root, 6)
    view.clearButton = Theme.Button(root, 'Clear key', function() view:ClearKey(view.selected) end, 'secondary',
        { width = 140 })
    view.clearButton.Right:Set(function() return view.changeButton.Left() - Scale(10) end)
    LayoutHelpers.AtBottomIn(view.clearButton, root, 6)
    view.status = Theme.Cell(root, 13, C.muted)
    view.status.Left:Set(root.Left)
    view.status.Right:Set(function() return view.clearButton.Left() - Scale(16) end)
    LayoutHelpers.AtVerticalCenterIn(view.status, view.changeButton)

    ----------------------------------------------------------------------------------------------------------------

    function view:Say(text, color)
        self.statusText, self.statusColor = text, color or C.muted
        Theme.SetText(self.status, text or '')
        Theme.SetColor(self.status, self.statusColor)
    end

    function view:PaintButtons()
        local entry = self.selected
        self.changeButton:SetEnabled(entry ~= nil)
        self.clearButton:SetEnabled(entry ~= nil and entry.binding ~= nil and entry.binding ~= '')
        if entry then
            self:Say(entry.name .. ': ' .. (entry.keyText ~= '' and entry.keyText or 'not bound') ..
                '. Double-click or Change key to set another.')
        end
    end

    function view:Refresh()
        local filter = Lower(options.search.edit:GetText())
        self.rows = Rows(filter)
        self.list:SetItems(self.rows)
        -- The selection survives a refresh by its action.
        if self.selected then
            local wanted = self.selected.action
            self.selected = nil
            for _, row in self.rows do
                if row.action == wanted then
                    self.selected = row
                end
            end
        end
        self.list.selectedKey = self.selected and self.selected.key or false
        self.list:Paint()
        local base = BaseName()
        local own = Prefs.GetFromCurrentProfile('UserKeyMap') ~= nil
        for _, choice in self.presetChoices do
            choice.selected = choice.preset == base
            choice:Paint(false)
        end
        local count = 0
        for _ in Prefs.GetFromCurrentProfile(kOwnPresets) or {} do
            count = count + 1
        end
        self.mineButton:SetLabel(count > 0 and ('My presets (' .. count .. ')') or 'My presets')
        self.mineButton:SetEnabled(count > 0)
        self:PaintButtons()
        if not self.selected and not self.statusText then
            self:Say(table.getn(self.rows) .. ' actions' .. (own and ', with your own changes' or '') ..
                '. Pick one to change its key.')
        end
    end

    --- A yes/no question over the launcher; yes runs `onYes`.
    local function Confirm(title, text, yesText, onYes)
        local cover = Widgets.Modal(launcher.root, 520, 220)
        local panel = cover.panel
        local head = Theme.Title(panel, title, 16, C.text)
        LayoutHelpers.AtLeftTopIn(head, panel, 26, 22)
        local body = Theme.Paragraph(panel, 14, C.muted)
        body.Left:Set(function() return panel.Left() + Scale(26) end)
        body.Right:Set(function() return panel.Right() - Scale(26) end)
        body.Top:Set(function() return panel.Top() + Scale(64) end)
        body:SetText(text)
        local yes = Theme.Button(panel, yesText, function()
            cover:Destroy()
            onYes()
        end, 'primary', { width = 200 })
        LayoutHelpers.AtRightIn(yes, panel, 26)
        LayoutHelpers.AtBottomIn(yes, panel, 22)
        local no = Theme.Button(panel, 'Cancel', function() cover:Destroy() end, 'secondary', { width = 120 })
        no.Right:Set(function() return yes.Left() - Scale(12) end)
        LayoutHelpers.AtBottomIn(no, panel, 22)
        return cover
    end

    --- FAF's preset `name` in place of the bindings (the player's own changes go, unless saved as a preset first).
    function view:UsePreset(name, label)
        KeyMapper.ResetUserKeyMapTo(name)
        ApplyToInput()
        LOG('LAUNCHER: key bindings: the ' .. tostring(label or name) .. ' preset')
        self:Say('The ' .. tostring(label or name) .. ' preset is in use.', C.good)
        self:Refresh()
    end

    function view:AskPreset(name, label)
        if Prefs.GetFromCurrentProfile('UserKeyMap') == nil and BaseName() == name then
            return
        end
        Confirm('Use the ' .. label .. ' preset',
            'Every key binding becomes the ' .. label .. ' preset\'s. Changes of your own go, unless you save them as ' ..
            'a preset first.', 'Use ' .. label, function() view:UsePreset(name, label) end)
    end

    --- Saves the bindings as the player's preset `name` (replacing one of that name).
    function view:SavePreset(name)
        local presets = Prefs.GetFromCurrentProfile(kOwnPresets) or {}
        presets[name] = { base = BaseName(), map = KeyMapper.GetCurrentKeyMap(), debug = KeyMapper.GetUserDebugKeyMap() }
        Prefs.SetToCurrentProfile(kOwnPresets, presets)
        if rawget(_G, 'SavePreferences') then
            SavePreferences()
        end
        LOG('LAUNCHER: key bindings saved as ' .. name)
        self:Say('Saved as your preset "' .. name .. '".', C.good)
        self:Refresh()
    end

    function view:AskSave()
        local cover = Widgets.Modal(launcher.root, 480, 230)
        local panel = cover.panel
        local head = Theme.Title(panel, 'Save as my preset', 16, C.text)
        LayoutHelpers.AtLeftTopIn(head, panel, 26, 22)
        local field = Theme.TextField(panel, 428, 'A name for these key bindings', nil, 40)
        LayoutHelpers.AtLeftTopIn(field, panel, 26, 84)
        local function Save()
            local name = field.edit:GetText()
            if string.find(name, '%S') then
                cover:Destroy()
                view:SavePreset(name)
            end
        end
        field.edit.OnEnterPressed = function()
            Save()
            return true
        end
        field.edit:AcquireFocus()
        local save = Theme.Button(panel, 'Save', Save, 'primary', { width = 160, icon = 'check' })
        LayoutHelpers.AtRightIn(save, panel, 26)
        LayoutHelpers.AtBottomIn(save, panel, 22)
        local cancel = Theme.Button(panel, 'Cancel', function() cover:Destroy() end, 'secondary', { width = 120 })
        cancel.Right:Set(function() return save.Left() - Scale(12) end)
        LayoutHelpers.AtBottomIn(cancel, panel, 22)
    end

    --- The player's preset `name` in place of the bindings.
    function view:LoadPreset(name)
        local preset = (Prefs.GetFromCurrentProfile(kOwnPresets) or {})[name]
        if not preset then
            return
        end
        Prefs.SetToCurrentProfile('UserKeyMapName', preset.base or kPresets[1][1])
        Prefs.SetToCurrentProfile('UserKeyMap', preset.map)
        Prefs.SetToCurrentProfile('UserDebugKeyMap', preset.debug)
        ApplyToInput()
        LOG('LAUNCHER: key bindings from the preset ' .. name)
        self:Say('Your preset "' .. name .. '" is in use.', C.good)
        self:Refresh()
    end

    function view:DeletePreset(name)
        local presets = Prefs.GetFromCurrentProfile(kOwnPresets) or {}
        presets[name] = nil
        Prefs.SetToCurrentProfile(kOwnPresets, presets)
        if rawget(_G, 'SavePreferences') then
            SavePreferences()
        end
        self:Say('Your preset "' .. name .. '" is deleted.')
        self:Refresh()
    end

    function view:OpenMine()
        local items = {}
        local names = {}
        for name in Prefs.GetFromCurrentProfile(kOwnPresets) or {} do
            table.insert(names, name)
        end
        table.sort(names)
        for _, name in names do
            table.insert(items, { 'Use "' .. name .. '"', key = 'use', name = name, color = C.text })
        end
        for _, name in names do
            table.insert(items, { 'Delete "' .. name .. '"', key = 'delete', name = name, color = C.bad })
        end
        return Widgets.Dropdown(self.mineButton, items, function(item)
            if item.key == 'use' then
                Confirm('Use your preset', 'Every key binding becomes your preset "' .. item.name .. '"\'s.',
                    'Use it', function() view:LoadPreset(item.name) end)
            else
                Confirm('Delete your preset', 'Your preset "' .. item.name .. '" goes. The key bindings in use stay.',
                    'Delete', function() view:DeletePreset(item.name) end)
            end
        end, { width = 300 })
    end

    --- Binds `key` (FAF's spelling, "Ctrl-Shift-F") to the row's action; the key's other action loses it.
    function view:Assign(entry, key)
        KeyMapper.SetUserKeyMapping(key, entry.binding, entry.action)
        -- FAF's own rule: an order's Shift action follows its key ("attack" brings "shift_attack").
        local target = KeyMapper.GetShiftAction(entry.action, 'orders')
        if target and not KeyMapper.ContainsKeyModifiers(key) then
            KeyMapper.SetUserKeyMapping('Shift-' .. key, target.key, target.name)
        end
        ApplyToInput()
        LOG('LAUNCHER: key bindings: ' .. key .. ' for ' .. entry.action)
        self:Say(entry.name .. ' is on ' .. KeyText(key) .. ' now.', C.good)
        self:Refresh()
    end

    function view:ClearKey(entry)
        if not entry or not entry.binding then
            return
        end
        KeyMapper.ClearUserKeyMapping(entry.binding)
        local target = KeyMapper.GetShiftAction(entry.action, 'orders')
        if target and target.key then
            KeyMapper.ClearUserKeyMapping(target.key)
        end
        ApplyToInput()
        self:Say(entry.name .. ' has no key now.')
        self:Refresh()
    end

    --- Waits for a key (with Ctrl, Alt and Shift as held) for the row's action, as FAF's key screen does.
    function view:AskKey(entry)
        if not entry then
            return
        end
        local cover = Widgets.Modal(launcher.root, 560, 270)
        local panel = cover.panel
        local head = Theme.Title(panel, 'Press a key', 16, C.text)
        LayoutHelpers.AtLeftTopIn(head, panel, 26, 22)
        local what = Theme.Text(panel, 'For ' .. entry.name .. '. Hold Ctrl, Alt or Shift with it for a combination.', 13,
            C.muted)
        LayoutHelpers.AtLeftTopIn(what, panel, 26, 60)
        local keyText = Theme.Text(panel, entry.keyText ~= '' and entry.keyText or '...', 28, C.gold, true)
        LayoutHelpers.AtHorizontalCenterIn(keyText, panel)
        LayoutHelpers.AtTopIn(keyText, panel, 100)
        local clash = Theme.Paragraph(panel, 13, C.warn)
        clash.Left:Set(function() return panel.Left() + Scale(26) end)
        clash.Right:Set(function() return panel.Right() - Scale(26) end)
        clash.Top:Set(function() return panel.Top() + Scale(150) end)
        local pattern = nil
        local catcher = Group(panel)
        LayoutHelpers.FillParent(catcher, panel)
        catcher:AcquireKeyboardFocus(false)
        local codes = KeyMapper.GetKeyCodeLookup()
        local names = import('/lua/keymap/keynames.lua').keyNames
        local function Close()
            catcher:AbandonKeyboardFocus()
            cover:Destroy()
        end
        local assign = Theme.Button(panel, 'Use this key', function()
            if pattern then
                Close()
                view:Assign(entry, pattern)
            end
        end, 'primary', { width = 200, icon = 'check' })
        LayoutHelpers.AtRightIn(assign, panel, 26)
        LayoutHelpers.AtBottomIn(assign, panel, 22)
        assign:SetEnabled(false)
        local cancel = Theme.Button(panel, 'Cancel', Close, 'secondary', { width = 120 })
        cancel.Right:Set(function() return assign.Left() - Scale(12) end)
        LayoutHelpers.AtBottomIn(cancel, panel, 22)
        --- A key pressed: its pattern (FAF's "Ctrl-Alt-Shift-Key" order) and who else has it.
        function view.TakeKey(code, modifiers)
            local key = codes[code]
            if not key then
                return
            end
            local text = ''
            if key ~= 'Ctrl' and modifiers.Ctrl then
                text = text .. names['11'] .. '-'
            end
            if key ~= 'Alt' and modifiers.Alt then
                text = text .. names['12'] .. '-'
            end
            if key ~= 'Shift' and modifiers.Shift then
                text = text .. names['10'] .. '-'
            end
            pattern = text .. key
            Theme.SetText(keyText, KeyText(pattern))
            assign:SetEnabled(true)
            local details = KeyMapper.GetKeyMappingDetails()[pattern]
            clash:SetText(details and details.id ~= entry.action and
                (KeyText(pattern) .. ' is in use for "' .. tostring(details.name) .. '". It moves to ' .. entry.name ..
                ', and that action keeps no key.') or '',
                C.warn)
        end
        catcher.HandleEvent = function(self, event)
            if event.Type == 'KeyDown' then
                view.TakeKey(event.RawKeyCode, event.Modifiers)
                return true
            end
            return false
        end
        view.keyDialog = { Close = Close, Use = function() assign.onClick() end }
        return cover
    end

    return view
end
