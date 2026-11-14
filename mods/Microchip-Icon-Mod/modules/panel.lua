local UI = import('/lua/ui/uiutil.lua')
local L = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Edit = import('/lua/maui/edit.lua').Edit
local Popup = import('/lua/ui/controls/popups/popup.lua').Popup
local Catalog = import('/mods/Microchip-Icon-Mod/modules/catalog.lua').Icons
local Scales = import('/mods/Microchip-Icon-Mod/modules/scales.lua')
local window
local function Box(parent, x, y, w, h, colour)
    local b = Bitmap(parent)
    b:SetSolidColor(colour)
    b.Width:Set(L.ScaleNumber(w)); b.Height:Set(L.ScaleNumber(h))
    L.AtLeftTopIn(b, parent, x, y)
    return b
end
local function Text(parent, text, size, x, y, colour)
    local t = UI.CreateText(parent, text, size, UI.bodyFont)
    L.AtLeftTopIn(t, parent, x, y)
    t:SetColor(colour or 'ffe9ece9'); t:DisableHitTest()
    return t
end
local function Input(parent, x, y, width, limit)
    local e = Edit(parent)
    e.Width:Set(L.ScaleNumber(width)); e.Height:Set(L.ScaleNumber(26))
    L.AtLeftTopIn(e, parent, x, y)
    UI.SetupEditStd(e, 'ffe9ece9', 'ff080b10', 'ff000000', 'ff8adbe6', UI.bodyFont, 16, limit)
    return e
end
local function Button(parent, label, x, y, click)
    local b = UI.CreateButtonWithDropshadow(parent, '/BUTTON/medium/', label)
    L.AtLeftTopIn(b, parent, x, y)
    b.OnClick = click
    return b
end

function Open(parent)
    if window and not IsDestroyed(window) then return window end
    local content = Group(parent or GetFrame(0))
    content.Width:Set(L.ScaleNumber(720)); content.Height:Set(L.ScaleNumber(630))
    local background = Box(content, 0, 0, 720, 630, 'ff0c1016'); background:DisableHitTest()
    local popup = Popup(parent or GetFrame(0), content)
    window = popup
    local closed = popup.OnClosed
    popup.OnClosed = function(self) window = nil; closed(self) end
    Text(content, 'Microchip Icon Mod', 24, 20, 12, 'ffb8e5e9')
    Text(content, '100% = current mod size. Apply changes live during the match.', 14, 20, 48)
    Text(content, 'Enter a whole percentage from 25 to 400.', 13, 20, 70, 'ffb0bac6')
    Text(content, 'Search', 14, 20, 105)
    local search = Input(content, 88, 101, 390, 64)
    Text(content, 'Icon', 14, 30, 140)
    Text(content, 'Name', 14, 100, 140)
    Text(content, 'Scale', 14, 554, 140)

    local saved, draft = Scales.Load(), Scales.Load()
    local filtered, first, rows, rendering = {}, 0, {}, false
    local status = Text(content, '', 13, 20, 554, 'ffb8e5e9')
    local count = Text(content, '', 12, 500, 107, 'ffb0bac6')
    local function Pending()
        local changed = 0
        for _, icon in ipairs(Catalog) do
            if tonumber(draft[icon.key]) ~= saved[icon.key] then changed = changed + 1 end
        end
        status:SetText('Pending changes: ' .. changed .. ' icons')
    end
    local list = Group(content)
    list.Width:Set(L.ScaleNumber(660)); list.Height:Set(L.ScaleNumber(384))
    L.AtLeftTopIn(list, content, 20, 162)
    local refresh
    list.GetScrollValues = function(self, axis) return 0, table.getn(filtered), first, math.min(first + 8, table.getn(filtered)) end
    list.ScrollSetTop = function(self, axis, top)
        first = math.max(0, math.min(math.max(0, table.getn(filtered) - 8), math.floor(top)))
        refresh()
    end
    list.ScrollLines = function(self, axis, amount) self:ScrollSetTop(axis, first + amount) end
    list.ScrollPages = function(self, axis, amount) self:ScrollSetTop(axis, first + amount * 8) end
    list.IsScrollable = function(self, axis) return table.getn(filtered) > 8 end
    for i = 1, 8 do
        local y = (i - 1) * 48
        local row = {}
        row.bg = Box(list, 0, y, 650, 48, math.mod(i, 2) == 0 and 'ff10151c' or 'ff151b23')
        row.bg:DisableHitTest()
        row.icon = Bitmap(list)
        row.icon.Width:Set(L.ScaleNumber(40)); row.icon.Height:Set(L.ScaleNumber(40))
        L.AtLeftTopIn(row.icon, list, 8, y + 4); row.icon:DisableHitTest()
        row.name = Text(list, '', 14, 80, y + 14)
        row.edit = Input(list, 534, y + 11, 72, 5)
        row.percent = Text(list, '%', 16, 615, y + 13)
        row.edit.OnTextChanged = function(edit, text)
            if not rendering and row.key then draft[row.key] = edit:GetText(); Pending() end
        end
        row.edit.OnEnterPressed = function() return true end
        rows[i] = row
    end
    local scrollbar = UI.CreateVertScrollbarFor(list, 0, nil, 0, 0)
    refresh = function()
        rendering = true
        for i, row in ipairs(rows) do
            local icon = filtered[first + i]
            row.key = icon and icon.key or nil
            if icon then
                row.icon:SetTexture('/mods/Microchip-Icon-Mod/custom-strategic-icons/' .. icon.key .. '_rest.dds')
                row.name:SetText(icon.name)
                row.edit:SetText(tostring(draft[icon.key]))
                row.icon:Show(); row.edit:Show(); row.percent:Show()
            else
                row.name:SetText(''); row.icon:Hide(); row.edit:Hide(); row.percent:Hide()
            end
        end
        count:SetText(table.getn(filtered) .. ' / ' .. table.getn(Catalog) .. ' icons')
        rendering = false
    end
    local function Wheel(self, event)
        if event.Type == 'WheelRotation' then
            list:ScrollLines(nil, event.WheelRotation > 0 and -3 or 3)
            return true
        end
        return false
    end
    list.HandleEvent = Wheel
    for _, row in ipairs(rows) do
        local old = row.edit.HandleEvent
        row.edit.HandleEvent = function(self, event)
            if Wheel(self, event) then return true end
            return old(self, event)
        end
    end
    local function Filter()
        local query = string.lower(search:GetText() or '')
        filtered = {}
        for _, icon in ipairs(Catalog) do
            if query == '' or string.find(string.lower(icon.name .. ' ' .. icon.key), query, 1, true) then
                table.insert(filtered, icon)
            end
        end
        first = 0; refresh()
    end
    search.OnTextChanged = Filter
    Button(content, 'Reset Defaults', 10, 580, function()
        for _, icon in ipairs(Catalog) do draft[icon.key] = 100 end
        refresh(); Pending()
    end)
    Button(content, 'Apply', 392, 580, function()
        local ok, message = Scales.Apply(draft, true)
        if ok then saved = Scales.Load(); draft = Scales.Load(); refresh() end
        status:SetText(message)
        status:SetColor(ok and 'ffb8e5e9' or 'ffffa090')
    end)
    Button(content, 'Close', 550, 580, function() popup:Close() end)
    Filter(); Pending()
    return popup
end
