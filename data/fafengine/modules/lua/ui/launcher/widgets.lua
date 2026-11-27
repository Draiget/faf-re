-- The launcher's shared pieces, used by its screens and by the lobby screen: maps on this computer and their
-- pictures, a modal panel, a list that has controls only for the rows on screen, a thin scroll mark and a dropdown.

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local C = Theme.Colors
local Scale = Theme.Scale

-- Maps on this computer: the scenario of a map folder, or false.
local scenarios = {}
function LocalScenario(map)
    if not map or map == '' then
        return false
    end
    local key = string.lower(map)
    if scenarios[key] == nil then
        local path = '/maps/' .. key .. '/' .. key .. '_scenario.lua'
        local found = false
        if DiskGetFileInfo(path) then
            local ok, scenario = pcall(import('/lua/ui/maputil.lua').LoadScenario, path)
            found = ok and scenario or false
        end
        scenarios[key] = found
    end
    return scenarios[key]
end

function MapTitle(map)
    local scenario = LocalScenario(map)
    if scenario and scenario.name then
        return LOC(scenario.name)
    end
    return map or ''
end

--- A map's picture in `frame` (a panel): the map's own preview when it's on this computer, else a map icon.
function MapPicture(frame)
    local MapPreview = import('/lua/ui/controls/mappreview.lua').MapPreview
    local picture = MapPreview(frame)
    LayoutHelpers.FillParentFixedBorder(picture, frame, 1)
    picture:DisableHitTest()
    picture.Depth:Set(function() return frame.Depth() + 1 end)
    local placeholder = Theme.Icon(frame, 'maps', 28, C.subtle, 1.5)
    LayoutHelpers.AtCenterIn(placeholder, frame)
    placeholder.Depth:Set(function() return frame.Depth() + 1 end)
    -- The texture loads when the map changes; which of the two shows is set every time, as a Show on an ancestor
    -- shows both.
    frame.SetMap = function(self, map)
        if self.map ~= map then
            self.map = map
            local scenario = LocalScenario(map)
            local shown = false
            if scenario then
                shown = (scenario.preview and scenario.preview ~= '' and picture:SetTexture(scenario.preview)) or false
                if not shown and scenario.map then
                    shown = picture:SetTextureFromMap(scenario.map) or false
                end
            end
            self.shown = shown and true or false
        end
        Theme.SetVisible(picture, self.shown)
        Theme.SetVisible(placeholder, not self.shown)
    end
    return picture
end

--- Tabs along a page's heading: {key, label} each; onPick(key). :Set(chosen, counts) marks one and writes counts.
function Tabs(parent, entries, onPick)
    local tabs = Group(parent)
    tabs:DisableHitTest()
    LayoutHelpers.SetHeight(tabs, 40)
    tabs.items = {}
    for i, entry in entries do
        local key = entry[1]
        local tab = Group(tabs)
        tab.label = Theme.Text(tab, string.upper(entry[2]), 13, C.muted, true)
        tab.count = Theme.Text(tab, '', 11, C.subtle, true)
        LayoutHelpers.AtLeftIn(tab.label, tab, 0)
        LayoutHelpers.AtVerticalCenterIn(tab.label, tab)
        tab.count.Left:Set(function() return tab.label.Right() + Scale(8) end)
        LayoutHelpers.AtVerticalCenterIn(tab.count, tab)
        tab.Width:Set(function() return tab.count.Right() - tab.Left() end)
        tab.Top:Set(tabs.Top)
        tab.Bottom:Set(tabs.Bottom)
        tab.Height:Set(function() return tab.Bottom() - tab.Top() end)
        if i == 1 then
            tab.Left:Set(tabs.Left)
        else
            local before = tabs.items[i - 1]
            tab.Left:Set(function() return before.Right() + Scale(28) end)
        end
        tab.underline = Theme.Rect(tab, C.accent)
        tab.underline.Left:Set(tab.Left)
        tab.underline.Right:Set(tab.Right)
        tab.underline.Bottom:Set(tab.Bottom)
        tab.underline.Height:Set(Scale(2))
        tab.underline.Width:Set(function() return tab.underline.Right() - tab.underline.Left() end)
        tab.underline:DisableHitTest()
        tab.key = key
        Theme.HitArea(tab, function(self, event)
            if event.Type == 'MouseEnter' then
                tab.over = true
                tabs:Paint()
            elseif event.Type == 'MouseExit' then
                tab.over = false
                tabs:Paint()
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                Theme.ClickSound()
                onPick(key)
                return true
            end
            return false
        end)
        tabs.items[i] = tab
    end
    tabs.Paint = function(self)
        for _, tab in self.items do
            local chosen = tab.key == self.chosen
            Theme.SetColor(tab.label, chosen and C.accent or (tab.over and C.text or C.muted))
            Theme.SetVisible(tab.underline, chosen)
        end
    end
    tabs.Set = function(self, chosen, counts)
        self.chosen = chosen
        for _, tab in self.items do
            Theme.SetText(tab.count, counts[tab.key] and tostring(counts[tab.key]) or '')
        end
        self:Paint()
    end
    return tabs
end

--- A scrolling document: blocks of text, each {style, text} with style 'h1', 'h2', 'h3', 'bullet', 'text' or 'gap',
--- wrapped to the view's width and drawn with controls only for the lines on screen. :SetBlocks(blocks) shows a
--- document from its top; the mouse wheel scrolls it.
local kTextStyles = {
    h1 = { size = 20, color = C.text, bold = true, gapAfter = 6 },
    h2 = { size = 15, color = C.accent, bold = true, gapBefore = 8, gapAfter = 2 },
    h3 = { size = 13, color = C.text, bold = true, gapBefore = 4 },
    text = { size = 13, color = C.muted },
    bullet = { size = 13, color = C.muted, indent = 18 },
    bullet2 = { size = 13, color = C.muted, indent = 36 },
    gap = { size = 6 },
}
local kUnitIcon = 48 -- a 'units' block's icons, as large as the build bar's
local kUnitCell = 84 -- an icon and the room for its name under it
function TextView(parent)
    local view = Group(parent, 'launcher text')
    view.blocks = {}
    view.lines = {}
    view.top = 1
    view.rows = {}
    view.wrappedFor = -1
    local probes = {}
    local function Probe(style)
        if not probes[style] then
            local spec = kTextStyles[style]
            local probe = Theme.Text(view, '', spec.size, spec.color, spec.bold)
            probe.Left:Set(view.Left)
            probe.Top:Set(view.Top)
            Theme.SetVisible(probe, false)
            probes[style] = probe
        end
        return probes[style]
    end
    local WrapText = import('/lua/maui/text.lua').WrapText
    --- The blocks as lines of the view's width: {style, text, height, indent, mark}.
    function view:Wrap()
        local width = self.Right() - self.Left() - Scale(14)
        self.wrappedFor = width
        local lines = {}
        for _, block in self.blocks do
            local spec = kTextStyles[block.style] or kTextStyles.text
            if spec.gapBefore then
                table.insert(lines, { style = 'gap', text = '', height = Scale(spec.gapBefore) })
            end
            if block.style == 'gap' then
                table.insert(lines, { style = 'gap', text = '', height = Scale(spec.size) })
            elseif block.style == 'units' then
                -- Units as the build bar shows them, as many to a line as fit: {id, name, icon} each.
                local indent = Scale(block.indent or 18)
                local perLine = math.max(1, math.floor((width - indent) / Scale(kUnitCell)))
                local count = table.getn(block.units or {})
                for first = 1, count, perLine do
                    local units = {}
                    for i = first, math.min(count, first + perLine - 1) do
                        table.insert(units, block.units[i])
                    end
                    table.insert(lines, { style = 'units', text = '', units = units, indent = indent,
                        height = Scale(kUnitIcon + 26) })
                end
            else
                local indent = Scale(spec.indent or 0)
                local probe = Probe(block.style)
                local wrapped = WrapText(block.text, math.max(Scale(60), width - indent), function(piece)
                    return probe:GetStringAdvance(piece)
                end)
                for i, text in wrapped do
                    table.insert(lines, { style = block.style, text = text, height = Scale(spec.size + 6), indent = indent,
                        mark = (block.style == 'bullet' or block.style == 'bullet2') and i == 1,
                        markAt = indent - Scale(14) })
                end
                if spec.gapAfter then
                    table.insert(lines, { style = 'gap', text = '', height = Scale(spec.gapAfter) })
                end
            end
        end
        self.lines = lines
    end
    function view:SetBlocks(blocks)
        self.blocks = blocks or {}
        self.top = 1
        self.wrappedFor = -1
        self:Paint()
    end
    local function Row(index)
        local row = view.rows[index]
        if not row then
            row = {}
            for style, spec in kTextStyles do
                if style ~= 'gap' and style ~= 'units' then
                    local text = Theme.Text(view, '', spec.size, spec.color, spec.bold)
                    text.Left:Set(view.Left)
                    text.Top:Set(view.Top)
                    row[style] = text
                end
            end
            row.dot = Theme.Text(view, '-', 13, C.subtle)
            row.dot.Left:Set(view.Left)
            row.dot.Top:Set(view.Top)
            view.rows[index] = row
        end
        return row
    end
    -- A line's unit icons and names, kept apart from its texts (Paint hides every text of a row by walking it).
    view.iconRows = {}
    local function Icons(index, count)
        local pool = view.iconRows[index]
        if not pool then
            pool = {}
            view.iconRows[index] = pool
        end
        for i = table.getn(pool) + 1, count do
            local cell = {}
            cell.frame = Theme.Panel(view, 'ff08121a', C.line)
            LayoutHelpers.SetDimensions(cell.frame, kUnitIcon + 2, kUnitIcon + 2)
            cell.frame.Left:Set(view.Left)
            cell.frame.Top:Set(view.Top)
            cell.icon = Bitmap(cell.frame)
            cell.icon:DisableHitTest()
            LayoutHelpers.FillParentFixedBorder(cell.icon, cell.frame, 1)
            cell.icon.Depth:Set(function() return cell.frame.Depth() + 2 end)
            cell.name = Theme.Cell(view, 11, C.muted)
            pool[i] = cell
        end
        return pool
    end
    local function HideIcons(index, from)
        for i, cell in (view.iconRows[index] or {}) do
            if i >= from then
                Theme.SetVisible(cell.frame, false)
                Theme.SetVisible(cell.name, false)
            end
        end
    end
    function view:Paint()
        if self.wrappedFor ~= self.Right() - self.Left() - Scale(14) then
            self:Wrap()
        end
        local y = 0
        local height = self.Bottom() - self.Top()
        local used = 0
        local index = self.top
        while index <= table.getn(self.lines) do
            local line = self.lines[index]
            if y + line.height > height then
                break
            end
            used = used + 1
            local row = Row(used)
            local top = y
            for style, text in row do
                if style ~= 'dot' then
                    if style == line.style then
                        Theme.SetText(text, line.text)
                        local indent = line.indent or 0
                        text.Left:Set(function() return view.Left() + indent end)
                        text.Top:Set(function() return view.Top() + top end)
                        Theme.SetVisible(text, true)
                    else
                        Theme.SetVisible(text, false)
                    end
                end
            end
            Theme.SetVisible(row.dot, line.mark and true or false)
            if line.style == 'units' then
                local pool = Icons(used, table.getn(line.units))
                for i, unit in line.units do
                    local cell = pool[i]
                    local left = (line.indent or 0) + Scale((i - 1) * kUnitCell)
                    cell.frame.Left:Set(function() return view.Left() + left end)
                    cell.frame.Top:Set(function() return view.Top() + top + Scale(2) end)
                    if cell.shownIcon ~= unit.icon then
                        cell.shownIcon = unit.icon
                        cell.icon:SetTexture(unit.icon)
                    end
                    Theme.SetText(cell.name, unit.name)
                    -- The name under the icon, centred on it when it fits, else cut to the cell.
                    local nameWidth = cell.name:GetStringAdvance(unit.name)
                    local room = Scale(kUnitCell - 8)
                    cell.name.Left:Set(function()
                        return cell.frame.Left() + math.floor((cell.frame.Width() - math.min(nameWidth, room)) / 2)
                    end)
                    cell.name.Right:Set(function() return cell.name.Left() + room end)
                    cell.name.Top:Set(function() return cell.frame.Bottom() + Scale(3) end)
                    Theme.SetVisible(cell.frame, true)
                    Theme.SetVisible(cell.name, true)
                end
                HideIcons(used, table.getn(line.units) + 1)
            else
                HideIcons(used, 1)
            end
            if line.mark then
                local markAt = line.markAt or Scale(4)
                row.dot.Left:Set(function() return view.Left() + markAt end)
                row.dot.Top:Set(function() return view.Top() + top end)
            end
            y = y + line.height
            index = index + 1
        end
        for i = used + 1, table.getn(self.rows) do
            for _, text in self.rows[i] do
                Theme.SetVisible(text, false)
            end
            HideIcons(i, 1)
        end
        self.shownLines = used
        if self.mark then
            self.mark:Update()
        end
    end
    function view:Scrolled()
        return self.top, self.shownLines or 0, table.getn(self.lines)
    end
    view.mark = ScrollMark(view, view)
    -- Groups take no events: the wheel goes to a transparent area over the text.
    Theme.HitArea(view, function(self, event)
        if event.Type == 'WheelRotation' then
            local step = event.WheelRotation > 0 and -3 or 3
            view.top = math.max(1, math.min(view.top + step, math.max(1, table.getn(view.lines) - (view.shownLines or 1) + 1)))
            view:Paint()
            return true
        end
        return false
    end)
    return view
end

--- A country's flag as FAF ships them (/countries/<code>.dds, lower case), or nil for none (or FAF's "world").
function FlagPath(country)
    if country and country ~= '' and string.lower(country) ~= 'world' then
        local path = UIUtil.UIFile('/countries/' .. string.lower(country) .. '.dds')
        if DiskGetFileInfo(path) then
            return path
        end
    end
    return nil
end

--- What FAF's lobby told us about a player (FafOnline_Player: country, clan, ratings), or an empty table.
function PlayerFacts(login)
    if login and login ~= '' and rawget(_G, 'FafOnline_Player') then
        return FafOnline_Player(login) or {}
    end
    return {}
end

--- A player as the launcher shows one everywhere: flag, [clan] and name, the name clickable (onClick(login)) when
--- given. :Set{login=, country=, clan=, color=} (country and clan from FAF's lobby when not given); :Width() follows.
function PlayerTag(parent, size, onClick)
    local tag = Group(parent)
    tag:DisableHitTest()
    tag.flag = Bitmap(tag)
    tag.flag:DisableHitTest()
    LayoutHelpers.SetDimensions(tag.flag, 20, 14)
    LayoutHelpers.AtLeftIn(tag.flag, tag, 0)
    LayoutHelpers.AtVerticalCenterIn(tag.flag, tag)
    tag.clan = Theme.Text(tag, '', size or 13, C.accent)
    LayoutHelpers.AtVerticalCenterIn(tag.clan, tag)
    tag.name = Theme.Text(tag, '', size or 13, C.text)
    LayoutHelpers.AtVerticalCenterIn(tag.name, tag)
    LayoutHelpers.SetHeight(tag, (size or 13) + 8)
    tag.Width:Set(function() return tag.name.Right() - tag.Left() end)
    tag.Set = function(self, player)
        player = player or {}
        local facts = (player.country == nil or player.clan == nil) and PlayerFacts(player.login) or {}
        local flag = FlagPath(player.country or facts.country)
        local clan = player.clan or facts.clan or ''
        self.login = player.login
        self.color = player.color or C.text
        if flag then
            self.flag:SetTexture(flag)
            LayoutHelpers.SetDimensions(self.flag, 20, 14)
        end
        Theme.SetVisible(self.flag, flag ~= nil)
        Theme.SetText(self.clan, clan ~= '' and ('[' .. clan .. ']') or '')
        self.clan.Left:Set(function() return self.Left() + (flag and Scale(26) or 0) end)
        self.name.Left:Set(function() return self.clan.Right() + (clan ~= '' and Scale(5) or 0) end)
        Theme.SetText(self.name, player.login or '')
        Theme.SetColor(self.name, self.color)
    end
    if onClick then
        local area = Theme.HitArea(tag, function(self, event)
            if not tag.login or tag.login == '' then
                return false
            end
            if event.Type == 'MouseEnter' then
                Theme.SetColor(tag.name, C.accent)
            elseif event.Type == 'MouseExit' then
                Theme.SetColor(tag.name, tag.color)
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                Theme.ClickSound()
                onClick(tag.login)
                return true
            end
            return false
        end)
        area.Width:Set(tag.Width)
    end
    return tag
end

--- A dimmed cover over the whole screen that takes every click, with a bracketed panel in its middle.
function Modal(root, width, height)
    local cover = Theme.Rect(root, 'e0020508')
    LayoutHelpers.FillParent(cover, root)
    Theme.SizeFromEdges(cover)
    cover.Depth:Set(function() return root.Depth() + 500 end)
    cover.HandleEvent = function(self, event)
        return true
    end
    local panel = Theme.Panel(cover, 'ff0b161e', C.lineStrong)
    LayoutHelpers.SetDimensions(panel, width, height)
    LayoutHelpers.AtCenterIn(panel, root)
    panel.Depth:Set(function() return cover.Depth() + 1 end)
    Theme.Brackets(panel, C.accent, true)
    cover.panel = panel
    return cover
end

function Message(root, title, text)
    local cover = Modal(root, 520, 190)
    local panel = cover.panel
    local head = Theme.Title(panel, title, 16, C.text)
    LayoutHelpers.AtLeftTopIn(head, panel, 24, 20)
    local body = Theme.Cell(panel, 13, C.muted)
    LayoutHelpers.AtLeftTopIn(body, panel, 24, 60)
    LayoutHelpers.AtRightIn(body, panel, 24)
    body:SetText(text)
    local ok = Theme.Button(panel, 'OK', function() cover:Destroy() end, 'primary', { width = 120 })
    LayoutHelpers.AtRightIn(ok, panel, 24)
    LayoutHelpers.AtBottomIn(ok, panel, 20)
    return cover
end

--- The size of the screen in layout units (pixels over the UI scale).
function FrameUnits()
    local frame = GetFrame(0)
    return LayoutHelpers.InvScaleNumber(frame.Width()), LayoutHelpers.InvScaleNumber(frame.Height())
end

--- A thin scrollbar along `area`'s right edge for a list with `Scrolled()` -> first, shown, total.
function ScrollMark(area, list)
    local track = Theme.Rect(area, C.line)
    track.Right:Set(area.Right)
    track.Top:Set(area.Top)
    track.Bottom:Set(area.Bottom)
    track.Width:Set(Scale(3))
    track:DisableHitTest()
    local thumb = Theme.Rect(area, C.accent)
    thumb.Right:Set(area.Right)
    thumb.Width:Set(Scale(3))
    thumb:DisableHitTest()
    thumb.Depth:Set(function() return track.Depth() + 1 end)
    local mark = {}
    mark.Update = function(self)
        local first, shown, total = list:Scrolled()
        local visible = total > shown
        Theme.SetVisible(track, visible)
        Theme.SetVisible(thumb, visible)
        if visible then
            local height = track.Height()
            local size = math.max(Scale(16), math.floor(height * shown / total))
            local top = math.floor((height - size) * (first - 1) / math.max(1, total - shown))
            thumb.Top:Set(function() return track.Top() + top end)
            thumb.Height:Set(size)
        end
    end
    return mark
end

--- A list that has controls only for the rows on screen. columns: { {title, share, text(item), color}, ... };
--- onPick(item, double).
function VirtualList(parent, columns, onPick)
    local list = Group(parent, 'launcher list')
    list.items = {}
    list.top = 1
    list.rows = {}
    list.selectedKey = false
    list.hoverRow = false
    local rowHeight = 28

    local header = Group(list)
    LayoutHelpers.AtLeftTopIn(header, list, 0, 0)
    header.Right:Set(list.Right)
    LayoutHelpers.SetHeight(header, 22)
    local body = Group(list)
    body.Left:Set(list.Left)
    body.Right:Set(function() return list.Right() - Scale(10) end)
    body.Top:Set(function() return header.Bottom() + Scale(4) end)
    body.Bottom:Set(list.Bottom)
    list.body = body

    local function Edge(index, of, last)
        local share = 0
        for i = 1, (last and index or index - 1) do
            share = share + columns[i][2]
        end
        if last then
            return function() return of.Left() + math.floor(share * of.Width()) - Scale(6) end
        end
        return function() return of.Left() + math.floor(share * of.Width()) + Scale(10) end
    end
    for index, column in columns do
        local title = Theme.Cell(header, 10, C.subtle, true)
        title.Left:Set(Edge(index, body, false))
        title.Right:Set(Edge(index, body, true))
        LayoutHelpers.AtVerticalCenterIn(title, header)
        title:SetText(string.upper(column[1]))
    end
    local line = Theme.Rect(list, C.line)
    line.Left:Set(list.Left)
    line.Right:Set(list.Right)
    line.Top:Set(header.Bottom)
    line.Height:Set(1)

    local function VisibleCount()
        return math.max(1, math.floor(body.Height() / Scale(rowHeight)))
    end

    local function MakeRow(index)
        local row = Theme.Rect(body, C.clear)
        row.Left:Set(body.Left)
        row.Right:Set(body.Right)
        row.Top:Set(function() return body.Top() + (index - 1) * Scale(rowHeight) end)
        LayoutHelpers.SetHeight(row, rowHeight)
        row.Width:Set(function() return row.Right() - row.Left() end)
        row.cells = {}
        for c, column in columns do
            local cell = Theme.Cell(row, 13, column[4] or C.text)
            cell.Left:Set(Edge(c, body, false))
            cell.Right:Set(Edge(c, body, true))
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
            elseif (event.Type == 'ButtonPress' or event.Type == 'ButtonDClick') and event.Modifiers.Left then
                list.selectedKey = self.item.key
                list:Paint()
                onPick(self.item, event.Type == 'ButtonDClick', self)
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
        self.top = math.min(self.top, math.max(1, table.getn(items) - VisibleCount() + 1))
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

    function list:Scrolled()
        return self.top, VisibleCount(), table.getn(self.items)
    end

    function list:Paint()
        self:EnsureRows()
        for i, row in self.rows do
            local item = self.items[self.top + i - 1]
            row.item = item
            if item then
                local selected = item.key == self.selectedKey
                for c, column in columns do
                    Theme.SetText(row.cells[c], column[3](item) or '')
                    Theme.SetColor(row.cells[c], selected and C.accent or (item.color or column[4] or C.text))
                end
                row:SetSolidColor(selected and C.selected or (self.hoverRow == row and C.raised or C.clear))
            else
                for c = 1, table.getn(columns) do
                    Theme.SetText(row.cells[c], '')
                end
                row:SetSolidColor(C.clear)
            end
        end
        if self.mark then
            self.mark:Update()
        end
    end

    function list:ScrollLines(axis, delta)
        self:ScrollSetTop(axis, self.top + math.floor(delta))
    end

    function list:ScrollSetTop(axis, top)
        local maxTop = math.max(1, table.getn(self.items) - VisibleCount() + 1)
        top = math.max(1, math.min(math.floor(top), maxTop))
        if top ~= self.top then
            self.top = top
            self:Paint()
        end
    end

    list.mark = ScrollMark(body, list)
    return list
end


local openDropdowns = 0

--- How many dropdown lists are open now (the launcher's test walk checks none outlives its screen).
function OpenDropdowns()
    return openDropdowns
end

--- A list that opens under `anchor` and closes on a pick or a click anywhere else. items: { {text, key, color,
--- icon (texture path), swatch (colour)}, ... }; onPick(item). opts.width (units), opts.maxRows.
function Dropdown(anchor, items, onPick, opts)
    opts = opts or {}
    local frame = GetFrame(0)
    local catcher = Theme.Rect(frame, C.clear)
    LayoutHelpers.FillParent(catcher, frame)
    Theme.SizeFromEdges(catcher)
    catcher.Depth:Set(frame:GetTopmostDepth() + 1) -- once: a live topmost depth would count the catcher itself
    local rowHeight = 28
    local count = table.getn(items)
    local shown = math.min(count, opts.maxRows or 14)
    local panel = Theme.Panel(catcher, 'ff0b161e', C.lineStrong)
    panel.Depth:Set(function() return catcher.Depth() + 1 end)
    LayoutHelpers.SetDimensions(panel, opts.width or math.max(120, LayoutHelpers.InvScaleNumber(anchor.Width())), shown * rowHeight + 8)
    -- Under the anchor's left edge; moved left when it would run past the screen's right (a status bar's corner).
    panel.Left:Set(function() return math.max(frame.Left(), math.min(anchor.Left(), frame.Right() - panel.Width())) end)
    panel.Top:Set(function()
        local below = anchor.Bottom() + Scale(2)
        if below + panel.Height() > frame.Bottom() then
            return anchor.Top() - Scale(2) - panel.Height()
        end
        return below
    end)
    local top = 1
    local rows = {}
    local closed = false
    openDropdowns = openDropdowns + 1
    local function Close()
        if not closed then
            closed = true
            openDropdowns = openDropdowns - 1
            catcher:Destroy()
        end
    end
    local function Paint()
        for i, row in rows do
            local item = items[top + i - 1]
            row.item = item
            Theme.SetText(row.label, item and item[1] or '')
            Theme.SetColor(row.label, item and (item.color or item[3]) or C.text)
            if row.icon then
                Theme.SetVisible(row.icon, item ~= nil and item.icon ~= nil)
                if item and item.icon then
                    row.icon:SetTexture(item.icon)
                    LayoutHelpers.SetDimensions(row.icon, 20, 20)
                end
            end
            Theme.SetVisible(row.swatch, item ~= nil and item.swatch ~= nil)
            if item and item.swatch then
                row.swatch:SetSolidColor(item.swatch)
            end
        end
    end
    for loopRow = 1, shown do
        -- Lua 5.0 keeps one loop variable for every pass: a closure needs its own copy.
        local i = loopRow
        local row = Theme.Rect(panel, C.clear)
        row.Left:Set(function() return panel.Left() + 1 end)
        row.Right:Set(function() return panel.Right() - 1 end)
        row.Top:Set(function() return panel.Top() + Scale(4) + (i - 1) * Scale(rowHeight) end)
        row.Height:Set(Scale(rowHeight))
        row.Width:Set(function() return row.Right() - row.Left() end)
        row.Depth:Set(function() return panel.Depth() + 2 end)
        row.icon = Bitmap(row)
        row.icon:DisableHitTest()
        LayoutHelpers.AtLeftIn(row.icon, row, 8)
        LayoutHelpers.AtVerticalCenterIn(row.icon, row)
        row.icon.Depth:Set(function() return row.Depth() + 1 end)
        row.swatch = Theme.Rect(row, C.clear)
        row.swatch:DisableHitTest()
        LayoutHelpers.AtLeftIn(row.swatch, row, 10)
        LayoutHelpers.AtVerticalCenterIn(row.swatch, row)
        LayoutHelpers.SetDimensions(row.swatch, 16, 16)
        row.swatch.Depth:Set(function() return row.Depth() + 1 end)
        row.label = Theme.Cell(row, 13, C.text)
        row.label.Left:Set(function() return row.Left() + Scale(34) end)
        row.label.Right:Set(function() return row.Right() - Scale(8) end)
        LayoutHelpers.AtVerticalCenterIn(row.label, row)
        row.label.Depth:Set(function() return row.Depth() + 1 end)
        row.HandleEvent = function(self, event)
            if event.Type == 'WheelRotation' then
                top = math.max(1, math.min(top + (event.WheelRotation > 0 and -1 or 1), math.max(1, count - shown + 1)))
                Paint()
                return true
            elseif event.Type == 'MouseEnter' then
                self:SetSolidColor(C.raised)
            elseif event.Type == 'MouseExit' then
                self:SetSolidColor(C.clear)
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                local item = self.item
                Close()
                Theme.ClickSound()
                if item then
                    onPick(item)
                end
                return true
            end
            return false
        end
        rows[i] = row
    end
    catcher.HandleEvent = function(self, event)
        if event.Type == 'ButtonPress' or event.Type == 'ButtonDClick' then
            Close()
            return true
        end
        return event.Type == 'WheelRotation'
    end
    -- The list sits on the root frame, not in its screen, so it goes with the screen by hand: it closes once the
    -- control it opened from is destroyed or hidden (the lobby left, another page shown).
    local isDestroyed = rawget(_G, 'IsDestroyed')
    local function AnchorGone()
        if isDestroyed and isDestroyed(anchor) then
            return true
        end
        local control = anchor
        while control do
            if control:IsHidden() then
                return true
            end
            control = control:GetParent()
        end
        return false
    end
    catcher:SetNeedsFrameUpdate(true)
    catcher.OnFrame = function(self, delta)
        if AnchorGone() then
            LOG('LAUNCHER: a dropdown closed with its screen')
            Close()
        end
    end
    Paint()
    catcher.Close = Close -- tests close it with this
    return catcher
end
