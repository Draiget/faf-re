-- The launcher's Changelog page: FAF's patch notes (/lua/ui/lobby/changelog/generated/, the same notes FAF's own
-- changelog shows), the versions in a list and the chosen one's notes as a document: headings, bullets, paragraphs.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local UIUtil = import('/lua/ui/uiutil.lua')

-- Units by name, for the units a note mentions: FAF's strings name each unit as "<id>_name" (url0303_name =
-- "Loyalist"), in English and in the player's language. Read once, when a note first needs it.
local unitIndex = nil
local function UnitIndex()
    if unitIndex then
        return unitIndex
    end
    unitIndex = { byName = {}, names = {} }
    local strings = {}
    local ok, why = pcall(doscript, '/loc/us/strings_db.lua', strings)
    if not ok then
        WARN('LAUNCHER: changelog: unit names unread: ' .. tostring(why))
    end
    local function Add(name, id)
        -- Names of four letters and more: shorter ones are words of the notes as often as units.
        if type(name) == 'string' and string.len(name) >= 4 and not unitIndex.byName[name] then
            unitIndex.byName[name] = id
            table.insert(unitIndex.names, name)
        end
    end
    for key, value in strings do
        local _, _, id = string.find(key, '^(%a%a%a%d%d%d%d)_name$')
        if id then
            Add(value, id)
            Add(LOC('<LOC ' .. key .. '>' .. value), id)
        end
    end
    -- Longer names first: "Submarine Hunter" before "Hunter".
    table.sort(unitIndex.names, function(a, b) return string.len(a) > string.len(b) end)
    return unitIndex
end

--- The build bar's icon of unit `id`, or nil when the game has none.
local function UnitIcon(id)
    local path = UIUtil.UIFile('/icons/units/' .. string.lower(id) .. '_icon.dds')
    if path and DiskGetFileInfo(path) then
        return path
    end
    return nil
end

--- The units `text` names (whole words, the unit's own capitals), and `markedId`'s first: {id, name, icon} each,
--- at most eight, each once.
local function UnitsIn(text, markedId)
    local found = {}
    local seen = {}
    local function Add(id, name)
        id = string.lower(id)
        if seen[id] or table.getn(found) >= 8 then
            return
        end
        local icon = UnitIcon(id)
        if icon then
            seen[id] = true
            table.insert(found, { id = id, name = name, icon = icon })
        end
    end
    if markedId then
        -- The unit's own name from FAF's strings; the mark's text (up to a colon) for a unit they don't name (FAF's
        -- marks are sometimes a section's title, "Interrupt Pathfinding for Engineers").
        local name = LOC('<LOC ' .. string.lower(markedId) .. '_name>' .. markedId)
        if name == markedId then
            name = LOC('<LOC ' .. string.lower(markedId) .. '_desc>' .. markedId) -- "Engineer" for one with no name
        end
        if name == markedId then
            name = string.gsub(text, ':.*$', '')
        end
        Add(markedId, name)
    end
    local index = UnitIndex()
    local taken = {}
    for _, name in index.names do
        local from = 1
        while true do
            local at, to = string.find(text, name, from, true)
            if not at then
                break
            end
            local before = at > 1 and string.sub(text, at - 1, at - 1) or ' '
            local after = string.sub(text, to + 1, to + 1)
            local inside = false
            for i = at, to do
                if taken[i] then
                    inside = true
                end
            end
            if not inside and not string.find(before, '%w') and not string.find(after, '%w') then
                for i = at, to do
                    taken[i] = true -- "Hunter" inside "Submarine Hunter" is the longer name's
                end
                Add(index.byName[name], name)
            end
            from = to + 1
        end
    end
    return found
end

--- A unit's faction from its id's second letter (uel0101: UEF), with the colour its card's edge takes.
local kFactions = {
    e = { 'UEF', C.accent }, a = { 'Aeon', C.good }, r = { 'Cybran', C.bad }, s = { 'Seraphim', C.gold },
}

--- A stat a note states: "Range: 42 → 35", "TurretYawSpeed 120: → 130", "Weapon range decreased 330 → 300";
--- {label, old, new, oldText, newText}, or nil for a line that isn't one (a sentence with an arrow in it).
local kArrow = '\226\134\146' -- "→" in UTF-8, as FAF writes its notes
local function StatOf(text)
    local number = '(-?%d+%.?%d*)'
    local _, _, label, old, new, rest = string.find(text, '^%s*(.-)%s*:%s*' .. number .. '%s*' .. kArrow .. '%s*' ..
        number .. '%s*(.*)$')
    if not label then
        _, _, label, old, new, rest = string.find(text, '^%s*(.-)%s+' .. number .. '%s*:?%s*' .. kArrow .. '%s*' ..
            number .. '%s*(.*)$')
    end
    if not label or label == '' or string.len(label) > 40 or string.find(label, '/') or string.len(rest or '') > 24 then
        return nil
    end
    local oldValue, newValue = tonumber(old), tonumber(new)
    if not oldValue or not newValue then
        return nil
    end
    return { label = label, old = oldValue, new = newValue, oldText = old, newText = new,
        unit = rest ~= '' and (' ' .. rest) or nil }
end

--- Unit cards: a units block standing for a line that was only the unit's name becomes the card's head (icon, name,
--- kind, faction), and the stat lines under it (until the next unit or heading) become its stat rows.
local function Cards(blocks)
    local out = {}
    local head = nil -- the card the stat lines right under it belong to
    for _, block in blocks do
        local stat = block.style ~= 'gap' and block.style ~= 'units' and StatOf(block.text or '')
        if block.style == 'units' and block.head then
            local unit = block.units[1]
            local faction = kFactions[string.sub(unit.id, 2, 2)] or { '', C.accent }
            local kind = LOC('<LOC ' .. unit.id .. '_desc>')
            if kind == '' or string.find(kind, '^<LOC') then
                kind = ''
            end
            head = { style = 'unitHead', id = unit.id, name = unit.name, icon = unit.icon, color = faction[2],
                kind = faction[1] .. (kind ~= '' and ('  -  ' .. kind) or '') .. '  -  ' .. string.upper(unit.id),
                indent = block.indent or 0, stats = {} }
            table.insert(out, head)
        elseif stat then
            -- A stat line: in the card of the unit right above it, else a stat row on its own.
            if head then
                table.insert(head.stats, stat)
            else
                stat.style = 'stat'
                stat.indent = (block.style == 'bullet2' and 40) or 22
                table.insert(out, stat)
            end
        else
            if block.style ~= 'gap' then
                head = nil -- another subject: the card ends
            end
            table.insert(out, block)
        end
    end
    return out
end

--- A patch's notes as TextView blocks. FAF writes them as Markdown lines; its "{% unit X %} Name {% endunit %}"
--- marks are dropped, the name kept. Each heading, bullet or paragraph that names units is followed by their icons.
local function Blocks(patch)
    local blocks = {}
    local paragraph = nil
    local function Flush()
        if paragraph then
            table.insert(blocks, { style = 'text', text = paragraph })
            paragraph = nil
        end
    end
    if not patch.description and patch.path then
        local loaded, file = pcall(import, patch.path) -- read when shown
        patch.description = loaded and file and file.Changelog and file.Changelog.Description or
            { "These notes can't be read." }
    end
    for _, raw in patch.description or {} do
        -- "{% unit X %} Name {% endunit %} text": the unit's name as a small heading, the text after it.
        local _, _, unitId, unitName, afterUnit = string.find(raw,
            '^%s*{%%%s*unit%s*([%w_]*)%s*%%}%s*(.-)%s*{%%%s*endunit%s*%%}%s*(.*)$')
        if unitName then
            Flush()
            table.insert(blocks, { style = 'h3', text = unitName, unitId = unitId ~= '' and unitId or nil })
            raw = afterUnit
        end
        local line = string.gsub(raw, '{%%%s*unit[^%%]*%%}', '')
        line = string.gsub(line, '{%%%s*endunit%s*%%}', '')
        line = string.gsub(line, '^%s+$', '')
        local _, _, hashes, heading = string.find(line, '^(#+)%s*(.*)$')
        local _, _, spaces, bullet = string.find(line, '^(%s*)[-*]%s+(.*)$')
        local last = blocks[table.getn(blocks)]
        if hashes then
            Flush()
            table.insert(blocks, { style = string.len(hashes) == 1 and 'h1' or (string.len(hashes) == 2 and 'h2' or 'h3'),
                text = heading })
        elseif bullet then
            Flush()
            table.insert(blocks, { style = string.len(spaces) >= 2 and 'bullet2' or 'bullet', text = bullet })
        elseif not paragraph and last and (last.style == 'bullet' or last.style == 'bullet2') and
            string.find(line, '^%s%s+%S') then
            last.text = last.text .. ' ' .. string.gsub(line, '^%s+', '') -- a bullet FAF broke over lines
        elseif line == '' then
            Flush()
            table.insert(blocks, { style = 'gap', text = '' })
        elseif paragraph then
            paragraph = paragraph .. ' ' .. line -- a paragraph FAF broke over lines
        else
            paragraph = line
        end
    end
    Flush()
    -- The units each heading, bullet and paragraph names, as icons under it.
    -- A unit shows once in its section (the notes under one heading), where it is first named.
    local withUnits = {}
    local shown = {}
    for _, block in blocks do
        table.insert(withUnits, block)
        if block.style == 'h1' or block.style == 'h2' or block.style == 'h3' then
            shown = {}
        end
        if block.style ~= 'gap' and block.style ~= 'h1' and block.style ~= 'h2' then
            local ok, units = pcall(UnitsIn, block.text or '', block.unitId)
            if ok then
                local fresh = {}
                for _, unit in units do
                    if not shown[unit.id] then
                        shown[unit.id] = true
                        table.insert(fresh, unit)
                    end
                end
                units = fresh
            end
            if ok and table.getn(units) > 0 then
                -- A line that is only the unit's name ("- Selen", a heading "Mercy"): the icon with its name stands
                -- in its place instead of saying the name twice.
                local bare = string.lower(string.gsub(string.gsub(block.text or '', '[%s:]+$', ''), '^%s+', ''))
                local head = table.getn(units) == 1 and bare == string.lower(units[1].name)
                if head then
                    table.remove(withUnits)
                end
                table.insert(withUnits, { style = 'units', units = units, head = head,
                    indent = (block.style == 'bullet' and 18) or (block.style == 'bullet2' and 36) or 0 })
            elseif not ok then
                WARN('LAUNCHER: changelog: units of a note: ' .. tostring(units))
            end
        end
    end
    return Cards(withUnits)
end

function Build(launcher, page)
    local view = {}
    launcher.changelogView = view
    -- FAF's notes: one file per version listed in its overview (FAF's game from 2024); older games kept them all
    -- in changelogData.lua. Each patch here: version, name, date, description (lines).
    view.patches = {}
    local newest = 0
    local hasOverview = DiskGetFileInfo('/lua/ui/lobby/changelog/generated/overview.lua')
    local ok, overview = false, nil
    if hasOverview then
        ok, overview = pcall(import, '/lua/ui/lobby/changelog/generated/overview.lua')
    end
    if ok and overview and overview.Overview then
        for _, entry in overview.Overview.Changelogs or {} do
            local patch = { version = entry.Version, name = entry.Name, date = entry.Date, path = entry.Path }
            table.insert(view.patches, patch)
            newest = math.max(newest, tonumber(entry.Version) or 0)
        end
    elseif DiskGetFileInfo('/lua/ui/lobby/changelogdata.lua') then
        local loaded, data = pcall(import, '/lua/ui/lobby/changelogdata.lua')
        for _, patch in (loaded and data and data.gamePatches) or {} do
            table.insert(view.patches, { version = patch.version, name = tostring(patch.version) .. ' - ' ..
                tostring(patch.name), description = patch.description })
            newest = math.max(newest, tonumber(patch.version) or 0)
        end
    end
    view.newest = newest

    local title = Theme.Title(page, 'Changelog', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    local subtitle = Theme.Text(page, 'What changed in each version of FAF\'s game', 13, C.muted)
    subtitle.Left:Set(function() return title.Right() + Scale(24) end)
    subtitle.Bottom:Set(function() return title.Bottom() - Scale(2) end)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return page.Top() + Scale(40) end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    -- The versions on the left, the notes on the right.
    local listArea = Group(page)
    listArea.Left:Set(page.Left)
    listArea.Width:Set(Scale(260))
    listArea.Top:Set(function() return divider.Bottom() + Scale(16) end)
    listArea.Bottom:Set(page.Bottom)
    listArea.Height:Set(function() return listArea.Bottom() - listArea.Top() end)
    local items = {}
    for index, patch in view.patches do
        table.insert(items, { key = tostring(patch.version), patch = patch, index = index })
    end
    view.items = items
    view.list = Widgets.VirtualList(listArea, {
        { 'Version', 0.62, function(item) return item.patch.name or tostring(item.patch.version) end },
        { 'Date', 0.38, function(item) return item.patch.date or '' end, C.subtle },
    }, function(item)
        view:Show(item)
    end)
    LayoutHelpers.FillParent(view.list, listArea)
    local panel = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(panel, C.accent)
    panel.Left:Set(function() return listArea.Right() + Scale(20) end)
    panel.Right:Set(page.Right)
    panel.Top:Set(listArea.Top)
    panel.Bottom:Set(page.Bottom)
    view.document = Widgets.TextView(panel)
    view.document.Left:Set(function() return panel.Left() + Scale(24) end)
    view.document.Right:Set(function() return panel.Right() - Scale(16) end)
    view.document.Top:Set(function() return panel.Top() + Scale(20) end)
    view.document.Bottom:Set(function() return panel.Bottom() - Scale(16) end)
    view.document.Width:Set(function() return view.document.Right() - view.document.Left() end)
    view.document.Height:Set(function() return view.document.Bottom() - view.document.Top() end)

    function view:Show(item)
        self.shown = item
        self.list.selectedKey = item and item.key or false
        self.document:SetBlocks(item and Blocks(item.patch) or { { style = 'text', text = 'No notes in this build.' } })
        self.list:Paint()
    end

    function view:Refresh()
        if not self.started then
            self.started = true
            self.list:SetItems(self.items)
            self:Show(self.items[1])
            -- Read: FAF's own changelog (its lobby opens it once per new version) doesn't open by itself for it.
            if self.newest > 0 then
                import('/lua/user/prefs.lua').SetToCurrentProfile('LobbyChangelog', self.newest)
            end
        end
    end

    return view
end
