-- The launcher's Changelog page: FAF's patch notes (/lua/ui/lobby/changelog/generated/, the same notes FAF's own
-- changelog shows), the versions in a list and the chosen one's notes as a document: headings, bullets, paragraphs.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

--- A patch's notes as TextView blocks. FAF writes them as Markdown lines; its "{% unit X %} Name {% endunit %}"
--- marks are dropped, the name kept.
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
        local _, _, unitName, afterUnit = string.find(raw, '^%s*{%%%s*unit[^%%]*%%}%s*(.-)%s*{%%%s*endunit%s*%%}%s*(.*)$')
        if unitName then
            Flush()
            table.insert(blocks, { style = 'h3', text = unitName })
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
    return blocks
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
