-- Updates of this engine: once a session the launcher reads the engine's releases on GitHub (FafLibrary_Releases) and
-- compares them with the running build (GetEngineInfo().Version: "2026.11.015", "2026.11.013-nightly", or the newest
-- release in a build's history with its commit, "2026.11.015-a48d131"). A newer release of the same channel (releases
-- for a release build, nightlies too for a nightly) shows as a notice; its notes, and those of every release between,
-- open in "What's new" with the download page a click away. After an update the running release's notes show once.
-- The engine doesn't update itself: a player downloads the new build as they got this one.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kSeenKey = 'fafre_whatsnew_seen' -- the newest version whose notes the player has seen

--- A version's numbers {year, month, number} and whether it's a nightly; nil for a build without a release number.
function Parse(version)
    local _, _, year, month, number = string.find(version or '', '^(%d+)%.(%d+)%.(%d+)')
    if not year then
        return nil
    end
    return { tonumber(year), tonumber(month), tonumber(number), nightly = string.find(version, 'nightly') ~= nil,
        exact = string.find(version, '^%d+%.%d+%.%d+$') ~= nil or string.find(version, '^%d+%.%d+%.%d+%-nightly$') ~= nil }
end

--- -1, 0 or 1 as release number a is older than, the same as or newer than b.
function Compare(a, b)
    for i = 1, 3 do
        if a[i] ~= b[i] then
            return a[i] < b[i] and -1 or 1
        end
    end
    return 0
end

--- The releases newer than `running` that a player on its channel would take, newest first.
function Newer(releases, running)
    local mine = Parse(running)
    local list = {}
    if not mine then
        return list
    end
    for _, release in releases or {} do
        local version = Parse(release.tag_name)
        -- A build of a commit after a release ("2026.11.015-a48d131") is past that release already.
        local newer = version and (Compare(version, mine) > 0 or (Compare(version, mine) == 0 and mine.nightly and
            not version.nightly))
        if newer and not release.draft and (mine.nightly or not (release.prerelease or version.nightly)) then
            table.insert(list, release)
        end
    end
    table.sort(list, function(a, b) return Compare(Parse(a.tag_name), Parse(b.tag_name)) > 0 end)
    return list
end

--- A release's notes (GitHub Markdown) as the launcher's text blocks: headings, bullets, paragraphs.
function Blocks(body)
    local blocks = {}
    body = string.gsub(body or '', '\r', '')
    for line in string.gfind(body .. '\n', '([^\n]*)\n') do
        local text = string.gsub(line, '%*%*', '')
        text = string.gsub(text, '`', '')
        text = string.gsub(text, '%[([^%]]*)%]%([^%)]*%)', '%1') -- [words](address) as the words
        local _, _, hashes, heading = string.find(text, '^(#+)%s+(.*)$')
        local _, _, indent, bullet = string.find(text, '^(%s*)[%-%*]%s+(.*)$')
        if heading then
            table.insert(blocks, { style = string.len(hashes) <= 2 and 'h2' or 'h3', text = heading })
        elseif bullet then
            table.insert(blocks, { style = string.len(indent) >= 2 and 'bullet2' or 'bullet', text = bullet })
        elseif string.find(text, '%S') then
            table.insert(blocks, { style = 'text', text = text })
        end
    end
    return blocks
end

local Updates = {}
Updates.__index = Updates

function Updates:Running()
    if self.testVersion then
        return self.testVersion -- a test's stand-in for the build's own version
    end
    local ok, info = pcall(function() return GetEngineInfo() end)
    return ok and info and info.Version or ''
end

function Updates:Check()
    if not rawget(_G, 'FafLibrary_Releases') then
        return
    end
    self.job = FafLibrary_Releases()
    self.failure = nil
end

function Updates:Poll()
    if not self.job then
        return
    end
    local state = FafLibrary_Job(self.job)
    if state and state.state == 'working' then
        return
    end
    self.job = nil
    if not state or state.state ~= 'done' then
        self.failure = state and state.message or 'GitHub didn\'t answer'
        LOG('LAUNCHER: updates: the release list didn\'t load: ' .. tostring(self.failure))
        return
    end
    self.releases = state.data or {}
    local running = self:Running()
    self.newer = Newer(self.releases, running)
    LOG('LAUNCHER: updates: running ' .. running .. ', ' .. table.getn(self.releases) .. ' releases, ' ..
        table.getn(self.newer) .. ' newer' .. (self.newer[1] and (', newest ' .. self.newer[1].tag_name) or ''))
    local launcher = self.launcher
    if self.newer[1] and launcher.notify then
        local newest = self.newer[1]
        launcher.notify:Add('update', 'Update available: ' .. newest.tag_name,
            'You run ' .. running .. '. Click to see what\'s new and where to download it.',
            function() self:Open() end)
    end
    -- The running release's notes once, after an update: the version differs from the one last seen.
    local mine = Parse(running)
    local seen = Parse(Prefs.GetFromCurrentProfile(kSeenKey) or '')
    if mine and mine.exact and seen and Compare(mine, seen) > 0 then
        for _, release in self.releases do
            if release.tag_name == running then
                self:Open({ release }, 'What\'s new in ' .. running)
                break
            end
        end
    end
    if mine and mine.exact and (not seen or Compare(mine, seen) > 0) then
        Prefs.SetToCurrentProfile(kSeenKey, running)
    end
end

--- "What's new": the notes of `list` (the newer releases by default), newest first, with their download pages.
function Updates:Open(list, heading)
    list = list or self.newer or {}
    if self.dialog then
        self.dialog:Destroy()
        self.dialog = nil
    end
    local launcher = self.launcher
    local width, height = Widgets.FrameUnits()
    local cover = Widgets.Modal(launcher.root, 820, math.min(640, height - 60))
    self.dialog = cover
    local panel = cover.panel
    local running = self:Running()
    local newest = list[1]
    local title = Theme.Title(panel, heading or 'What\'s new', 18, C.text)
    LayoutHelpers.AtLeftTopIn(title, panel, 26, 22)
    local note = Theme.Text(panel, newest and heading == nil and ('You run ' .. running .. '; ' .. newest.tag_name ..
        ' is out.') or ('You run ' .. running .. '.'), 13, C.muted)
    note.Left:Set(title.Left)
    note.Top:Set(function() return title.Bottom() + Scale(8) end)
    local close = Theme.Button(panel, '', function() self:Close() end, 'ghost', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(close, panel, 16, 16)
    local download = Theme.Button(panel, 'Download page', function()
        if newest and newest.html_url then
            LOG('LAUNCHER: updates: opening ' .. newest.html_url)
            OpenURL(newest.html_url)
        end
    end, 'primary', { icon = 'download', width = 200 })
    LayoutHelpers.AtRightIn(download, panel, 26)
    LayoutHelpers.AtBottomIn(download, panel, 20)
    Theme.SetVisible(download, newest ~= nil and newest.html_url ~= nil and heading == nil)
    local later = Theme.Button(panel, heading and 'Close' or 'Later', function() self:Close() end, 'secondary',
        { width = 120 })
    later.Right:Set(function() return (download:IsHidden() and panel.Right() - Scale(26)) or (download.Left() - Scale(10)) end)
    LayoutHelpers.AtBottomIn(later, panel, 20)
    local hint = Theme.Text(panel, 'Install it the way you installed this build; your settings stay.', 12, C.subtle)
    hint.Left:Set(title.Left)
    LayoutHelpers.AtVerticalCenterIn(hint, later)
    Theme.SetVisible(hint, heading == nil)
    local document = Widgets.TextView(panel)
    document.Left:Set(title.Left)
    document.Right:Set(function() return panel.Right() - Scale(16) end)
    document.Top:Set(function() return note.Bottom() + Scale(16) end)
    document.Bottom:Set(function() return later.Top() - Scale(14) end)
    document.Width:Set(function() return document.Right() - document.Left() end)
    document.Height:Set(function() return document.Bottom() - document.Top() end)
    local blocks = {}
    for _, release in list do
        local when = rawget(_G, 'FafLibrary_LocalTime') and release.published_at and
            FafLibrary_LocalTime(release.published_at) or release.published_at or ''
        table.insert(blocks, { style = 'h1', text = release.tag_name .. '   ' .. string.sub(tostring(when), 1, 10) })
        for _, block in Blocks(release.body) do
            table.insert(blocks, block)
        end
        table.insert(blocks, { style = 'gap', text = '' })
    end
    if not list[1] then
        blocks = { { style = 'text', text = 'You run the newest release.' } }
    end
    document:SetBlocks(blocks)
    self.shownBlocks = table.getn(blocks)
    LOG('LAUNCHER: updates: what\'s new open, ' .. table.getn(list) .. ' releases, ' .. self.shownBlocks .. ' blocks')
end

function Updates:Close()
    if self.dialog then
        self.dialog:Destroy()
        self.dialog = nil
    end
end

function Create(launcher)
    local updates = setmetatable({ launcher = launcher }, Updates)
    updates:Check()
    return updates
end
