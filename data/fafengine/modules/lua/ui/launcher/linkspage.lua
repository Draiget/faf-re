-- The launcher's Links page (under News): every site FAF runs, as cards in two groups (play, watch), each with what it
-- is for and the host it opens, so a player sees where a click takes them before they click. Only FAF's own sites,
-- as the FAF Rust client's directory has them (ui/src/features/links/linkDirectory.ts at 70c88a5): a list held here,
-- not fetched, so the page works offline and opens nothing a download could have changed. The News page's row of
-- links reads the same list (Links()).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Kit = import('/fafengine/modules/lua/ui/launcher/kit.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kSections = { { 'play', 'Play and talk' }, { 'watch', 'Watch' } }

-- { id, icon, name, what it is for, address, section }
local kLinks = {
    { 'website', 'globe', 'FAForever', 'The first address to give a new player: what FAF is and how to start.',
        'https://www.faforever.com/', 'play' },
    { 'discord', 'chat', 'Discord', 'FAF\'s Discord server: talk, find games, ask for help.',
        'https://discord.gg/fQxrjwru6E', 'play' },
    { 'wiki', 'book', 'Wiki', 'Guides, the game\'s mechanics and FAF\'s own pages.', 'https://wiki.faforever.com/',
        'play' },
    { 'forum', 'news', 'Forum', 'Announcements, balance talk, bug reports and the rest.', 'https://forum.faforever.com/',
        'play' },
    { 'tournaments', 'trophy', 'Tournaments', 'FAF\'s tournament site: brackets, sign-ups and results.',
        'https://tournaments.faforever.com/', 'play' },
    { 'daily', 'calendar', 'FAF Daily', 'A short daily digest of what happened on FAF.', 'https://daily.faforever.com/',
        'play' },
    { 'rules', 'shield', 'Rules', 'FAF\'s rules of conduct, and what happens when they are broken.',
        'https://www.faforever.com/rules', 'play' },
    { 'support', 'star', 'Support FAF', 'FAF runs on donations: servers, the vault and the rest.',
        'https://www.patreon.com/faf', 'play' },
    { 'twitch', 'tv', 'Twitch', 'FAF\'s own channel: casts of tournaments and big games.', 'https://www.twitch.tv/faflive',
        'watch' },
    { 'youtube', 'play', 'YouTube', 'FAF\'s channel: casts, guides and trailers.',
        'https://www.youtube.com/c/ForgedAllianceForever', 'watch' },
}

--- The list, for the News page's row: { {name, icon, url}, ... }.
function Links()
    local list = {}
    for _, link in kLinks do
        table.insert(list, { link[3], link[2], link[5] })
    end
    return list
end

--- The host a card opens, as a reader says it: "faforever.com", "discord.gg".
function Host(url)
    local host = string.gsub(url or '', '^%a+://', '')
    host = string.gsub(host, '/.*$', '')
    return (string.gsub(host, '^www%.', ''))
end

local function Card(view, parent, link)
    local card = Theme.Panel(parent, 'ff0b1822', C.line)
    LayoutHelpers.SetHeight(card, 80)
    card.link = link
    local plate = Theme.Panel(card, 'ff08121a', C.line)
    LayoutHelpers.SetDimensions(plate, 48, 48)
    LayoutHelpers.AtLeftIn(plate, card, 16)
    LayoutHelpers.AtVerticalCenterIn(plate, card)
    card.icon = Theme.Icon(plate, link[2], 26, C.accent)
    LayoutHelpers.AtCenterIn(card.icon, plate)
    card.name = Theme.Cell(card, 16, C.text, true)
    card.name.Left:Set(function() return plate.Right() + Scale(16) end)
    card.name.Right:Set(function() return card.Right() - Scale(16) end)
    LayoutHelpers.AtTopIn(card.name, card, 10)
    card.name:SetText(link[3])
    card.hint = Theme.Cell(card, 12, C.muted)
    card.hint.Left:Set(card.name.Left)
    card.hint.Right:Set(function() return card.Right() - Scale(16) end)
    card.hint.Top:Set(function() return card.name.Bottom() + Scale(4) end)
    card.hint:SetText(link[4])
    card.host = Theme.Cell(card, 11, C.subtle)
    card.host.Left:Set(card.name.Left)
    card.host.Right:Set(function() return card.open.Left() - Scale(8) end)
    card.host.Top:Set(function() return card.hint.Bottom() + Scale(4) end)
    card.host:SetText(Host(link[5]))
    card.tag = Theme.Tag(card, 'Official', C.accent)
    -- On the address's line, right: the name and its line above keep the card's width.
    card.tag.Right:Set(function() return card.Right() - Scale(16) end)
    LayoutHelpers.AtVerticalCenterIn(card.tag, card.host)
    card.open = Theme.Icon(card, 'external', 16, C.subtle)
    card.open.Right:Set(function() return card.tag.Left() - Scale(10) end)
    LayoutHelpers.AtVerticalCenterIn(card.open, card.tag)
    Theme.HitArea(card, function(self, event)
        if event.Type == 'MouseEnter' then
            Theme.HoverSound()
            card:SetColors('ff10222f', C.accent)
            card.open:SetIcon('external', C.accent)
            return true
        elseif event.Type == 'MouseExit' then
            card:SetColors('ff0b1822', C.line)
            card.open:SetIcon('external', C.subtle)
            return true
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            Theme.ClickSound()
            view:Open(link)
            return true
        end
        return false
    end)
    return card
end

function Build(launcher, page)
    local view = { cards = {} }
    launcher.linksView = view

    local title = Theme.Title(page, 'Links', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    local intro = Theme.Text(page, 'Sites FAF runs. Each opens in your browser; the address under it says where.', 13,
        C.muted)
    intro.Left:Set(function() return title.Right() + Scale(40) end)
    LayoutHelpers.AtVerticalCenterIn(intro, title)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return title.Bottom() + Scale(18) end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    -- The sections one under the other; as few cards to a row (2 to 4) as let every section fit the page's height.
    local counts = {}
    for _, link in kLinks do
        counts[link[6]] = (counts[link[6]] or 0) + 1
    end
    local function Columns()
        local room = page.Bottom() - divider.Bottom()
        for columns = 2, 4 do
            local need = 0
            for _, section in kSections do
                local rows = math.ceil((counts[section[1]] or 0) / columns)
                need = need + Scale(20 + 18 + 12) + rows * Scale(80) + math.max(0, rows - 1) * Scale(14)
            end
            if need <= room then
                return columns
            end
        end
        return 4
    end
    local above = divider
    for _, section in kSections do
        local key = section[1]
        local heading = Kit.Heading(page, section[2])
        heading.Left:Set(page.Left)
        local headingAbove = above
        heading.Top:Set(function() return headingAbove.Bottom() + Scale(20) end)
        local area = Group(page)
        area.Left:Set(page.Left)
        area.Right:Set(page.Right)
        area.Width:Set(function() return area.Right() - area.Left() end)
        area.Top:Set(function() return heading.Bottom() + Scale(12) end)
        area:DisableHitTest()
        local cards = {}
        for _, link in kLinks do
            if link[6] == key then
                table.insert(cards, Card(view, area, link))
            end
        end
        local gap = 14
        for i, card in cards do
            local index = i - 1
            card.Left:Set(function()
                local columns = Columns()
                local width = (area.Width() - Scale(gap) * (columns - 1)) / columns
                return area.Left() + math.floor(math.mod(index, columns) * (width + Scale(gap)))
            end)
            card.Width:Set(function()
                local columns = Columns()
                return math.floor((area.Width() - Scale(gap) * (columns - 1)) / columns)
            end)
            card.Top:Set(function()
                return area.Top() + math.floor(index / Columns()) * (Scale(80) + Scale(gap))
            end)
            table.insert(view.cards, card)
        end
        local count = table.getn(cards)
        area.Height:Set(function()
            local rows = math.ceil(count / Columns())
            return rows * Scale(80) + math.max(0, rows - 1) * Scale(gap)
        end)
        above = area
    end
    view.status = Theme.Text(page, '', 12, C.subtle)
    view.status.Left:Set(page.Left)
    view.status.Bottom:Set(page.Bottom)

    function view:Open(link)
        LOG('LAUNCHER: links: opening ' .. link[5])
        OpenURL(link[5])
        Theme.SetText(self.status, 'Opened ' .. Host(link[5]) .. ' in your browser.')
    end

    function view:Refresh()
    end

    return view
end
