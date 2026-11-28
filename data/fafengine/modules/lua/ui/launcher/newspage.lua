-- The launcher's News page: FAF's news posts (its website's posts, FafLibrary_News) as cards with their pictures, by
-- category (tournaments, game updates, casts), the chosen post read in full on the right, and FAF's links (website,
-- forum, wiki, Discord, unit database, rules, support) under the cards. The links are the FAF client's own.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kRowHeight = 112
local kTabs = { { 'all', 'All' }, { 'tournament', 'Tournaments' }, { 'updates', 'Game updates' }, { 'casts', 'Casts' } }
-- FAF's post categories (lower case) by tab; the FAF client's own list.
local kTabOfCategory = {
    ['tournament'] = 'tournament',
    ['fa update'] = 'updates', ['balance'] = 'updates', ['lobby update'] = 'updates', ['server update'] = 'updates',
    ['development update'] = 'updates', ['featured mods'] = 'updates', ['ladder'] = 'updates', ['website'] = 'updates',
    ['cast'] = 'casts', ['podcast'] = 'casts',
}
-- Categories that say where a post shows, not what it is about.
local kHiddenCategories = { newshub = true, advertisement = true, uncategorized = true }
-- FAF's sites, the Links page's list (linkspage.lua), less the two video channels.
local kLinks = {}
for _, link in import('/fafengine/modules/lua/ui/launcher/linkspage.lua').Links() do
    if link[1] ~= 'Twitch' and link[1] ~= 'YouTube' then
        table.insert(kLinks, link)
    end
end

------------------------------------------------------------------------------------------------------------------------
-- The posts' HTML as the launcher's text blocks.

local function Utf8(code)
    if code < 0x80 then
        return string.char(code)
    elseif code < 0x800 then
        return string.char(192 + math.floor(code / 64), 128 + math.mod(code, 64))
    elseif code < 0x10000 then
        return string.char(224 + math.floor(code / 4096), 128 + math.mod(math.floor(code / 64), 64), 128 + math.mod(code, 64))
    end
    return string.char(240 + math.floor(code / 262144), 128 + math.mod(math.floor(code / 4096), 64),
        128 + math.mod(math.floor(code / 64), 64), 128 + math.mod(code, 64))
end

local kEntities = { amp = '&', lt = '<', gt = '>', quot = '"', apos = "'", nbsp = ' ', hellip = '...', ndash = '-',
    mdash = '-', rsquo = "'", lsquo = "'", rdquo = '"', ldquo = '"' }

local function Decode(text)
    text = string.gsub(text or '', '&#[xX](%x+);', function(hex) return Utf8(tonumber(hex, 16)) end)
    text = string.gsub(text, '&#(%d+);', function(code)
        local value = tonumber(code)
        -- Typographic dashes and quotes as plain ones: every game font has those.
        if value == 8211 or value == 8212 then
            return '-'
        elseif value == 8216 or value == 8217 then
            return "'"
        elseif value == 8220 or value == 8221 then
            return '"'
        elseif value == 8230 then
            return '...'
        end
        return Utf8(value)
    end)
    text = string.gsub(text, '&(%a+);', function(name) return kEntities[name] or ('&' .. name .. ';') end)
    return text
end

local function Trim(text)
    local trimmed = string.gsub(string.gsub(text or '', '^%s+', ''), '%s+$', '')
    return trimmed
end

--- A post's text without its HTML: one line.
local function Plain(html)
    local text = string.gsub(html or '', '<[^>]*>', ' ')
    text = string.gsub(Decode(text), '%s+', ' ')
    return Trim(text)
end

--- A post's HTML as TextView blocks: headings, paragraphs, list items.
local function Blocks(html)
    local text = string.gsub(html or '', '\r', '')
    text = string.gsub(text, '<[hH][123][^>]*>', '\n@@H2 ')
    text = string.gsub(text, '<[hH][456][^>]*>', '\n@@H3 ')
    text = string.gsub(text, '</[hH]%d>', '\n')
    text = string.gsub(text, '<[lL][iI][^>]*>', '\n@@LI ')
    text = string.gsub(text, '</[lL][iI]>', '\n')
    text = string.gsub(text, '</?[pP][^>]*>', '\n')
    text = string.gsub(text, '<[bB][rR][^>]*>', '\n')
    text = string.gsub(text, '</?[dD][iI][vV][^>]*>', '\n')
    text = string.gsub(text, '<[^>]*>', '')
    text = Decode(text)
    local blocks = {}
    for line in string.gfind(text .. '\n', '([^\n]*)\n') do
        line = Trim(string.gsub(line, '%s+', ' '))
        if line ~= '' then
            local _, _, heading = string.find(line, '^@@H2 (.*)$')
            local _, _, small = string.find(line, '^@@H3 (.*)$')
            local _, _, item = string.find(line, '^@@LI (.*)$')
            if heading then
                table.insert(blocks, { style = 'h2', text = Trim(heading) })
            elseif small then
                table.insert(blocks, { style = 'h3', text = Trim(small) })
            elseif item then
                table.insert(blocks, { style = 'bullet', text = Trim(item) })
            else
                table.insert(blocks, { style = 'text', text = line })
                table.insert(blocks, { style = 'gap', text = '' })
            end
        end
    end
    return blocks
end

--- An HTML text (a post, a tutorial's description) as TextView blocks; its plain one-line text. For other pages.
function HtmlBlocks(html)
    return Blocks(html)
end

function HtmlPlain(html)
    return Plain(html)
end

--- One post from FAF's website as the page shows it.
local function Post(raw)
    local embedded = raw._embedded or {}
    local categories, tabs = {}, {}
    for _, group in (embedded['wp:term'] or {}) do
        for _, term in group do
            local name = term.name and Decode(term.name) or ''
            local key = string.lower(name)
            if term.taxonomy == 'category' and name ~= '' and not kHiddenCategories[key] then
                table.insert(categories, name)
                if kTabOfCategory[key] then
                    tabs[kTabOfCategory[key]] = true
                end
            end
        end
    end
    local media = embedded['wp:featuredmedia'] and embedded['wp:featuredmedia'][1]
    local sizes = media and media.media_details and media.media_details.sizes or {}
    local function Size(names)
        for _, name in names do
            if sizes[name] and sizes[name].source_url then
                return sizes[name].source_url
            end
        end
        return media and media.source_url
    end
    local author = embedded.author and embedded.author[1] and embedded.author[1].name or ''
    local external = raw.newshub_externalLinkUrl
    return {
        key = tostring(raw.id), title = Plain(raw.title and raw.title.rendered), date = raw.date or '',
        author = author, categories = categories, tabs = tabs, link = raw.link,
        external = type(external) == 'string' and external ~= '' and external or nil,
        excerpt = Plain(raw.excerpt and raw.excerpt.rendered), html = raw.content and raw.content.rendered or '',
        small = Size({ 'medium', 'medium_large', 'thumbnail' }), large = Size({ 'medium_large', 'large', 'full' }),
    }
end

------------------------------------------------------------------------------------------------------------------------

function Build(launcher, page)
    local view = { tab = 'all', posts = nil, pageNumber = 0, more = true, rows = {}, top = 0, jobs = {}, thumbJobs = {} }
    launcher.newsView = view

    local title = Theme.Title(page, 'News', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, kTabs, function(key)
        view.tab = key
        view.top = 0
        view:Paint()
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

    -- FAF's links along the bottom of the left column.
    local column = Group(page)
    column.Left:Set(page.Left)
    column.Right:Set(function() return page.Left() + math.floor(page.Width() * 0.44) end)
    column.Top:Set(function() return divider.Bottom() + Scale(18) end)
    column.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(column)
    local linksCaption = Theme.Caption(column, 'FAF links', C.accent)
    view.links = {}
    local before = nil
    for i, link in kLinks do
        local url = link[3]
        local button = Theme.Button(column, link[1], function()
            LOG('LAUNCHER: news: opening ' .. url)
            OpenURL(url)
        end, 'ghost', { icon = link[2], height = 30 })
        local after = before
        local index = i
        -- Two rows of links, as many to a row as fit.
        button.Left:Set(function()
            if not after or index == 5 then
                return column.Left()
            end
            return after.Right() + Scale(6)
        end)
        button.Bottom:Set(function()
            return index < 5 and (column.Bottom() - Scale(38)) or column.Bottom()
        end)
        table.insert(view.links, button)
        before = button
    end
    linksCaption.Left:Set(column.Left)
    linksCaption.Bottom:Set(function() return view.links[1].Top() - Scale(8) end)

    local area = Group(column)
    area.Left:Set(column.Left)
    area.Right:Set(column.Right)
    area.Top:Set(column.Top)
    area.Bottom:Set(function() return linksCaption.Top() - Scale(16) end)
    Theme.SizeFromEdges(area)
    view.area = area
    view.note = Theme.Paragraph(area, 14, C.subtle)
    view.note.Left:Set(area.Left)
    view.note.Right:Set(area.Right)
    view.note.Top:Set(function() return area.Top() + Scale(8) end)
    view.loader = Theme.Loader(area)
    LayoutHelpers.AtCenterIn(view.loader, area)
    Theme.HitArea(area, function(self, event)
        if event.Type == 'WheelRotation' then
            view:Scroll(event.WheelRotation > 0 and -1 or 1)
            return true
        end
        return false
    end).Depth:Set(function() return area.Depth() - 1 end)
    view.moreButton = Theme.Button(area, 'Load more', function() view:Load() end, 'secondary',
        { icon = 'chevronDown', width = 180, height = 32 })
    LayoutHelpers.AtHorizontalCenterIn(view.moreButton, area)

    -- The chosen post.
    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Left:Set(function() return column.Right() + Scale(24) end)
    detail.Right:Set(page.Right)
    detail.Top:Set(column.Top)
    detail.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(detail)
    local x = 24
    view.picture = Bitmap(detail)
    view.picture:DisableHitTest()
    view.picture.Left:Set(function() return detail.Left() + Scale(x) end)
    view.picture.Top:Set(function() return detail.Top() + Scale(x) end)
    -- 16:9 across the panel, at most a third of its height.
    view.picture.Height:Set(function()
        return math.min(math.floor((detail.Width() - Scale(2 * x)) * 9 / 16), math.floor(detail.Height() / 3))
    end)
    view.picture.Width:Set(function() return math.floor(view.picture.Height() * 16 / 9) end)
    view.postTitle = Theme.Text(detail, '', 20, C.text, true)
    view.postTitle.Left:Set(function() return detail.Left() + Scale(x) end)
    -- Under the picture, or at the top without one (Paint sets it when that changes).
    view.PlaceTitle = function(self, withPicture)
        if self.titleWithPicture == withPicture then
            return
        end
        self.titleWithPicture = withPicture
        if withPicture then
            self.postTitle.Top:Set(function() return self.picture.Bottom() + Scale(16) end)
        else
            self.postTitle.Top:Set(function() return detail.Top() + Scale(x) end)
        end
    end
    view:PlaceTitle(false)
    view.postMeta = Theme.Cell(detail, 12, C.subtle)
    view.postMeta.Left:Set(view.postTitle.Left)
    view.postMeta.Right:Set(function() return detail.Right() - Scale(x) end)
    view.postMeta.Top:Set(function() return view.postTitle.Bottom() + Scale(6) end)
    view.open = Theme.Button(detail, 'Open on FAF\'s website', function()
        local post = view.chosen
        if post and (post.external or post.link) then
            OpenURL(post.external or post.link)
        end
    end, 'primary', { icon = 'external', width = 260 })
    view.open.Right:Set(function() return detail.Right() - Scale(x) end)
    view.open.Bottom:Set(function() return detail.Bottom() - Scale(18) end)
    view.document = Widgets.TextView(detail)
    view.document.Left:Set(view.postTitle.Left)
    view.document.Right:Set(function() return detail.Right() - Scale(16) end)
    view.document.Top:Set(function() return view.postMeta.Bottom() + Scale(14) end)
    view.document.Bottom:Set(function() return view.open.Top() - Scale(12) end)
    view.document.Width:Set(function() return view.document.Right() - view.document.Left() end)
    view.document.Height:Set(function() return view.document.Bottom() - view.document.Top() end)

    local function Row(index)
        local row = view.rows[index]
        if row then
            return row
        end
        row = Theme.Panel(area, 'ff0d1c27', C.line)
        row.Left:Set(area.Left)
        row.Right:Set(area.Right)
        LayoutHelpers.SetHeight(row, kRowHeight - 8)
        row.Width:Set(function() return row.Right() - row.Left() end)
        row.frame = Theme.Panel(row, 'ff08121a', C.line)
        LayoutHelpers.SetDimensions(row.frame, 160, 90)
        LayoutHelpers.AtLeftIn(row.frame, row, 7)
        LayoutHelpers.AtVerticalCenterIn(row.frame, row)
        row.picture = Bitmap(row.frame)
        row.picture:DisableHitTest()
        LayoutHelpers.FillParentFixedBorder(row.picture, row.frame, 1)
        row.picture.Depth:Set(function() return row.frame.Depth() + 2 end)
        row.icon = Theme.Icon(row.frame, 'news', 28, C.subtle, 1.5)
        LayoutHelpers.AtCenterIn(row.icon, row.frame)
        row.title = Theme.Cell(row, 15, C.text, true)
        row.title.Left:Set(function() return row.frame.Right() + Scale(14) end)
        row.title.Right:Set(function() return row.Right() - Scale(12) end)
        row.title.Top:Set(function() return row.Top() + Scale(10) end)
        row.meta = Theme.Cell(row, 12, C.accent)
        row.meta.Left:Set(row.title.Left)
        row.meta.Right:Set(row.title.Right)
        row.meta.Top:Set(function() return row.title.Bottom() + Scale(4) end)
        row.excerpt = Theme.Cell(row, 12, C.muted)
        row.excerpt.Left:Set(row.title.Left)
        row.excerpt.Right:Set(row.title.Right)
        row.excerpt.Top:Set(function() return row.meta.Bottom() + Scale(8) end)
        Theme.HitArea(row, function(self, event)
            if not row.post then
                return false
            end
            if event.Type == 'MouseEnter' then
                row.over = true
                view:Paint()
            elseif event.Type == 'MouseExit' then
                row.over = false
                view:Paint()
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                Theme.ClickSound()
                view:Choose(row.post)
                return true
            elseif event.Type == 'WheelRotation' then
                view:Scroll(event.WheelRotation > 0 and -1 or 1)
                return true
            end
            return false
        end)
        view.rows[index] = row
        return row
    end

    ----------------------------------------------------------------------------------------------------------------

    --- A picture from FAF's website: the path once downloaded and readable, else nil (asked for, kept for later).
    local function Picture(url)
        if not url or not rawget(_G, 'FafLibrary_Thumbnail') then
            return nil
        end
        local path, job = FafLibrary_Thumbnail(url)
        if not path and job and job > 0 and not view.thumbJobs[job] then
            view.thumbJobs[job] = true
        elseif not path and job == 0 then
            view.mountWanted = true
        end
        return path
    end

    function view:Load()
        if not rawget(_G, 'FafLibrary_News') then
            self.failure = 'This build has no access to FAF\'s news.'
            return
        end
        if self.jobs.page or not self.more then
            return
        end
        local number = self.pageNumber + 1
        local id, why = FafLibrary_News({ page = number })
        if not id then
            self.failure = tostring(why)
            return
        end
        self.jobs.page = { id = id, done = function(data)
            view.pageNumber = number
            view.posts = view.posts or {}
            local count = 0
            for _, raw in (data or {}) do
                if type(raw) == 'table' and raw.id then
                    table.insert(view.posts, Post(raw))
                    count = count + 1
                end
            end
            view.more = count >= 12
            if not view.chosen and view.posts[1] then
                view:Choose(view.posts[1])
            end
            LOG('LAUNCHER: news: page ' .. number .. ', ' .. count .. ' posts')
        end }
    end

    function view:Choose(post)
        self.chosen = post
        self.document:SetBlocks(Blocks(post.html))
        self:Paint()
    end

    function view:Shown()
        local shown = {}
        for _, post in (self.posts or {}) do
            if self.tab == 'all' or post.tabs[self.tab] then
                table.insert(shown, post)
            end
        end
        return shown
    end

    function view:Scroll(by)
        self.top = math.max(0, self.top + by)
        self:Paint()
    end

    function view:Poll()
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if not state or state.state ~= 'working' then
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: news: reading ' .. key .. ' failed: ' .. tostring(err))
                    end
                else
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s website didn\'t answer.'
                end
            end
        end
        for job in self.thumbJobs do
            local state = FafLibrary_Job(job)
            if not state or state.state ~= 'working' then
                self.thumbJobs[job] = nil
                self.mountWanted = true
            end
        end
        if self.mountWanted and not next(self.thumbJobs) then
            self.mountWanted = false
            FafLibrary_MountThumbnails()
        end
    end

    function view:Paint()
        local counts = {}
        for _, post in (self.posts or {}) do
            counts.all = (counts.all or 0) + 1
            for tab in post.tabs do
                counts[tab] = (counts[tab] or 0) + 1
            end
        end
        self.tabs:Set(self.tab, counts)
        Theme.SetVisible(self.loader, self.posts == nil and not self.failure)
        local shown = self:Shown()
        local note = ''
        if self.failure and not self.posts then
            note = 'The news didn\'t load: ' .. self.failure
        elseif self.posts and table.getn(shown) == 0 then
            note = 'No posts of this kind among the ones loaded.'
        end
        self.note:SetText(note, self.failure and C.bad or C.subtle)

        local rows = math.max(1, math.floor((self.area.Height() - Scale(44)) / Scale(kRowHeight)))
        self.top = math.max(0, math.min(self.top, table.getn(shown) - rows))
        for i = 1, rows do
            local row = Row(i)
            local post = shown[self.top + i]
            row.post = post
            Theme.SetVisible(row, post ~= nil)
            if post then
                local slot = i - 1
                row.Top:Set(function() return self.area.Top() + slot * Scale(kRowHeight) end)
                local picture = Picture(post.small)
                if picture and row.shownPicture ~= picture then
                    row.shownPicture = picture
                    row.picture:SetTexture(picture)
                end
                Theme.SetVisible(row.picture, picture ~= nil)
                Theme.SetVisible(row.icon, picture == nil)
                Theme.SetText(row.title, post.title)
                local date = rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(post.date) or post.date
                Theme.SetText(row.meta, string.sub(date or '', 1, 10) .. (table.getn(post.categories) > 0 and
                    ('  -  ' .. table.concat(post.categories, ', ')) or ''))
                Theme.SetText(row.excerpt, post.excerpt)
                local chosen = self.chosen == post
                row:SetColors(chosen and 'ff123145' or (row.over and C.raised or 'ff0d1c27'),
                    chosen and C.accent or (row.over and C.lineStrong or C.line))
            end
        end
        for i = rows + 1, table.getn(self.rows) do
            Theme.SetVisible(self.rows[i], false)
        end
        -- Load more under the last card, when the cards end on screen and FAF has more.
        local last = math.min(rows, table.getn(shown) - self.top)
        self.moreButton.Top:Set(function() return self.area.Top() + last * Scale(kRowHeight) + Scale(4) end)
        Theme.SetVisible(self.moreButton, self.posts ~= nil and self.more and self.top + rows >= table.getn(shown))
        self.moreButton:SetEnabled(self.jobs.page == nil)

        local post = self.chosen
        local picture = post and Picture(post.large)
        if picture and self.shownPicture ~= picture then
            self.shownPicture = picture
            self.picture:SetTexture(picture)
        end
        Theme.SetVisible(self.picture, picture ~= nil)
        self:PlaceTitle(picture ~= nil)
        Theme.SetText(self.postTitle, post and post.title or '')
        local date = post and (rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(post.date) or post.date) or ''
        Theme.SetText(self.postMeta, post and (date .. (post.author ~= '' and ('  -  ' .. post.author) or '') ..
            (table.getn(post.categories) > 0 and ('  -  ' .. table.concat(post.categories, ', ')) or '')) or '')
        Theme.SetVisible(self.open, post ~= nil)
    end

    function view:Refresh()
        if not self.posts and not self.jobs.page and not self.failure then
            self:Load()
        end
        self:Poll()
        self:Paint()
    end

    return view
end
