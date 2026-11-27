-- The launcher's Chat page: FAF's chat (the engine's FafChat_* functions: IRC over a WebSocket to the FAF server's
-- chat, signed in with the player's FAF sign-in). Channels on the left, the chosen channel's lines in the middle, who
-- is in it on the right, and a line to write in. The chat starts when the player asks for it the first time (it joins
-- #aeolus under their FAF name); after that, each time the page shows.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kKeep = 400 -- lines kept per channel on the page
local kAutoStart = 'fafre_chat_auto'

local function Available()
    return rawget(_G, 'FafChat_Status') ~= nil
end

--- "14:05" in this computer's time from the server's time, or ''.
local function Clock(iso)
    if not iso or iso == '' or not rawget(_G, 'FafLibrary_LocalTime') then
        return ''
    end
    local text = FafLibrary_LocalTime(iso) or ''
    local _, _, clock = string.find(text, '(%d+:%d+)$')
    return clock or ''
end

--- A nick without its channel prefix (@ for operators, + for voice).
local function Bare(nick)
    return (string.gsub(nick or '', '^[@%+%%~&]+', ''))
end

function Build(launcher, page)
    local view = { channel = nil, lines = {}, seen = {}, unread = {}, atBottom = true }
    launcher.chatView = view

    local title = Theme.Title(page, 'Chat', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.subtitle = Theme.Text(page, '', 13, C.subtle)
    view.subtitle.Left:Set(function() return title.Right() + Scale(24) end)
    view.subtitle.Bottom:Set(function() return title.Bottom() - Scale(3) end)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return title.Bottom() + Scale(14) end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    local body = Group(page)
    body.Left:Set(page.Left)
    body.Right:Set(page.Right)
    body.Top:Set(function() return divider.Bottom() + Scale(16) end)
    body.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(body)
    view.body = body

    -- Channels: the joined ones, with how many new lines each has; a field joins another.
    local channels = Group(body)
    channels.Left:Set(body.Left)
    channels.Top:Set(body.Top)
    channels.Bottom:Set(body.Bottom)
    LayoutHelpers.SetWidth(channels, 210)
    channels.Right:Set(function() return channels.Left() + channels.Width() end)
    channels.Height:Set(function() return channels.Bottom() - channels.Top() end)
    view.channelList = Widgets.VirtualList(channels, {
        { 'Channels', 1.0, function(item)
            local private = string.sub(item.key, 1, 1) ~= '#' and string.sub(item.key, 1, 1) ~= '&'
            return item.key .. (private and '  - private' or '') ..
                ((view.unread[item.key] or 0) > 0 and ('  (' .. view.unread[item.key] .. ')') or '')
        end },
    }, function(item)
        view:Choose(item.key)
    end)
    view.channelList.Left:Set(channels.Left)
    view.channelList.Right:Set(channels.Right)
    view.channelList.Top:Set(channels.Top)
    view.channelList.Bottom:Set(function() return channels.Bottom() - Scale(48) end)
    Theme.SizeFromEdges(view.channelList)
    view.joinField = Theme.TextField(channels, 210, 'Join a channel', 'plus', 40)
    view.joinField.Left:Set(channels.Left)
    view.joinField.Top:Set(function() return channels.Bottom() - Scale(34) end)
    view.joinField.edit.OnEnterPressed = function(self, text)
        if text and text ~= '' then
            local ok, why = FafChat_Join(text)
            view.notice = ok and ('Joining ' .. text .. '...') or tostring(why)
            view.joinField.edit:SetText('')
        end
        return true
    end

    -- Who is in the chosen channel; a name opens the player's profile.
    local users = Group(body)
    users.Right:Set(body.Right)
    users.Top:Set(body.Top)
    users.Bottom:Set(body.Bottom)
    LayoutHelpers.SetWidth(users, 200)
    users.Left:Set(function() return users.Right() - users.Width() end)
    users.Height:Set(function() return users.Bottom() - users.Top() end)
    view.userList = Widgets.VirtualList(users, {
        { 'In the channel', 1.0, function(item) return item.key end },
    }, function(item, double)
        if item and launcher.ShowProfile then
            launcher:ShowProfile(Bare(item.key))
        end
    end)
    LayoutHelpers.FillParent(view.userList, users)
    Theme.SizeFromEdges(view.userList)

    -- The lines, the topic over them, and the line to write in.
    local middle = Theme.Panel(body, C.panel, C.line)
    middle.Left:Set(function() return channels.Right() + Scale(20) end)
    middle.Right:Set(function() return users.Left() - Scale(20) end)
    middle.Top:Set(body.Top)
    middle.Bottom:Set(function() return body.Bottom() - Scale(48) end)
    view.middle = middle
    view.topic = Theme.Cell(middle, 12, C.subtle)
    view.topic.Left:Set(function() return middle.Left() + Scale(18) end)
    view.topic.Right:Set(function() return middle.Right() - Scale(18) end)
    view.topic.Top:Set(function() return middle.Top() + Scale(10) end)
    view.document = Widgets.TextView(middle)
    view.document.Left:Set(function() return middle.Left() + Scale(18) end)
    view.document.Right:Set(function() return middle.Right() - Scale(12) end)
    view.document.Top:Set(function() return middle.Top() + Scale(32) end)
    view.document.Bottom:Set(function() return middle.Bottom() - Scale(10) end)
    Theme.SizeFromEdges(view.document)
    view.input = Theme.TextField(body, 400, 'Write to the channel', 'chat', 400)
    view.input.Left:Set(middle.Left)
    view.input.Right:Set(function() return middle.Right() - Scale(130) end)
    view.input.Width:Set(function() return view.input.Right() - view.input.Left() end)
    view.input.Top:Set(function() return body.Bottom() - Scale(34) end)
    view.input.edit.OnEnterPressed = function(self, text)
        view:Send(text)
        return true
    end
    view.sendButton = Theme.Button(body, 'Send', function() view:Send(view.input.edit:GetText()) end, 'primary',
        { width = 120, icon = 'arrowRight' })
    view.sendButton.Right:Set(middle.Right)
    view.sendButton.Top:Set(view.input.Top)

    -- Before the chat starts (and when it fails): what it does, and the button that starts it.
    local intro = Theme.Panel(body, C.panel, C.line)
    LayoutHelpers.SetDimensions(intro, 560, 220)
    LayoutHelpers.AtCenterIn(intro, body)
    Theme.Brackets(intro, C.accent, true)
    view.intro = intro
    local introHead = Theme.Title(intro, 'FAF chat', 18)
    LayoutHelpers.AtHorizontalCenterIn(introHead, intro)
    LayoutHelpers.AtTopIn(introHead, intro, 26)
    view.introText = Theme.Paragraph(intro, 13, C.muted)
    view.introText.centered = true
    view.introText.Left:Set(function() return intro.Left() + Scale(30) end)
    view.introText.Right:Set(function() return intro.Right() - Scale(30) end)
    view.introText.Top:Set(function() return intro.Top() + Scale(70) end)
    view.startButton = Theme.Button(intro, 'Join the chat', function() view:Start() end, 'primary',
        { width = 220, icon = 'chat' })
    LayoutHelpers.AtHorizontalCenterIn(view.startButton, intro)
    LayoutHelpers.AtBottomIn(view.startButton, intro, 26)

    ----------------------------------------------------------------------------------------------------------------

    function view:Start()
        local ok, why = FafChat_Start()
        if ok then
            Prefs.SetToCurrentProfile(kAutoStart, true)
            self.notice = nil
        else
            self.notice = 'The chat didn\'t start: ' .. tostring(why) .. '.'
        end
        self:Refresh()
    end

    function view:Send(text)
        if not self.channel or not text or text == '' then
            return
        end
        local ok, why = FafChat_Say(self.channel, text)
        if ok then
            self.input.edit:SetText('')
            self.atBottom = true
        else
            self.notice = tostring(why)
        end
        self:Refresh()
    end

    --- A private conversation with `nick`, opened and shown (FafChat_Private; Leave closes it).
    function view:OpenPrivate(nick)
        if rawget(_G, 'FafChat_Private') and nick and nick ~= '' then
            FafChat_Private(nick)
            self:Choose(nick)
        end
    end

    function view:Choose(channel)
        self.channel = channel
        self.unread[channel] = 0
        self.atBottom = true
        self.shownFor = nil
        self:Refresh()
    end

    --- New lines of every joined channel since the last look; unread counts for the ones not shown.
    function view:Take(channels)
        for _, channel in channels do
            local from = self.seen[channel] or 0
            local got = FafChat_Lines(channel, from)
            local lines = self.lines[channel] or {}
            for _, line in got.lines or {} do
                table.insert(lines, line)
                if channel ~= self.channel and not line.history and not line.self then
                    self.unread[channel] = (self.unread[channel] or 0) + 1
                end
            end
            while table.getn(lines) > kKeep do
                table.remove(lines, 1)
            end
            self.lines[channel] = lines
            if got.total ~= from then
                self.changed = self.changed or channel == self.channel
            end
            self.seen[channel] = got.total or from
        end
    end

    --- The chosen channel's lines as the text view's blocks: "14:05  Name: text", one's own in the accent colour.
    function view:Blocks()
        local blocks = {}
        local lastHistory = nil
        for _, line in self.lines[self.channel] or {} do
            if lastHistory and not line.history then
                table.insert(blocks, { style = 'chatEvent', text = '- earlier lines above -' })
            end
            lastHistory = line.history
            local clock = Clock(line.time)
            local head = (clock ~= '' and (clock .. '  ') or '')
            if line.event then
                table.insert(blocks, { style = 'chatEvent', text = head .. line.from .. ' ' .. line.text })
            elseif line.action then
                table.insert(blocks, { style = line.self and 'chatSelf' or 'chat', text = head .. '* ' .. line.from ..
                    ' ' .. line.text })
            else
                table.insert(blocks, { style = line.self and 'chatSelf' or 'chat', text = head .. line.from .. ':  ' ..
                    line.text })
            end
        end
        if table.getn(blocks) == 0 then
            table.insert(blocks, { style = 'chatEvent', text = 'No lines yet.' })
        end
        return blocks
    end

    function view:Refresh()
        if not Available() then
            Theme.SetText(self.subtitle, 'This build has no chat.')
            return
        end
        local status = FafChat_Status()
        local online = launcher.lastStatus or {}
        local server = online.server == 'test' and 'FAF test server\'s chat' or 'FAF\'s chat'
        local joined = status.state == 'joined'
        if not joined and status.state ~= 'connecting' and Prefs.GetFromCurrentProfile(kAutoStart) and
            online.signIn == 'signedin' and not self.autoTried then
            self.autoTried = true -- once a showing; a failure waits for the button
            FafChat_Start()
            status = FafChat_Status()
        end
        Theme.SetText(self.subtitle, joined and (server .. ' as ' .. status.nick) or server)
        for _, control in { self.channelList, self.joinField, self.userList, self.middle, self.input, self.sendButton } do
            Theme.SetVisible(control, joined)
        end
        Theme.SetVisible(self.intro, not joined)
        if not joined then
            local text
            if online.signIn ~= 'signedin' then
                text = 'Sign in to FAF on the Multiplayer page first; the chat signs in with the same account.'
            elseif status.state == 'connecting' then
                text = 'Signing in to ' .. server .. '...'
            elseif status.state == 'failed' then
                text = 'The chat failed: ' .. tostring(status.message) .. '. Join the chat tries again.'
            else
                text = 'Talk with other players in ' .. server .. '. Joining signs you in under your FAF name and ' ..
                    'joins #aeolus, FAF\'s main channel; other channels are one name away.'
            end
            if self.notice then
                text = text .. '  ' .. self.notice
            end
            if self.introShown ~= text then
                self.introShown = text
                self.introText:SetText(text, status.state == 'failed' and C.bad or C.muted)
            end
            self.startButton:SetEnabled(online.signIn == 'signedin' and status.state ~= 'connecting')
            return
        end
        local channels = status.channels or {}
        -- The chosen channel, or the first one when it was left (or none was chosen yet).
        local still = false
        for _, channel in channels do
            still = still or channel == self.channel
        end
        if not still then
            self.channel = channels[1]
            self.shownFor = nil
        end
        self:Take(channels)
        local items = {}
        for _, channel in channels do
            table.insert(items, { key = channel })
        end
        self.channelList.selectedKey = self.channel or false
        self.channelList:SetItems(items)
        local info = self.channel and FafChat_Channel(self.channel) or { users = {} }
        Theme.SetText(self.topic, info.topic ~= '' and info.topic or (self.channel or ''))
        local people = {}
        table.sort(info.users, function(a, b) return string.lower(Bare(a)) < string.lower(Bare(b)) end)
        for _, user in info.users do
            table.insert(people, { key = user })
        end
        self.userList:SetItems(people)
        if self.changed or self.shownFor ~= self.channel then
            self.changed = false
            self.shownFor = self.channel
            -- Following the newest lines unless the player scrolled up to read.
            local document = self.document
            local wasAtBottom = self.atBottom or (document.top or 1) >= table.getn(document.lines) - (document.shownLines or 0)
            document:SetBlocks(self:Blocks())
            if wasAtBottom then
                document.top = math.max(1, table.getn(document.lines) - (document.shownLines or 1) + 1)
                document:Paint()
                document.top = math.max(1, table.getn(document.lines) - (document.shownLines or 1) + 1)
                document:Paint()
            end
            self.atBottom = false
        end
    end

    return view
end
