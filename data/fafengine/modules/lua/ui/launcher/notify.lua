-- The launcher's notifications: what happened while the player looked elsewhere, as a toast in the bottom right
-- corner for a few seconds and in the bell's list in the top bar (its count the ones not seen yet). From: friends
-- coming online and going offline (FAF's lobby), private messages and lines that name the player in FAF's chat, and
-- a match found in the matchmaker. A toast or a list entry does what it is about: the conversation, the channel, the
-- matchmaking page, the friend in Contacts. Each source starts from what is there when the launcher comes up, so
-- nothing old shows.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kToastSeconds = 6
local kMaxToasts = 3
local kKeep = 30

local Notifier = {}
Notifier.__index = Notifier

--- One notice: kind ('friend', 'message', 'mention', 'match'), title, text, and what a click does.
function Notifier:Add(kind, title, text, action)
    local notice = { kind = kind, title = title, text = text or '', action = action, at = GetSystemTimeSeconds() }
    table.insert(self.notices, 1, notice)
    while table.getn(self.notices) > kKeep do
        table.remove(self.notices)
    end
    self.unseen = self.unseen + 1
    LOG('LAUNCHER: notice: ' .. kind .. ': ' .. title .. (text and text ~= '' and (' - ' .. text) or ''))
    self:Toast(notice)
    self:PaintBell()
end

function Notifier:Act(notice)
    if notice and notice.action then
        local ok, why = pcall(notice.action)
        if not ok then
            WARN('LAUNCHER: notice: ' .. tostring(why))
        end
    end
end

------------------------------------------------------------------------------------------------------------------------
-- Toasts.

function Notifier:Toast(notice)
    local root = self.launcher.root
    if not root then
        return
    end
    local toast = Theme.Panel(root, 'f20b161e', C.lineStrong)
    Theme.Brackets(toast, C.accent)
    toast.Depth:Set(function() return root.Depth() + 300 end)
    LayoutHelpers.SetDimensions(toast, 360, 74)
    toast.Right:Set(function() return root.Right() - Scale(24) end)
    local icon = Theme.Icon(toast, ({ friend = 'users', message = 'chat', mention = 'chat', match = 'play' })[notice.kind] or
        'bell', 20, C.accent)
    LayoutHelpers.AtLeftTopIn(icon, toast, 14, 14)
    local title = Theme.Cell(toast, 14, C.text, true)
    title.Left:Set(function() return icon.Right() + Scale(12) end)
    title.Right:Set(function() return toast.Right() - Scale(14) end)
    title.Top:Set(function() return toast.Top() + Scale(12) end)
    Theme.SetText(title, notice.title)
    local text = Theme.Cell(toast, 12, C.muted)
    text.Left:Set(title.Left)
    text.Right:Set(title.Right)
    text.Top:Set(function() return title.Bottom() + Scale(6) end)
    Theme.SetText(text, notice.text)
    local notifier = self
    Theme.HitArea(toast, function(control, event)
        if event.Type == 'ButtonPress' and event.Modifiers.Left then
            Theme.ClickSound()
            notifier:Act(notice)
            toast.ends = 0
            return true
        end
        return false
    end)
    toast.ends = GetSystemTimeSeconds() + kToastSeconds
    table.insert(self.toasts, 1, toast)
    import('/fafengine/modules/lua/ui/launcher/anim.lua').FadeIn(toast, 0.2)
    while table.getn(self.toasts) > kMaxToasts do
        table.remove(self.toasts):Destroy()
    end
    self:PlaceToasts()
end

function Notifier:PlaceToasts()
    local root = self.launcher.root
    for i, toast in self.toasts do
        local index = i - 1
        toast.Bottom:Set(function() return root.Bottom() - Scale(52 + index * 84) end)
    end
end

function Notifier:ExpireToasts()
    local now = GetSystemTimeSeconds()
    local kept = {}
    for _, toast in self.toasts do
        if toast.ends <= now then
            -- Fades out, then goes (anim.lua; at once with Reduce motion).
            local gone = toast
            import('/fafengine/modules/lua/ui/launcher/anim.lua').Run(gone, 0.25, function(t)
                gone:SetAlpha(1 - t, true)
            end, function()
                gone:Destroy()
            end)
        else
            table.insert(kept, toast)
        end
    end
    if table.getn(kept) ~= table.getn(self.toasts) then
        self.toasts = kept
        self:PlaceToasts()
    end
end

------------------------------------------------------------------------------------------------------------------------
-- The bell.

function Notifier:PaintBell()
    local bell = self.bell
    if not bell then
        return
    end
    Theme.SetText(self.badge, self.unseen > 9 and '9+' or tostring(self.unseen))
    Theme.SetVisible(self.badgeBack, self.unseen > 0)
    Theme.SetVisible(self.badge, self.unseen > 0)
end

--- The bell's list under it: the latest notices (a click acts), and Clear.
function Notifier:OpenList()
    self.unseen = 0
    self:PaintBell()
    local items = {}
    for _, notice in self.notices do
        table.insert(items, { notice.title .. (notice.text ~= '' and ('  -  ' .. notice.text) or ''), notice = notice })
    end
    if table.getn(items) == 0 then
        table.insert(items, { 'Nothing new.', color = C.subtle })
    else
        table.insert(items, { 'Clear the list', clear = true, color = C.subtle })
    end
    local notifier = self
    self.list = Widgets.Dropdown(self.bell, items, function(item)
        if item.clear then
            notifier.notices = {}
        elseif item.notice then
            notifier:Act(item.notice)
        end
    end, { width = 460, maxRows = 12 })
end

--- The bell goes into the top bar's utilities (launcher.lua makes it as a tab without a page).
function Notifier:AttachBell(item)
    self.bell = item
    self.badgeBack = Theme.Rect(item, C.bad)
    LayoutHelpers.SetDimensions(self.badgeBack, 18, 14)
    self.badgeBack.Right:Set(function() return item.Right() - Scale(6) end)
    self.badgeBack.Top:Set(function() return item.Top() + Scale(14) end)
    self.badgeBack:DisableHitTest()
    self.badge = Theme.Text(item, '', 10, C.text, true)
    LayoutHelpers.AtCenterIn(self.badge, self.badgeBack)
    self.badge:DisableHitTest()
    self:PaintBell()
end

------------------------------------------------------------------------------------------------------------------------
-- The sources.

function Notifier:PollFriends()
    if not rawget(_G, 'FafOnline_Contacts') then
        return
    end
    local contacts = FafOnline_Contacts()
    local online = {}
    for _, item in (contacts.friends or {}) do
        online[item.id] = item.online and (item.login or true) or false
    end
    if self.friends then
        for id, now in online do
            local before = self.friends[id]
            if now and not before and before ~= nil then
                local login = type(now) == 'string' and now or ('player ' .. id)
                self:Add('friend', login .. ' is online', 'Your friend came online.', function()
                    self.launcher:ShowPage('contacts')
                end)
            elseif not now and before then
                local login = type(before) == 'string' and before or ('player ' .. id)
                self:Add('friend', login .. ' went offline', '', function()
                    self.launcher:ShowPage('contacts')
                end)
            end
        end
    end
    self.friends = online
end

function Notifier:PollChat()
    if not rawget(_G, 'FafChat_Status') then
        return
    end
    local status = FafChat_Status()
    if status.state ~= 'joined' then
        return
    end
    local nick = string.lower(status.nick or '')
    local launcher = self.launcher
    -- The channels there at the first look start from their end; one that comes later (a private message opens its
    -- conversation) from its first line.
    local starting = not self.chatStarted
    self.chatStarted = true
    for _, channel in (status.channels or {}) do
        local got = FafChat_Lines(channel, self.chatSeen[channel] or 0)
        local first = starting and self.chatSeen[channel] == nil
        self.chatSeen[channel] = got.total or 0
        if not first then
            local private = string.sub(channel, 1, 1) ~= '#' and string.sub(channel, 1, 1) ~= '&'
            local chatView = launcher.chatView
            local looking = launcher.page == 'chat' and chatView and chatView.channel == channel
            for _, line in (got.lines or {}) do
                if not line.self and not line.history and not line.event and not looking then
                    local text = line.text or ''
                    local named = nick ~= '' and string.find(' ' .. string.lower(text) .. ' ', '[^%w_]' ..
                        string.gsub(nick, '([%^%$%(%)%%%.%[%]%*%+%-%?])', '%%%1') .. '[^%w_]')
                    if private or named then
                        local target = channel
                        self:Add(private and 'message' or 'mention', private and ('Message from ' .. line.from) or
                            (line.from .. ' named you in ' .. channel), text, function()
                            launcher:ShowPage('chat')
                            if launcher.chatView then
                                launcher.chatView:Choose(target)
                            end
                        end)
                    end
                end
            end
        end
    end
end

function Notifier:PollMatch()
    if not rawget(_G, 'FafOnline_Queues') then
        return
    end
    local info = FafOnline_Queues() or {}
    if info.state == 'found' and self.matchState ~= 'found' and self.matchState ~= nil then
        self:Add('match', 'Match found', 'In ' .. tostring(info.matched or 'the matchmaker') .. ': the game is starting.',
            function() self.launcher:ShowPage('matchmaking') end)
    end
    self.matchState = info.state or 'idle'
end

--- A matchmaker party invite: a notice that opens Matchmaking, where it is accepted or declined.
function Notifier:PollParty()
    if not rawget(_G, 'FafOnline_Party') then
        return
    end
    local party = FafOnline_Party() or {}
    local now = {}
    for _, invite in party.invites or {} do
        now[invite.id] = true
        if self.partyInvites and not self.partyInvites[invite.id] then
            local who = invite.login ~= '' and invite.login or ('player ' .. invite.id)
            self:Add('party', 'Party invite', who .. ' invites you to queue together.',
                function() self.launcher:ShowPage('matchmaking') end)
        end
    end
    self.partyInvites = now
end

function Notifier:Poll()
    for _, source in { 'PollFriends', 'PollChat', 'PollMatch', 'PollParty' } do
        local ok, why = pcall(self[source], self)
        if not ok and not self.failed then
            self.failed = true
            WARN('LAUNCHER: notices: ' .. source .. ': ' .. tostring(why))
        end
    end
    self:ExpireToasts()
end

function Create(launcher)
    return setmetatable({ launcher = launcher, notices = {}, toasts = {}, unseen = 0, chatSeen = {} }, Notifier)
end
