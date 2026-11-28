-- The launcher's Contacts page (beside Chat): the player's FAF friends and foes (FAF's lobby keeps them: the `social`
-- message, social_add and social_remove), online ones first, and every player online in FAF's lobby to find by name.
-- The chosen player: their profile, and adding or removing them as a friend or a foe. Offline friends and foes are
-- named through FAF's API (/data/player), as the lobby names only the players online.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kTabs = { { 'friends', 'Friends' }, { 'foes', 'Foes' }, { 'players', 'Find players' } }

function Build(launcher, page)
    local view = { tab = 'friends', names = {}, asked = {}, jobs = {} }
    launcher.contactsView = view

    local title = Theme.Title(page, 'Contacts', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, kTabs, function(key)
        view.tab = key
        view.list.top = 1
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

    view.search = Theme.TextField(page, 340, 'Find a player by name', 'search', 40)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search:OnChange(function()
        view.list.top = 1
        view:Paint()
    end)
    view.count = Theme.Text(page, '', 12, C.subtle)
    view.count.Left:Set(function() return view.search.Right() + Scale(20) end)
    LayoutHelpers.AtVerticalCenterIn(view.count, view.search)

    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Right:Set(page.Right)
    detail.Top:Set(function() return view.search.Bottom() + Scale(18) end)
    detail.Bottom:Set(page.Bottom)
    LayoutHelpers.SetWidth(detail, 420)
    detail.Left:Set(function() return detail.Right() - detail.Width() end)
    detail.Height:Set(function() return detail.Bottom() - detail.Top() end)
    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(function() return detail.Left() - Scale(24) end)
    area.Top:Set(detail.Top)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    view.list = Widgets.VirtualList(area, {
        { 'Player', 0.56, function(item)
            return { login = item.login or view.names[item.id] or ('player ' .. tostring(item.id)),
                country = item.country or '', clan = item.clan or '' }
        end, kind = 'player' },
        { 'Status', 0.24, function(item) return item.online and 'Online' or 'Offline' end, C.muted },
        { 'Rating', 0.2, function(item) return item.rating and tostring(item.rating) or '' end, C.gold },
    }, function(item, double)
        view.chosen = item
        if double then
            view:Profile()
        end
        view:Paint()
    end)
    LayoutHelpers.FillParent(view.list, area)
    Theme.SizeFromEdges(view.list)
    view.note = Theme.Paragraph(area, 14, C.subtle)
    view.note.Left:Set(area.Left)
    view.note.Right:Set(function() return area.Left() + math.min(area.Width(), Scale(600)) end)
    view.note.Top:Set(function() return area.Top() + Scale(40) end)

    local x = 24
    view.who = Widgets.PlayerTag(detail, 20, function(login) launcher:ShowProfile(login) end)
    LayoutHelpers.AtLeftTopIn(view.who, detail, x, 26)
    view.facts = Theme.Text(detail, '', 13, C.muted)
    view.facts.Left:Set(view.who.Left)
    view.facts.Top:Set(function() return view.who.Bottom() + Scale(8) end)
    view.relation = Theme.Text(detail, '', 13, C.accent)
    view.relation.Left:Set(view.who.Left)
    view.relation.Top:Set(function() return view.facts.Bottom() + Scale(6) end)
    view.profileButton = Theme.Button(detail, 'View profile', function() view:Profile() end, 'primary',
        { icon = 'user', width = 372 })
    view.profileButton.Left:Set(view.who.Left)
    view.profileButton.Top:Set(function() return view.relation.Bottom() + Scale(24) end)
    view.friendButton = Theme.Button(detail, 'Add friend', function() view:Toggle('friend') end, 'secondary',
        { icon = 'userCheck', width = 181 })
    view.friendButton.Left:Set(view.who.Left)
    view.friendButton.Top:Set(function() return view.profileButton.Bottom() + Scale(10) end)
    view.foeButton = Theme.Button(detail, 'Add foe', function() view:Toggle('foe') end, 'secondary',
        { icon = 'userX', width = 181 })
    view.foeButton.Left:Set(function() return view.friendButton.Right() + Scale(10) end)
    view.foeButton.Top:Set(view.friendButton.Top)
    view.messageButton = Theme.Button(detail, 'Message', function() view:Message() end, 'secondary',
        { icon = 'chat', width = 372 })
    view.messageButton.Left:Set(view.who.Left)
    view.messageButton.Top:Set(function() return view.friendButton.Bottom() + Scale(10) end)
    view.status = Theme.Paragraph(detail, 12, C.subtle)
    view.status.Left:Set(view.who.Left)
    view.status.Right:Set(function() return detail.Right() - Scale(x) end)
    view.status.Top:Set(function() return view.messageButton.Bottom() + Scale(16) end)

    ----------------------------------------------------------------------------------------------------------------

    local function Login(item)
        return item and (item.login or view.names[item.id])
    end

    function view:Profile()
        local login = Login(self.chosen)
        if login then
            launcher:ShowProfile(login)
        end
    end

    --- A private conversation with the chosen player in the chat (which signs in first when it isn't).
    function view:Message()
        local login = Login(self.chosen)
        if not login or not launcher.chatView then
            return
        end
        launcher:ShowPage('chat')
        launcher.chatView:OpenPrivate(login)
    end

    --- Friend or foe on (when off) or off (when on), through FAF's lobby.
    function view:Toggle(kind)
        local item = self.chosen
        if not item then
            return
        end
        local on = not item[kind]
        local set = kind == 'friend' and rawget(_G, 'FafOnline_SetFriend') or rawget(_G, 'FafOnline_SetFoe')
        if not set then
            return
        end
        local ok, why = set(item.id, on)
        local name = Login(item) or ('player ' .. item.id)
        self.statusText = ok and (name .. (on and (' is now a ' .. kind .. '.') or (' is no longer a ' .. kind .. '.'))) or
            ('FAF\'s lobby didn\'t take it: ' .. tostring(why))
        LOG('LAUNCHER: contacts: ' .. kind .. ' ' .. tostring(item.id) .. ' ' .. tostring(on) .. ': ' .. tostring(ok))
        self:Paint()
    end

    --- Names for offline friends and foes, asked of FAF's API once per id.
    function view:AskNames(items)
        local ids = {}
        for _, item in items do
            if not item.login and not self.names[item.id] and not self.asked[item.id] then
                self.asked[item.id] = true
                table.insert(ids, item.id)
            end
        end
        if table.getn(ids) == 0 or not rawget(_G, 'FafLibrary_Api') then
            return
        end
        local id = FafLibrary_Api('/data/player', { filter = 'id=in=(' .. table.concat(ids, ',') .. ')',
            ['page[size]'] = '100' })
        if id then
            table.insert(self.jobs, { id = id, done = function(doc)
                for _, player in (doc.data or {}) do
                    if player.id and player.attributes and player.attributes.login then
                        view.names[player.id] = player.attributes.login
                    end
                end
            end })
        end
    end

    function view:Items()
        local text = string.lower(self.search.edit:GetText() or '')
        if self.tab == 'players' then
            if not rawget(_G, 'FafOnline_Players') then
                return {}, 0
            end
            local list, total = FafOnline_Players(text, 500)
            for _, item in list do
                item.online = true
            end
            return list, total
        end
        local contacts = rawget(_G, 'FafOnline_Contacts') and FafOnline_Contacts() or {}
        local list = contacts[self.tab] or {}
        self:AskNames(list)
        local shown = {}
        for _, item in list do
            local name = string.lower(Login(item) or '')
            if text == '' or string.find(name, text, 1, true) then
                table.insert(shown, item)
            end
        end
        -- Online first, then by name.
        table.sort(shown, function(a, b)
            if a.online ~= b.online then
                return a.online
            end
            return string.lower(Login(a) or a.id) < string.lower(Login(b) or b.id)
        end)
        return shown, table.getn(list)
    end

    function view:Poll()
        local left = {}
        for _, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if state and state.state == 'working' then
                table.insert(left, job)
            elseif state and state.state == 'done' then
                pcall(job.done, state.data or {})
            end
        end
        self.jobs = left
    end

    function view:Paint()
        local status = launcher.lastStatus or {}
        local signedIn = status.lobby == 'signedin'
        local contacts = rawget(_G, 'FafOnline_Contacts') and FafOnline_Contacts() or {}
        local function Online(list)
            local count = 0
            for _, item in (list or {}) do
                count = count + (item.online and 1 or 0)
            end
            return count
        end
        self.tabs:Set(self.tab, { friends = table.getn(contacts.friends or {}), foes = table.getn(contacts.foes or {}) })
        local items, total = self:Items()
        -- The chosen player as the lists have them now (friend and foe follow a change).
        if self.chosen then
            local again = nil
            for _, item in items do
                if item.id == self.chosen.id then
                    again = item
                end
            end
            if not again then
                for _, list in { contacts.friends or {}, contacts.foes or {} } do
                    for _, item in list do
                        if item.id == self.chosen.id then
                            again = item
                        end
                    end
                end
            end
            if again then
                self.chosen = again
            elseif self.tab ~= 'players' then
                self.chosen.friend, self.chosen.foe = false, false
            end
        end
        self.list.selectedKey = false
        for _, item in items do
            item.key = item.id
        end
        self.list.selectedKey = self.chosen and self.chosen.id or false
        self.list:SetItems(items)
        local note = ''
        if not signedIn then
            note = 'Connect to FAF on Custom games: FAF\'s lobby keeps your friends and foes.'
        elseif table.getn(items) == 0 then
            note = (self.tab == 'friends' and 'No friends yet: find players and add them.') or
                (self.tab == 'foes' and 'No foes.') or 'No player online with that name.'
        end
        self.note:SetText(note, C.subtle)
        if self.tab == 'friends' then
            Theme.SetText(self.count, Online(contacts.friends) .. ' of ' .. total .. ' online')
        elseif self.tab == 'players' then
            Theme.SetText(self.count, total .. ' players online' .. (total > table.getn(items) and
                ('  (' .. table.getn(items) .. ' shown)') or ''))
        else
            Theme.SetText(self.count, '')
        end

        local item = self.chosen
        local login = Login(item)
        self.who:Set({ login = login or (item and ('player ' .. item.id)) or '', country = item and item.country or nil,
            clan = item and item.clan or nil })
        Theme.SetText(self.facts, item and ((item.online and 'Online' or 'Offline') .. (item.rating and
            ('  -  ' .. item.rating .. ' global') or '') .. (item.games and ('  -  ' .. item.games .. ' games') or '')) or
            'Choose a player.')
        Theme.SetText(self.relation, item and ((item.friend and 'Your friend') or (item.foe and 'Your foe') or '') or '')
        self.profileButton:SetEnabled(login ~= nil)
        local chat = rawget(_G, 'FafChat_Status') and FafChat_Status() or {}
        self.messageButton:SetEnabled(login ~= nil and chat.state == 'joined' and item ~= nil and item.online == true)
        self.friendButton:SetLabel(item and item.friend and 'Remove friend' or 'Add friend')
        self.foeButton:SetLabel(item and item.foe and 'Remove foe' or 'Add foe')
        self.friendButton:SetEnabled(item ~= nil and signedIn)
        self.foeButton:SetEnabled(item ~= nil and signedIn)
        self.status:SetText(self.statusText or '', C.subtle)
    end

    function view:Refresh()
        self:Poll()
        self:Paint()
    end

    return view
end
