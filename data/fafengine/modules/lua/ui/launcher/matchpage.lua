-- The launcher's Matchmaking page (Play > Matchmaking): FAF's matchmaker queues (the engine's FafOnline_Queues, from the
-- lobby's matchmaker_info), each a card with how many search in it, when it next makes matches and the player's
-- rating there, and Search or Stop; the factions the matchmaker may give the player; and where the search stands
-- (searching, a match found, cancelled). A match found starts as any FAF game does (game_launch).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kFactions = { { 'uef', 'UEF' }, { 'aeon', 'Aeon' }, { 'cybran', 'Cybran' }, { 'seraphim', 'Seraphim' } }
local kFactionsPref = 'fafre_mm_factions'
local kCardWidth = 380
local kCardHeight = 196

--- A queue's name for people, and the rating type FAF keeps for it.
local kQueues = {
    ladder1v1 = { '1v1', 'ladder_1v1', 'Ranked one against one' },
    tmm2v2 = { '2v2', 'tmm_2v2', 'Team matchmaking, two against two' },
    ladder2v2 = { '2v2', 'tmm_2v2', 'Team matchmaking, two against two' },
    tmm4v4_full_share = { '4v4 full share', 'tmm_4v4_full_share', 'Four against four; a defeated player\'s army goes to their team' },
    tmm4v4_share_until_death = { '4v4', 'tmm_4v4_share_until_death', 'Four against four; armies are shared until death' },
}
local function QueueInfo(name)
    local known = kQueues[name]
    if known then
        return known[1], known[2], known[3]
    end
    local text = string.gsub(string.gsub(name, '^tmm', ''), '_', ' ')
    return text, name, 'FAF matchmaker queue'
end

local function Clock(seconds)
    seconds = math.max(0, math.floor(seconds or 0))
    return string.format('%d:%02d', math.floor(seconds / 60), math.mod(seconds, 60))
end

function Build(launcher, page)
    local view = { cards = {} }
    launcher.matchView = view

    local title = Theme.Title(page, 'Matchmaking', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 0)
    local subtitle = Theme.Text(page, 'FAF pairs you with players of your rating; a queue makes matches when its round ends.',
        13, C.subtle)
    subtitle.Left:Set(function() return title.Right() + Scale(24) end)
    subtitle.Bottom:Set(function() return title.Bottom() - Scale(3) end)

    -- The factions the matchmaker may give: at least one, kept in the profile.
    local factionsCaption = Theme.Caption(page, 'Factions you play')
    LayoutHelpers.AtLeftIn(factionsCaption, page, 0)
    factionsCaption.Top:Set(function() return title.Bottom() + Scale(26) end)
    view.factionChoices = {}
    local before = nil
    for _, faction in kFactions do
        local key = faction[1]
        local choice = Theme.Choice(page, faction[2], 120, function(self)
            view:ToggleFaction(key)
        end)
        choice.key = key
        if before then
            local after = before
            choice.Left:Set(function() return after.Right() + Scale(8) end)
        else
            choice.Left:Set(page.Left)
        end
        choice.Top:Set(function() return factionsCaption.Bottom() + Scale(10) end)
        table.insert(view.factionChoices, choice)
        before = choice
    end

    -- The party: who queues with this player (FAF's lobby parties: the owner invites, members accept, the owner's
    -- search takes everyone), with its invites and an invite of a friend.
    view.party = Theme.Panel(page, C.panel, C.line)
    view.party.Right:Set(page.Right)
    view.party.Top:Set(function() return factionsCaption.Top() - Scale(6) end)
    view.party.Bottom:Set(function() return view.factionChoices[1].Bottom() + Scale(6) end)
    view.party.Left:Set(function() return math.max(view.factionChoices[4].Right() + Scale(40), page.Right() - Scale(760)) end)
    Theme.SizeFromEdges(view.party)
    view.partyCaption = Theme.Text(view.party, 'YOUR PARTY', 10, C.accent, true)
    LayoutHelpers.AtLeftTopIn(view.partyCaption, view.party, 14, 8)
    view.partyHint = Theme.Cell(view.party, 12, C.subtle)
    view.partyHint.Left:Set(function() return view.partyCaption.Right() + Scale(12) end)
    view.partyHint.Right:Set(function() return view.party.Right() - Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(view.partyHint, view.partyCaption)
    view.partyInvite = Theme.Button(view.party, 'Invite', function() view:PickFriend() end, 'secondary',
        { icon = 'plus', width = 110, height = 30 })
    view.partyLeave = Theme.Button(view.party, 'Leave', function()
        local ok, why = FafOnline_PartyLeave()
        view.notice = (not ok) and ('You are still in the party: ' .. tostring(why) .. '.') or nil
        view:Refresh()
    end, 'ghost', { icon = 'logout', width = 100, height = 30 })
    view.partyLeave.Right:Set(function() return view.party.Right() - Scale(10) end)
    view.partyLeave.Bottom:Set(function() return view.party.Bottom() - Scale(8) end)
    view.partyInvite.Right:Set(function() return view.partyLeave.Left() - Scale(8) end)
    view.partyInvite.Bottom:Set(view.partyLeave.Bottom)
    -- In a party the members take the row: Invite shrinks to its icon after them.
    view.partyInviteSmall = Theme.Button(view.party, '', function() view:PickFriend() end, 'secondary',
        { icon = 'plus', width = 34, height = 30 })
    view.partyInviteSmall.Bottom:Set(view.partyLeave.Bottom)
    -- An invite to another player's party: Accept or Decline.
    view.acceptInvite = Theme.Button(view.party, 'Accept', function() view:AnswerInvite(true) end, 'primary',
        { icon = 'check', width = 110, height = 30 })
    view.declineInvite = Theme.Button(view.party, 'Decline', function() view:AnswerInvite(false) end, 'secondary',
        { width = 100, height = 30 })
    view.acceptInvite.Right:Set(function() return view.declineInvite.Left() - Scale(8) end)
    view.acceptInvite.Bottom:Set(view.partyLeave.Bottom)
    view.declineInvite.Right:Set(view.partyLeave.Right)
    view.declineInvite.Bottom:Set(view.partyLeave.Bottom)
    view.members = {}
    for slot = 1, 4 do
        local member = Group(view.party)
        member:DisableHitTest()
        LayoutHelpers.SetHeight(member, 30)
        -- Each chip as wide as its name, faction letters and remove button, after the one before it.
        local before = view.members[slot - 1]
        member.Left:Set(function() return before and (before.Right() + Scale(6)) or (view.party.Left() + Scale(14)) end)
        member.Bottom:Set(view.partyLeave.Bottom)
        member.back = Theme.Panel(member, 'ff0d2130', C.line)
        LayoutHelpers.FillParent(member.back, member)
        member.tag = Widgets.PlayerTag(member, 12)
        member.tag.Left:Set(function() return member.Left() + Scale(8) end)
        LayoutHelpers.AtVerticalCenterIn(member.tag, member)
        member.factions = Theme.Text(member, '', 10, C.subtle, true)
        member.factions.Right:Set(function() return member.Right() - Scale(26) end)
        LayoutHelpers.AtVerticalCenterIn(member.factions, member)
        member.kick = Theme.Button(member, '', function()
            if member.id then
                local ok, why = FafOnline_PartyKick(member.id)
                view.notice = (not ok) and ('Not removed: ' .. tostring(why) .. '.') or nil
                view:Refresh()
            end
        end, 'ghost', { icon = 'close', width = 24, height = 24 })
        member.kick.Right:Set(function() return member.Right() - Scale(2) end)
        LayoutHelpers.AtVerticalCenterIn(member.kick, member)
        member.Width:Set(function()
            return Scale(8) + member.tag.Width() + Scale(10) + member.factions.Width() + Scale(28)
        end)
        view.members[slot] = member
    end

    -- Where the search stands.
    view.banner = Theme.Panel(page, C.panel, C.line)
    view.banner.Left:Set(page.Left)
    view.banner.Right:Set(page.Right)
    view.banner.Top:Set(function() return view.factionChoices[1].Bottom() + Scale(22) end)
    LayoutHelpers.SetHeight(view.banner, 56)
    view.banner.Width:Set(function() return view.banner.Right() - view.banner.Left() end)
    view.bannerDot = Theme.Dot(view.banner, 10, C.subtle)
    LayoutHelpers.AtLeftIn(view.bannerDot, view.banner, 18)
    LayoutHelpers.AtVerticalCenterIn(view.bannerDot, view.banner)
    view.bannerText = Theme.Text(view.banner, '', 15, C.text)
    view.bannerText.Left:Set(function() return view.bannerDot.Right() + Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(view.bannerText, view.banner)
    view.loader = Theme.Loader(view.banner)
    view.loader.Left:Set(function() return view.bannerText.Right() + Scale(18) end)
    LayoutHelpers.AtVerticalCenterIn(view.loader, view.banner)
    view.stopAll = Theme.Button(view.banner, 'Stop searching', function() view:StopAll() end, 'danger', { width = 190 })
    LayoutHelpers.AtRightIn(view.stopAll, view.banner, 12)
    LayoutHelpers.AtVerticalCenterIn(view.stopAll, view.banner)

    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(page.Right)
    area.Top:Set(function() return view.banner.Bottom() + Scale(22) end)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    view.area = area
    view.empty = Theme.Paragraph(area, 14, C.subtle)
    view.empty.Left:Set(area.Left)
    view.empty.Right:Set(function() return area.Left() + math.min(area.Width(), Scale(700)) end)
    view.empty.Top:Set(area.Top)

    --- A queue's card: its name, kind, searching players, the countdown to its round, the player's rating, Search.
    local function Card(index)
        local card = view.cards[index]
        if card then
            return card
        end
        card = Theme.Panel(area, 'ff0d1c27', C.line)
        LayoutHelpers.SetDimensions(card, kCardWidth, kCardHeight)
        local slot = index - 1
        card.Left:Set(function()
            local perRow = math.max(1, math.floor((area.Width() + Scale(16)) / Scale(kCardWidth + 16)))
            return area.Left() + math.mod(slot, perRow) * Scale(kCardWidth + 16)
        end)
        card.Top:Set(function()
            local perRow = math.max(1, math.floor((area.Width() + Scale(16)) / Scale(kCardWidth + 16)))
            return area.Top() + math.floor(slot / perRow) * Scale(kCardHeight + 16)
        end)
        card.edge = Theme.Rect(card, C.accent)
        card.edge:DisableHitTest()
        card.edge.Left:Set(card.Left)
        card.edge.Top:Set(card.Top)
        card.edge.Bottom:Set(card.Bottom)
        card.edge.Width:Set(Scale(3))
        card.name = Theme.Title(card, '', 20, C.text)
        LayoutHelpers.AtLeftTopIn(card.name, card, 20, 18)
        card.kind = Theme.Cell(card, 12, C.muted)
        card.kind.Left:Set(function() return card.Left() + Scale(20) end)
        card.kind.Right:Set(function() return card.Right() - Scale(16) end)
        card.kind.Top:Set(function() return card.Top() + Scale(52) end)
        card.players = Theme.Text(card, '', 26, C.text, true)
        LayoutHelpers.AtLeftTopIn(card.players, card, 20, 80)
        card.playersCaption = Theme.Text(card, 'SEARCHING', 10, C.muted, true)
        LayoutHelpers.AtLeftTopIn(card.playersCaption, card, 20, 116)
        card.pop = Theme.Text(card, '', 26, C.text, true)
        LayoutHelpers.AtLeftTopIn(card.pop, card, 140, 80)
        card.popCaption = Theme.Text(card, 'NEXT ROUND', 10, C.muted, true)
        LayoutHelpers.AtLeftTopIn(card.popCaption, card, 140, 116)
        card.rating = Theme.Text(card, '', 26, C.gold, true)
        LayoutHelpers.AtLeftTopIn(card.rating, card, 260, 80)
        card.ratingCaption = Theme.Text(card, 'YOUR RATING', 10, C.muted, true)
        LayoutHelpers.AtLeftTopIn(card.ratingCaption, card, 260, 116)
        card.button = Theme.Button(card, 'Search', function()
            if card.queue then
                view:Toggle(card.queue)
            end
        end, 'primary', { width = kCardWidth - 40, icon = 'search', height = 34 })
        LayoutHelpers.AtLeftIn(card.button, card, 20)
        LayoutHelpers.AtBottomIn(card.button, card, 16)
        view.cards[index] = card
        return card
    end

    ----------------------------------------------------------------------------------------------------------------

    function view:Factions()
        local kept = Prefs.GetFromCurrentProfile(kFactionsPref)
        if type(kept) ~= 'table' or table.getn(kept) == 0 then
            kept = { 'uef', 'aeon', 'cybran', 'seraphim' }
        end
        return kept
    end

    function view:ToggleFaction(key)
        local now, on = {}, false
        for _, faction in self:Factions() do
            if faction == key then
                on = true
            else
                table.insert(now, faction)
            end
        end
        if not on then
            table.insert(now, key)
        end
        if table.getn(now) == 0 then
            self.notice = 'Pick a faction at least.'
            self:Refresh()
            return
        end
        Prefs.SetToCurrentProfile(kFactionsPref, now)
        local ok, why = FafOnline_SetFactions(now)
        self.notice = (not ok) and ('FAF kept your factions as they were: ' .. tostring(why) .. '.') or nil
        self:Refresh()
    end

    function view:Toggle(queue)
        local ok, why = FafOnline_Search(queue.name, not queue.searching)
        if ok and not queue.searching then
            -- The matchmaker gives one of the factions picked here.
            FafOnline_SetFactions(self:Factions())
        end
        self.notice = (not ok) and ('The search didn\'t change: ' .. tostring(why) .. '.') or nil
        self:Refresh()
    end

    --- Accepts or declines the first invite.
    function view:AnswerInvite(accept)
        local party = FafOnline_Party()
        local invite = party.invites and party.invites[1]
        if not invite then
            return
        end
        local ok, why
        if accept then
            ok, why = FafOnline_PartyAccept(invite.id)
        else
            ok, why = FafOnline_PartyDecline(invite.id)
        end
        self.notice = (not ok) and ('The invite stands: ' .. tostring(why) .. '.') or nil
        self:Refresh()
    end

    --- A friend online to invite: a small list over the launcher; a click invites them.
    function view:PickFriend()
        if self.picker then
            self.picker:Destroy()
        end
        local cover = Widgets.Modal(launcher.root, 520, 460)
        self.picker = cover
        local panel = cover.panel
        local heading = Theme.Title(panel, 'Invite a friend', 16, C.text)
        LayoutHelpers.AtLeftTopIn(heading, panel, 24, 20)
        local close = Theme.Button(panel, '', function()
            cover:Destroy()
            view.picker = nil
        end, 'ghost', { icon = 'close', width = 40 })
        LayoutHelpers.AtRightTopIn(close, panel, 12, 12)
        local note = Theme.Text(panel, 'Friends online now. A click sends the invite.', 12, C.muted)
        note.Left:Set(heading.Left)
        note.Top:Set(function() return heading.Bottom() + Scale(8) end)
        local friends = {}
        for _, item in ((rawget(_G, 'FafOnline_Contacts') and FafOnline_Contacts() or {}).friends or {}) do
            if item.online and item.id then
                table.insert(friends, { key = tostring(item.id), id = item.id, login = item.login or ('player ' .. item.id),
                    country = item.country, clan = item.clan })
            end
        end
        local list = Widgets.VirtualList(panel, {
            { 'Player', 1.0, function(item) return { login = item.login, country = item.country, clan = item.clan } end,
                kind = 'player' },
        }, function(item)
            local ok, why = FafOnline_PartyInvite(item.id)
            view.notice = ok and nil or ('Not invited: ' .. tostring(why) .. '.')
            view.invited = ok and item.login or nil
            cover:Destroy()
            view.picker = nil
            view:Refresh()
        end)
        list.Left:Set(heading.Left)
        list.Right:Set(function() return panel.Right() - Scale(24) end)
        list.Top:Set(function() return note.Bottom() + Scale(14) end)
        list.Bottom:Set(function() return panel.Bottom() - Scale(20) end)
        list:SetItems(friends)
        local empty = Theme.Text(panel, 'None of your friends is online.', 13, C.subtle)
        empty.Left:Set(heading.Left)
        empty.Top:Set(function() return note.Bottom() + Scale(60) end)
        Theme.SetVisible(empty, table.getn(friends) == 0)
        return list, friends
    end

    function view:PaintParty(status)
        local party = rawget(_G, 'FafOnline_Party') and FafOnline_Party() or { members = {}, invites = {} }
        self.partyState = party
        local signedIn = status.lobby == 'signedin'
        local members = party.members or {}
        local invite = (party.invites or {})[1]
        local inParty = table.getn(members) > 1
        local me = status.login and status.login ~= '' and rawget(_G, 'FafOnline_Player') and FafOnline_Player(status.login)
        local myId = me and me.id and tostring(me.id) or nil
        local owner = party.owner or ''
        local hint
        if not signedIn then
            hint = 'Connect to FAF to queue with friends.'
        elseif invite and not inParty then
            hint = (invite.login ~= '' and invite.login or ('player ' .. invite.id)) .. ' invites you to queue together.'
        elseif inParty then
            hint = party.mine and 'You lead: your search takes everyone.' or 'The leader starts the search for everyone.'
        elseif self.invited then
            hint = 'Invited ' .. self.invited .. '; they join when they accept.'
        else
            hint = (party.note ~= '' and (party.note .. ' ') or '') .. 'Invite a friend to queue together.'
        end
        Theme.SetText(self.partyHint, hint)
        for slot, member in self.members do
            local entry = members[slot]
            Theme.SetVisible(member, entry ~= nil)
            if entry then
                member.id = entry.id
                local player = entry.login ~= '' and rawget(_G, 'FafOnline_Player') and FafOnline_Player(entry.login) or {}
                member.tag:Set({ login = entry.login ~= '' and entry.login or ('#' .. entry.id), country = player.country,
                    clan = player.clan, color = entry.id == owner and C.gold or C.text })
                local short = {}
                for _, faction in entry.factions or {} do
                    table.insert(short, string.upper(string.sub(faction, 1, 1)))
                end
                Theme.SetText(member.factions, table.concat(short, ''))
                Theme.SetVisible(member.kick, party.mine and entry.id ~= myId)
                member.back:SetColors(entry.id == owner and 'ff1d1a0d' or 'ff0d2130', entry.id == owner and
                    Theme.WithAlpha(C.gold, 0.5) or C.line)
            end
        end
        local showInvite = signedIn and invite ~= nil and not inParty
        Theme.SetVisible(self.acceptInvite, showInvite)
        Theme.SetVisible(self.declineInvite, showInvite)
        local leave = signedIn and inParty
        Theme.SetVisible(self.partyLeave, leave)
        if self.leaveShown ~= leave then
            self.leaveShown = leave
            self.partyInvite.Right:Set(function()
                return leave and (self.partyLeave.Left() - Scale(8)) or (self.party.Right() - Scale(10))
            end)
        end
        -- Full Invite out of a party; the small one after the last member (up to 4) in one this player leads.
        local canInvite = signedIn and not showInvite and (party.mine or not inParty)
        Theme.SetVisible(self.partyInvite, canInvite and not inParty)
        local count = table.getn(members)
        Theme.SetVisible(self.partyInviteSmall, canInvite and inParty and count < 4)
        if self.smallAfter ~= count then
            self.smallAfter = count
            local last = self.members[math.max(1, math.min(4, count))]
            self.partyInviteSmall.Left:Set(function() return last.Right() + Scale(8) end)
        end
        if inParty then
            self.invited = nil
        end
    end

    function view:StopAll()
        for _, queue in (FafOnline_Queues().queues or {}) do
            if queue.searching then
                FafOnline_Search(queue.name, false)
            end
        end
        self:Refresh()
    end

    function view:Refresh()
        if not rawget(_G, 'FafOnline_Queues') then
            self.empty:SetText('This build has no matchmaker.', C.subtle)
            return
        end
        local status = launcher.lastStatus or {}
        local info = FafOnline_Queues()
        local queues = info.queues or {}
        local me = status.login and status.login ~= '' and rawget(_G, 'FafOnline_Player') and FafOnline_Player(status.login) or {}
        local chosen = {}
        for _, faction in self:Factions() do
            chosen[faction] = true
        end
        for _, choice in self.factionChoices do
            choice.selected = chosen[choice.key] and true or false
            choice:Paint(false)
        end
        -- The banner: what the matchmaker is doing for this player.
        local searching = {}
        for _, queue in queues do
            if queue.searching then
                table.insert(searching, (QueueInfo(queue.name)))
            end
        end
        local text, color, busy = 'Pick a queue to search for a match.', C.subtle, false
        if status.lobby ~= 'signedin' then
            text, color = 'Connect to FAF on Custom games first; the matchmaker is part of FAF\'s lobby.', C.warn
        elseif info.state == 'found' then
            text, color, busy = 'Match found in ' .. (QueueInfo(info.matched or '')) .. '. Starting the game...', C.good, true
        elseif info.state == 'cancelled' then
            text, color = 'The match was cancelled (a player didn\'t answer). Search again when you\'re ready.', C.warn
        elseif table.getn(searching) > 0 then
            text, color, busy = 'Searching in ' .. table.concat(searching, ', ') .. '.', C.accent, true
        end
        if self.notice then
            text, color = self.notice, C.bad
        end
        self:PaintParty(status)
        if not self.notice and self.partyState and table.getn(self.partyState.members or {}) > 1 and
            not self.partyState.mine and table.getn(searching) == 0 and status.lobby == 'signedin' and
            info.state ~= 'found' then
            text, color = 'In a party: the leader starts the search.', C.subtle
        end
        Theme.SetText(self.bannerText, text)
        Theme.SetColor(self.bannerText, color)
        self.bannerDot:SetDotColor(color)
        Theme.SetVisible(self.loader, busy)
        Theme.SetVisible(self.stopAll, table.getn(searching) > 0)
        -- The queues.
        table.sort(queues, function(a, b)
            if a.teamSize ~= b.teamSize then
                return a.teamSize < b.teamSize
            end
            return a.name < b.name
        end)
        for i, queue in queues do
            local card = Card(i)
            card.queue = queue
            local name, ratingType, kind = QueueInfo(queue.name)
            Theme.SetText(card.name, name)
            Theme.SetText(card.kind, kind .. '  -  ' .. queue.teamSize .. ' vs ' .. queue.teamSize)
            Theme.SetText(card.players, tostring(queue.players))
            Theme.SetText(card.pop, Clock(queue.popIn))
            local rating = me.ratings and me.ratings[ratingType]
            Theme.SetText(card.rating, rating and tostring(math.floor(rating.rating or 0)) or '-')
            card.edge:SetSolidColor(queue.searching and C.good or C.accent)
            card:SetColors(queue.searching and 'ff0f2a24' or 'ff0d1c27', queue.searching and C.good or C.line)
            card.button:SetLabel(queue.searching and 'Stop searching' or 'Search')
            -- In a party only its leader searches (FAF's lobby refuses the others).
            local follower = self.partyState and table.getn(self.partyState.members or {}) > 1 and not self.partyState.mine
            card.button:SetEnabled(status.lobby == 'signedin' and info.state ~= 'found' and not follower)
            Theme.SetVisible(card, true)
        end
        for i = table.getn(queues) + 1, table.getn(self.cards) do
            Theme.SetVisible(self.cards[i], false)
        end
        self.empty:SetText(table.getn(queues) == 0 and (status.lobby == 'signedin' and
            'FAF\'s lobby hasn\'t listed its queues yet.' or 'The queues show once you are connected to FAF\'s lobby.') or '',
            C.subtle)
        self.queues = queues
    end

    return view
end
