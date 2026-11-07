-- Engine hook (data/fafengine, mounted by the engine at /fafengine and
-- registered as a hook directory): appended to /lua/ui/dialogs/disconnect.lua.
--
-- Issue #275: while a player takes a seat back, the engine leaves `rejoinStage`
-- (and `rejoinProgress` where the stage has a measure) in that player's
-- GetSessionClients entry. While they are lost, the Connectivity dialog above is
-- open as ever. From the moment they are on their way back the engine doesn't report
-- them as quiet, so that dialog and its auto-eject go away, and this one takes its
-- place: the same dialog to look at, whose row for that player says how far they have
-- got and keeps an eject button. The player coming back has the screen in the hook of
-- /lua/ui/uimain.lua instead. Without that field, which is every game where not all
-- clients announced rejoin, this never shows. If a returning player stops reporting,
-- the engine says "lost" again and the Connectivity dialog comes back. A player who
-- is back gets the announcement a defeated player gets.
--
-- FAF's Lua may carry these rows itself (issue #327): its disconnect.lua then defines its
-- own GetSessionClients in this module, and this block steps aside.

if not rawget(getfenv(1), 'GetSessionClients') then
    local UIUtil = import("/lua/ui/uiutil.lua")
    local LayoutHelpers = import("/lua/maui/layouthelpers.lua")
    local Bitmap = import("/lua/maui/bitmap.lua").Bitmap
    local Group = import("/lua/maui/group.lua").Group
    local SessionClients = import("/lua/ui/override/sessionclients.lua")

    local trackWidth = 236
    local dialog = false
    local stages = {}
    local stageStarts = {}
    local announcedBack = {}

    local function ElapsedText(seconds)
        return string.format("%d:%02d", math.floor(seconds / 60), math.mod(math.floor(seconds), 60))
    end

    local function PercentText(client)
        if client.rejoinProgress then
            return string.format(": %d%%", math.floor(client.rejoinProgress * 100))
        end
        return ''
    end

    --- A returning player reports every second. Loading a map can go quiet by itself.
    local function IsSilent(client)
        local allowed = 5
        if client.rejoinStage == 'loading' then
            allowed = 30
        end
        return client.rejoinSilent and client.rejoinSilent > allowed
    end

    --- What the row says for the stage the player is in.
    local function StageText(index, client)
        local stage = client.rejoinStage
        if stage == 'transfer' then
            return LOC("<LOC rejoin_0004>Step 1 of 3: receiving the game") .. PercentText(client)
        elseif stage == 'loading' then
            return LOC("<LOC rejoin_0005>Step 2 of 3: loading the map")
                .. ' (' .. ElapsedText(GetSystemTimeSeconds() - stageStarts[index]) .. ')'
        elseif stage == 'catchingUp' then
            return LOC("<LOC rejoin_0006>Step 3 of 3: catching up") .. PercentText(client)
        end
        return ''
    end

    --- As /lua/ui/game/gameresult.lua tells of a defeated player: the announcement
    --- goes to that player's line on the score board. FAF's option to hide player
    --- names can leave no line to find, which still shows it, from the top.
    local function AnnounceBack(client)
        LOG('REJOIN: showing ' .. client.name .. ' as back')

        local text
        if client['local'] then
            text = LOC("<LOC rejoin_0001>You are back in the game!")
        else
            text = LOCF("<LOC rejoin_0007>%s is back in the game!", client.name)
        end
        for army, info in GetArmiesTable().armiesTable do
            if info.nickname == client.name then
                import("/lua/ui/game/score.lua").ArmyAnnounce(army, text)
                return
            end
        end
        import("/lua/ui/game/announcement.lua").CreateAnnouncement(text)
    end

    --- On their way back, which is when this dialog speaks for them.
    local function IsReturning(client)
        return client.connected and client.rejoinStage and client.rejoinStage != 'lost'
            and client.rejoinStage != 'back' and not client['local']
    end

    local function CreateSlot(bg, index, client)
        local slot = Bitmap(bg, UIUtil.UIFile('/scx_menu/panel-brd/conn-bg.dds'))

        slot.id = UIUtil.CreateText(slot, index, 20, UIUtil.fixedFont)
        slot.id:SetColor('ffffffff')
        LayoutHelpers.AtLeftTopIn(slot.id, slot, 5, 1)

        slot.name = UIUtil.CreateText(slot, client.name, 16, UIUtil.fixedFont)
        slot.name:SetColor('FFbadbdb')
        LayoutHelpers.AtLeftTopIn(slot.name, slot, 20, 4)

        slot.state = Bitmap(slot)
        slot.state:SetTexture(UIUtil.UIFile('/game/unit-over/icon-skull_bmp.dds'))
        slot.state:DisableHitTest()
        slot.state:Hide()
        LayoutHelpers.AtRightTopIn(slot.state, slot, 2, 2)

        slot.ping = UIUtil.CreateText(slot, '', 14, UIUtil.fixedFont)
        LayoutHelpers.AtLeftTopIn(slot.ping, slot, 5, 32)

        slot.ejectedBy = UIUtil.CreateText(slot, '', 16, UIUtil.fixedFont)
        slot.ejectedBy:SetColor('FFbadbdb')
        LayoutHelpers.AtRightTopIn(slot.ejectedBy, slot, 5, 4)

        slot.status = UIUtil.CreateText(slot, '', 13, UIUtil.bodyFont)
        slot.status:SetColor('FFbadbdb')
        LayoutHelpers.AtLeftTopIn(slot.status, slot, 5, 24)

        slot.track = Bitmap(slot)
        slot.track:SetSolidColor('ff303030')
        slot.track:DisableHitTest()
        LayoutHelpers.SetDimensions(slot.track, trackWidth, 8)
        LayoutHelpers.AtLeftTopIn(slot.track, slot, 5, 44)

        slot.fill = Bitmap(slot.track)
        slot.fill:SetSolidColor('ff4fa0e0')
        slot.fill:DisableHitTest()
        LayoutHelpers.SetDimensions(slot.fill, 1, 8)
        LayoutHelpers.AtLeftTopIn(slot.fill, slot.track, 0, 0)

        slot.eject = UIUtil.CreateButtonStd(slot, '/widgets02/small', "<LOC UI_Disco0005>Eject From Game", 12, 0)
        slot.eject.label:SetFont(UIUtil.bodyFont, 12)
        LayoutHelpers.AtLeftTopIn(slot.eject, slot, 248, 24)
        slot.eject.OnClick = function(self, modifiers)
            EjectSessionClient(index)
        end

        return slot
    end

    --- As `CreateDialog` above lays out the Connectivity dialog, so this one replaces it where it stood.
    local function CreateRejoinDialog(clients)
        SessionClients.FastInterval()
        GetCursor():Show()

        local group = Group(GetFrame(0))
        group.Depth:Set(GetFrame(0):GetTopmostDepth() + 1)

        local bg = Bitmap(group, UIUtil.UIFile('/scx_menu/panel-brd/panel_brd_m.dds'))
        LayoutHelpers.FillParent(bg, group)
        bg.border = UIUtil.CreateSCXMenuPanelBorder(bg)

        local title = UIUtil.CreateText(bg, "<LOC UI_Disco0000>Connectivity", 18)
        LayoutHelpers.AtTopIn(title, bg, -52)
        LayoutHelpers.AtHorizontalCenterIn(title, group)

        group.slots = {}
        local previous = false
        for index, client in clients do
            local slot = CreateSlot(bg, index, client)
            group.slots[index] = slot
            if previous then
                LayoutHelpers.Below(slot, previous)
            else
                LayoutHelpers.AtTopIn(slot, group)
                LayoutHelpers.AtHorizontalCenterIn(slot, group)
            end
            previous = slot
        end

        group.Width:Set(function() return previous.Width() - 100 end)
        group.Height:Set(function() return previous.Height() * table.getsize(group.slots) - 34 end)
        LayoutHelpers.AtCenterIn(group, GetFrame(0))
        return group
    end

    local function DestroyRejoinDialog()
        if dialog then
            dialog:Destroy()
            dialog = false
            SessionClients.ResetInterval()
        end
    end

    local function UpdateSlot(slot, index, client, armies)
        if IsReturning(client) then
            slot.ping:Hide()
            slot.status:Show()
            slot.track:Show()
            if IsSilent(client) then
                slot.status:SetText(LOCF("<LOC rejoin_0008>No response for %s", ElapsedText(client.rejoinSilent)))
                slot.status:SetColor('FFe24f2d')
                slot.fill:SetSolidColor('ff707070')
                if not slot.silent then
                    slot.silent = true
                    LOG('REJOIN: showing ' .. client.name .. ' as not responding')
                end
            else
                slot.status:SetText(StageText(index, client))
                slot.status:SetColor('FFbadbdb')
                slot.fill:SetSolidColor('ff4fa0e0')
                slot.silent = false
            end
            if IsSilent(client) then
                -- The bar stays where it stopped.
            elseif client.rejoinProgress then
                LayoutHelpers.AtLeftTopIn(slot.fill, slot.track, 0, 0)
                LayoutHelpers.SetWidth(slot.fill, math.max(1, trackWidth * client.rejoinProgress))
            else
                -- No measure: a block that travels, so it can't be read as a percentage.
                local blockWidth = 60
                local travelled = math.mod(GetSystemTimeSeconds() - stageStarts[index], 3) / 3
                LayoutHelpers.AtLeftTopIn(slot.fill, slot.track, (trackWidth - blockWidth) * travelled, 0)
                LayoutHelpers.SetWidth(slot.fill, blockWidth)
            end
            slot.eject:Show()
        else
            slot.status:Hide()
            slot.track:Hide()
            slot.eject:Hide()
            slot.ping:Show()
            if client.connected then
                slot.ping:SetText(LOCF("%s: %d", "<LOC UI_Disco0003>Ping (ms)", client.ping))
                slot.ping:SetColor('FFbadbdb')
            else
                slot.ping:SetText(LOC("<LOC connectivity_0003>Not Connected"))
                slot.ping:SetColor('FFff0000')
            end
        end

        if armies[index] and armies[index].outOfGame then
            slot.state:Show()
            LayoutHelpers.AtRightTopIn(slot.ejectedBy, slot, 34, 4)
        else
            slot.state:Hide()
            LayoutHelpers.AtRightTopIn(slot.ejectedBy, slot, 5, 4)
        end

        local ejectedBy = ''
        for _, by in client.ejectedBy do
            if ejectedBy != '' then
                ejectedBy = ejectedBy .. ', ' .. tostring(by)
            else
                ejectedBy = LOC('<LOC UI_Disco0006>Ejected by') .. ': ' .. tostring(by)
            end
        end
        slot.ejectedBy:SetText(ejectedBy)
    end

    local baseUpdate = Update
    local engineClients = GetSessionClients

    --- What the Connectivity dialog above goes by: it opens on any vote to eject, and a vote
    --- against a returning player shows on their row in this dialog instead.
    function GetSessionClients()
        local clients = engineClients() or {}
        for _, client in clients do
            if IsReturning(client) then
                client.ejectedBy = {}
            end
        end
        return clients
    end

    --- The rest of what opens the Connectivity dialog: see `Update` above.
    local function ConnectivityIsOpen(clients)
        local stillin = {}
        for index, client in clients do
            if client.connected then
                table.insert(stillin, index)
            end
        end
        for _, client in clients do
            if client.quiet > 5000 then
                return true
            end
            if client.connected then
                if not IsReturning(client) and not table.equal(client.ejectedBy, {}) then
                    return true
                end
            elseif not table.equal(table.sorted(client.ejectedBy), stillin) then
                return true
            end
        end
        return false
    end

    function Update()
        baseUpdate()

        local clients = engineClients() or {}
        local anyReturning = false
        local connectivityOpen = ConnectivityIsOpen(clients)

        for index, client in clients do
            local stage = client.rejoinStage
            if stage == 'back' then
                stages[index] = nil
                if not announcedBack[index] then
                    announcedBack[index] = true
                    AnnounceBack(client)
                end
            else
                announcedBack[index] = nil
                if client.connected and stage and not client['local'] then
                    if stages[index] != stage then
                        stages[index] = stage
                        stageStarts[index] = GetSystemTimeSeconds()
                        LOG('REJOIN: showing ' .. client.name .. ' as ' .. stage)
                    end
                else
                    stages[index] = nil
                end
                if IsReturning(client) then
                    anyReturning = true
                end
            end
        end

        if not anyReturning then
            DestroyRejoinDialog()
            return
        end

        if not dialog then
            dialog = CreateRejoinDialog(clients)
        end

        -- Another player can be lost meanwhile, with the Connectivity dialog back where this one stands.
        if dialog.belowTop != connectivityOpen then
            dialog.belowTop = connectivityOpen
            if connectivityOpen then
                LayoutHelpers.AtTopIn(dialog, GetFrame(0), 90)
            else
                LayoutHelpers.AtCenterIn(dialog, GetFrame(0))
            end
        end

        local armies = GetArmiesTable().armiesTable
        for index, client in clients do
            if dialog.slots[index] then
                UpdateSlot(dialog.slots[index], index, client, armies)
            end
        end
    end
end
