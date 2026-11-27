-- faf-re hook of FAF's lua/ui/lobby/lobby.lua (plan WP17.6): in a lobby a tournament organiser runs on a game server,
-- the screen shows what the organiser set and changes nothing. A player chats, readies up and leaves; nobody kicks,
-- moves, starts the game or changes an option, faction, colour or team. The server drops such requests anyway
-- (src/server/LobbyRelay.cpp); this keeps every screen showing the same lobby. The engine sets the global
-- ServerLobbyControl to 'organiser' before the lobby's Lua runs (src/moho/app/ServerLobbyUi.cpp); elsewhere it is nil,
-- and this hook does nothing. The engine appends this file to FAF's (SCR_LuaDoFileConcat), so FAF's file-level locals
-- GUI and UpdateGame are in scope here. FAF's Lua errors on reading an undefined global: if a later lobby.lua renames
-- either, the pcalls below leave a warning in the log instead of a broken lobby.
do
    local saidLocked = false
    local function LockLobbyScreen()
        if rawget(_G, 'ServerLobbyControl') ~= 'organiser' or not GUI then
            return
        end
        local disabled = 0
        local function Off(control)
            if control and control.Disable then
                control:Disable()
                disabled = disabled + 1
            end
        end
        Off(GUI.launchGameButton)
        Off(GUI.gameoptionsButton)
        Off(GUI.becomeObserver)
        Off(GUI.AIFillButton)
        Off(GUI.AIClearButton)
        Off(GUI.restrictedUnitsOrPresetsBtn)
        Off(GUI.loadButton)
        -- The observer panel's lobby-changing buttons (lobby.lua: default options, random map, close empty slots, auto
        -- teams, auto balance) and the AI fill choosers. The CPU test, Settings, patch notes, briefing and Exit stay.
        Off(GUI.defaultOptions)
        Off(GUI.randMap)
        Off(GUI.closeEmptySlots)
        Off(GUI.autoTeams)
        Off(GUI.PenguinAutoBalance)
        Off(GUI.AIFillCombo)
        Off(GUI.TeamCountSelector)
        if GUI.slots then
            for _, slot in GUI.slots do
                Off(slot.name)
                Off(slot.faction)
                Off(slot.color)
                Off(slot.team)
            end
        end
        if not saidLocked then
            saidLocked = true
            LOG('faf-re lobby hook (WP17.6): an organiser runs this lobby; ' .. disabled .. ' controls are read-only')
        end
    end

    local function Lock()
        local locked, why = pcall(LockLobbyScreen)
        if not locked then
            WARN('faf-re lobby hook (WP17.6): ' .. tostring(why))
        end
    end

    -- The host's HostUtils.RefreshButtonEnabledness turns options, map, teams and launch back on whenever someone's
    -- readiness changes; HostUtils is made when a lobby is, so it's wrapped the first time the lobby refreshes.
    local function WrapHostRefresh()
        if HostUtils and type(HostUtils.RefreshButtonEnabledness) == 'function' and not rawget(HostUtils, 'FafReLocked') then
            local OriginalRefresh = HostUtils.RefreshButtonEnabledness
            HostUtils.RefreshButtonEnabledness = function(...)
                local result = OriginalRefresh(unpack(arg))
                Lock()
                return result
            end
            rawset(HostUtils, 'FafReLocked', true)
        end
    end

    local hooked, problem = pcall(function()
        local OriginalUpdateGame = UpdateGame
        if type(OriginalUpdateGame) ~= 'function' then
            error('UpdateGame is not a function here')
        end
        UpdateGame = function(...)
            local result = OriginalUpdateGame(unpack(arg))
            pcall(WrapHostRefresh)
            Lock()
            return result
        end
        -- SetSlotInfo turns a player's own colour, faction and team back on whenever their slot is drawn.
        local OriginalSetSlotInfo = SetSlotInfo
        if type(OriginalSetSlotInfo) == 'function' then
            SetSlotInfo = function(...)
                local result = OriginalSetSlotInfo(unpack(arg))
                Lock()
                return result
            end
        end
    end)
    if not hooked then
        WARN('faf-re lobby hook (WP17.6) not installed: ' .. tostring(problem))
    end
end

--- Engine addition (plan WP2.14): on a game server a launch is a request the server may refuse. FAF's TryLaunch
--- flattens gameInfo (GameInfo.Flatten) and leaves windowed mode before it sends the launch, as a launch in a
--- peer-to-peer lobby always goes ahead. Until the server answers, the lobby keeps running (its ping thread walks
--- gameInfo.PlayerOptions:pairs() every second), so on a game server the host's game info is made whole again as soon
--- as the launch is sent, as a joiner's lobby rebuilds the host's flat game info (GameInfo.CreateGameInfo).
do
    local function RestoreGameInfo()
        if gameInfo and gameInfo.PlayerOptions and gameInfo.PlayerOptions.pairs == nil then
            gameInfo = GameInfo.CreateGameInfo(LobbyComm.maxPlayerSlots, gameInfo)
        end
    end
    local wrapped, problem = pcall(function()
        local launch = TryLaunch
        if type(launch) ~= 'function' then
            error('TryLaunch is not a function here')
        end
        TryLaunch = function(skipNoObserversCheck)
            launch(skipNoObserversCheck)
            if rawget(_G, 'ServerLobbySession') then
                local restored, why = pcall(RestoreGameInfo)
                if not restored then
                    WARN('faf-re lobby (WP2.14): the game info was not rebuilt after the launch: ' .. tostring(why))
                end
            end
        end
    end)
    if not wrapped then
        WARN('faf-re lobby (WP2.14): ' .. tostring(problem))
    end

    --- The game server refused the launch (`ELobbySignal::LaunchRefused`, sent to everyone in the lobby): back into the
    --- lobby window (the host's TryLaunch and a joiner's `Launch` handler left it), and the reason in the chat.
    function ServerLaunchRefused(text)
        local restored, why = pcall(function()
            RestoreGameInfo()
            SetWindowedLobby(true)
            UpdateGame()
        end)
        if not restored then
            WARN('faf-re lobby (WP2.14): the lobby was not restored after a refused launch: ' .. tostring(why))
        end
        AddChatText(text)
    end
end

--- Engine addition (in-game launcher plan, WP4): the in-game launcher's own test (FAF_ONLINE_AUTOTEST, set only by
--- that test) ticks the host's ready box and presses Launch here, as a player would (FAF's TryLaunch wants every human
--- ready, the host too); nothing else calls it. True when it pressed.
function FafReTestPressLaunch()
    if not (GUI and GUI.launchGameButton and GUI.launchGameButton.OnClick and gameInfo and GUI.slots) then
        return false
    end
    for slot, player in gameInfo.PlayerOptions:pairs() do
        local row = GUI.slots[slot]
        if player.OwnerID == localPlayerID and not player.Ready and row and row.ready then
            row.ready:SetCheck(true)
        end
    end
    GUI.launchGameButton.OnClick(GUI.launchGameButton)
    return true
end

--- Engine addition (in-game launcher, WP5b): faf-re's lobby screen (/fafengine/modules/lua/ui/lobby/lobbyview.lua)
--- draws over this lobby. FafReLobbyApi is all it touches: reads of this file's state and the calls FAF's own
--- controls make, so the lobby's logic, network and host rules stay FAF's. Built after CreateUI; any error leaves
--- FAF's screen showing. Chat lines go to both screens.
do
    local api = {}
    api.GameInfo = function() return gameInfo end
    -- The lobby's connection while it is alive: FAF's ConnectionFailed and Ejected destroy it (its methods go)
    -- before they clear lobbyComm, and the screen may paint in between.
    local function Comm()
        return lobbyComm and lobbyComm.IsHost and lobbyComm or nil
    end
    api.IsHost = function() return Comm() and Comm():IsHost() or false end
    api.HostID = function() return hostID end
    api.LocalPlayerID = function() return localPlayerID end
    api.LocalSlot = function() return localPlayerID and FindSlotForID(localPlayerID) or nil end
    api.IsSinglePlayer = function() return singlePlayer end
    api.GameName = function() return gameName or '' end
    api.NumSlots = function() return numOpenSlots end
    api.GUI = function() return GUI end
    api.IsColorFree = function(index, slot) return IsColorFree(index, slot) end
    api.ShowMapPositions = function(control, scenario) ShowMapPositions(control, scenario) end
    api.ConfigureMapListeners = function(control, scenario) ConfigureMapListeners(control, scenario) end

    --- The slot's menu as FAF's name control has it (SetSlotInfo, ClearSlotInfo): nothing on your own slot.
    api.SlotMenu = function(slot)
        local hostKey = api.IsHost() and 'host' or 'client'
        local player = gameInfo.PlayerOptions[slot]
        if player then
            if player.Human and IsLocallyOwned(slot) then
                return nil
            end
            return GetSlotMenuTables(player.Human and 'player' or 'ai', hostKey, slot)
        end
        local state = 'open'
        if gameInfo.ClosedSlots[slot] and gameInfo.SpawnMex[slot] and gameInfo.AdaptiveMap then
            state = 'closed_spawn_mex'
        elseif gameInfo.ClosedSlots[slot] then
            state = 'closed'
        end
        return GetSlotMenuTables(state, hostKey)
    end
    api.SlotAction = function(slot, key, text) DoSlotBehavior(slot, key, text) end

    --- A new map, as the map dialog's selectBehavior does it for the host (no other option changed).
    api.SetMap = function(scenarioFile)
        if not api.IsHost() then
            return
        end
        local options = {}
        if gameInfo.GameOptions.ScenarioFile and string.lower(scenarioFile) ~= string.lower(gameInfo.GameOptions.ScenarioFile) then
            local scenario = MapUtil.LoadScenario(gameInfo.GameOptions.ScenarioFile)
            if scenario and scenario.options then
                for _, value in scenario.options do
                    gameInfo.GameOptions[value.key] = nil
                end
            end
        end
        options['ScenarioFile'] = scenarioFile
        ClearBadMapFlags()
        HostUtils.UpdateMods()
        SetGameOptions(options)
    end
    api.SetOption = function(key, value)
        if not api.IsHost() then
            return
        end
        SetGameOption(key, value)
        if key == 'AutoTeams' then
            AssignAutoTeams()
        end
    end
    api.Launch = function()
        if GUI.launchGameButton then
            GUI.launchGameButton.OnClick(GUI.launchGameButton)
        end
    end
    api.ToggleReady = function()
        local slot = localPlayerID and FindSlotForID(localPlayerID)
        local row = slot and GUI.slots[slot]
        if row and row.ready then
            row.ready:SetCheck(not gameInfo.PlayerOptions[slot].Ready)
        end
    end
    --- What FAF's chat field does with a line (commands such as /whisper included).
    api.Chat = function(text)
        if GUI.chatEdit and GUI.chatEdit.OnEnterPressed then
            GUI.chatEdit:SetText(text)
            GUI.chatEdit.OnEnterPressed(GUI.chatEdit, text)
            GUI.chatEdit:SetText('')
        end
    end
    --- A player's CPU benchmark (CPU_Benchmarks, the score FAF's slot bar shows; lower is faster), or nil.
    api.Cpu = function(name) return name and CPU_Benchmarks[name] or nil end
    --- The ping to a peer in milliseconds (lobbyComm's peers), or nil.
    api.Ping = function(id)
        if not Comm() or not id then
            return nil
        end
        for _, peer in Comm():GetPeers() do
            if peer.id == id and peer.ping then
                return math.floor(peer.ping)
            end
        end
        return nil
    end
    --- A peer as the lobby sees it (lobbyComm:GetPeers: id, name, status 'Established' once linked, ping,
    --- establishedPeers), or nil.
    api.Peer = function(id)
        if not Comm() or not id then
            return nil
        end
        for _, peer in Comm():GetPeers() do
            if peer.id == id then
                return peer
            end
        end
        return nil
    end
    --- The sim mods of the game, each a mod table (name, uid...).
    api.GameMods = function() return Mods.GetGameMods(gameInfo.GameMods) or {} end
    --- The mod manager as FAF opens it: the host picks the game's mods, everyone else sees them and picks UI mods.
    api.OpenMods = function()
        if api.IsHost() then
            import('/lua/ui/lobby/modsmanager.lua').CreateDialog(GUI, true, availableMods, OnModsChanged)
        elseif GUI.gameoptionsButton then
            GUI.gameoptionsButton.OnClick(GUI.gameoptionsButton)
        end
    end
    --- FAF's unit manager: the host changes the restrictions as the map dialog's Unit Manager does (they go out with
    --- SetGameOptions); everyone else sees them, as FAF's client button shows them.
    api.OpenRestrictions = function()
        local unitsManager = import('/lua/ui/lobby/unitsmanager.lua')
        if api.IsHost() then
            unitsManager.CreateDialog(GUI, gameInfo.GameOptions.RestrictedCategories, function(restricted)
                SetGameOptions({ RestrictedCategories = restricted })
            end, function() end, true)
        else
            unitsManager.CreateDialog(GUI, gameInfo.GameOptions.RestrictedCategories, function() end, function() end, false)
        end
    end
    --- FAF's presets dialog (host only).
    api.OpenPresets = function()
        if api.IsHost() and not singlePlayer then
            import('/lua/ui/lobby/presets.lua').CreateUI(GUI)
        end
    end
    --- FAF's own map and options dialog (the host's): every option page, presets and more.
    api.OpenAdvanced = function()
        if api.IsHost() and GUI.gameoptionsButton then
            GUI.gameoptionsButton.OnClick(GUI.gameoptionsButton)
        end
    end
    FafReLobbyApi = api

    local wrapped, problem = pcall(function()
        local createUI = CreateUI
        if type(createUI) ~= 'function' then
            error('CreateUI is not a function here')
        end
        CreateUI = function(maxPlayers)
            createUI(maxPlayers)
            local ok, why = pcall(function()
                local view = import('/fafengine/modules/lua/ui/lobby/lobbyview.lua')
                if view.Wanted() then
                    view.Create(api)
                end
            end)
            if not ok then
                WARN('faf-re lobby: our screen failed to build, FAF\'s shows: ' .. tostring(why))
            end
        end
        -- A lost game (the host left, the connection failed, a kick) is said on our screen when it shows, instead of
        -- FAF's dialog under it; its OK leaves the lobby as FAF's OK does.
        local initLobbyComm = InitLobbyComm
        if type(initLobbyComm) == 'function' then
            InitLobbyComm = function(a, b, c, d, e)
                initLobbyComm(a, b, c, d, e)
                local comm = lobbyComm
                for _, entry in { { 'ConnectionFailed', 'ConnectionFailed' }, { 'Ejected', 'Ejected' } } do
                    local event, stringKey = entry[1], entry[2]
                    local original = comm and comm[event]
                    if original then
                        comm[event] = function(self, reason)
                            original(self, reason)
                            pcall(function()
                                local text = LOCF(Strings[stringKey], Strings[reason] or reason)
                                local view = import('/fafengine/modules/lua/ui/lobby/lobbyview.lua')
                                if view.OnClosed(text, ReturnToMenu) and GUI.connectionFailedDialog then
                                    GUI.connectionFailedDialog:Destroy()
                                    GUI.connectionFailedDialog = false
                                end
                            end)
                        end
                    end
                end
            end
        end
        local addChatText = AddChatText
        if type(addChatText) == 'function' then
            AddChatText = function(text, playerID, scrollToBottom)
                addChatText(text, playerID, scrollToBottom)
                pcall(function()
                    local name = playerID and FindNameForID(playerID) or nil
                    local color = nil
                    for _, player in gameInfo.PlayerOptions:pairs() do
                        if player.OwnerID == playerID and player.Human then
                            color = gameColors.PlayerColors[player.PlayerColor]
                        end
                    end
                    import('/fafengine/modules/lua/ui/lobby/lobbyview.lua').OnChat(text, name, color)
                end)
            end
        end
    end)
    if not wrapped then
        WARN('faf-re lobby: not installed: ' .. tostring(problem))
    end
end
