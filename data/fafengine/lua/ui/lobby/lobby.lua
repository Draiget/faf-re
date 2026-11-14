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

do
local originalCreateUI = CreateUI
function CreateUI(maxPlayers)
    originalCreateUI(maxPlayers)
    if singlePlayer then return end
    -- The lobby can load before selected UI mods are active as script hooks.
    for _, mod in ipairs(Mods.GetUiMods()) do
        if mod.uid == 'a16bec45-d3ab-4be7-9915-0a43194c83fe' then
            local screen = GUI
            local alert = import(mod.location .. '/readyalert.lua')
            ForkThread(alert.WatchLobby, function()
                if GUI == screen and lobbyComm then
                    return gameInfo.PlayerOptions
                end
            end)
            break
        end
    end
end
end
