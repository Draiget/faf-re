-- The launcher's background battle: AI armies fight on a small map behind the launcher's panels while the camera cuts
-- between their fights. It is a single-player sandbox game (game option FafreMenuBattle) with the player as a watcher;
-- in it the game's HUD is hidden and the launcher is built over the world (the gamemain hook calls OnGameUI). Whatever
-- needs the front end (a lobby, a campaign, a replay, a FAF or server game) first ends the battle: Leave keeps the
-- action, the game ends (ExitGame), and the front end's launcher runs it (TakePending); a FAF match the engine starts
-- asks EndForMatch. Off: Options > Battle behind the launcher, /nomenubattle; on in a test only with /menubattle (the
-- tests' /nomovie turns it off, as it turns off the menu movie). The menu movie stays the fallback.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Prefs = import('/lua/user/prefs.lua')

local kMap = '/maps/SCMP_007/SCMP_007_scenario.lua' -- Open Palms: 10 km, six start spots, land fights in the open
-- Two against two, a rushing and an adaptive AI on each side, one of each faction; FAF's cheating AIs with prebuilt
-- bases, so armies meet within a couple of minutes instead of ten.
local kArmies = {
    { army = 'ARMY_1', team = 2, ai = 'rushcheat', faction = 1 },
    { army = 'ARMY_2', team = 3, ai = 'rushcheat', faction = 3 },
    { army = 'ARMY_3', team = 2, ai = 'adaptivecheat', faction = 2 },
    { army = 'ARMY_4', team = 3, ai = 'adaptivecheat', faction = 4 },
}
local kWatcherArmy = 'ARMY_5'
local kCutSeconds = 9 -- the camera moves to the newest busy place at most this often

-- The action for the front end's launcher is kept across the battle's end in the engine's front-end data (the UI's
-- modules load again in the front end): { method = a Launcher method's name, args = {...} }.
local kPendingKey = 'fafre_battle_pending'
local focus = false   -- the sim's newest busy place
local lastCut = -100
local cuts = 0
local started = false -- this process started a battle already (the first one shows the loading screen once)

--- Whether the launcher should show a battle behind it.
function Wanted()
    if HasCommandLineArg('/nomenubattle') then
        return false
    end
    if HasCommandLineArg('/menubattle') then
        return true
    end
    if HasCommandLineArg('/nomovie') then
        return false
    end
    local value = Prefs.GetOption('fafre_menu_battle')
    return value ~= false and value ~= 0 and value ~= 'off'
end

--- Whether the game running now is the launcher's battle.
function InBattle()
    local active = rawget(_G, 'SessionIsActive')
    if not active or not active() then
        return false
    end
    local ok, info = pcall(SessionGetScenarioInfo)
    local options = ok and info and info.Options or {}
    return options.FafreMenuBattle == true or options.FafreMenuBattle == 'true'
end

--- Starts the battle (from the front end's launcher). False when it can't.
function Start()
    local scenario = import('/lua/ui/maputil.lua').LoadScenario(kMap)
    if not scenario then
        WARN('MENU BATTLE: the map ' .. kMap .. ' is missing')
        return false
    end
    scenario.Options = {
        FogOfWar = 'none', NoRushOption = 'Off', PrebuiltUnits = 'On', Difficulty = 2, DoNotShareUnitCap = true,
        CheatMult = '2.0', BuildMult = '2.0',
        Timeouts = -1, GameSpeed = 'normal', UnitCap = '500', Victory = 'sandbox', CheatsEnabled = 'true',
        CivilianAlliance = 'enemy', TeamShareOverflow = 'enabled', Share = 'ShareUntilDeath',
        FafreMenuBattle = true,
    }
    local GetDefaultPlayerOptions = import('/lua/ui/lobby/lobbycomm.lua').GetDefaultPlayerOptions
    local teamInfo = {}
    for index, entry in kArmies do
        local ai = GetDefaultPlayerOptions('AI: ' .. entry.ai)
        ai.Human = false
        ai.AIPersonality = entry.ai
        ai.ArmyName = entry.army
        ai.Faction = entry.faction
        ai.Team = entry.team
        ai.StartSpot = index
        ai.PlayerColor = index
        ai.ArmyColor = index
        table.insert(teamInfo, ai)
    end
    local playerName = Prefs.GetFromCurrentProfile('Name') or 'Player'
    local watcher = GetDefaultPlayerOptions(playerName)
    watcher.Human = true
    watcher.ArmyName = kWatcherArmy
    watcher.Faction = 1
    watcher.Team = 1
    watcher.StartSpot = table.getn(kArmies) + 1
    watcher.PlayerColor = 6
    watcher.ArmyColor = 6
    table.insert(teamInfo, watcher)
    focus = false
    cuts = 0
    started = true
    LOG('MENU BATTLE: starting on ' .. kMap)
    LaunchSinglePlayerSession({ playerName = playerName, createReplay = false, scenarioInfo = scenario,
        teamInfo = teamInfo, scenarioMods = import('/lua/mods.lua').GetCampaignMods(scenario) })
    return true
end

--- In the battle: keeps launcher:<method>(unpack(args)) for the front end's launcher and ends the battle (true then);
--- outside it false, and the caller goes on.
function Leave(method, args)
    if not InBattle() then
        return false
    end
    SetFrontEndData(kPendingKey, { method = method, args = args or {} })
    LOG('MENU BATTLE: ending it for ' .. tostring(method))
    ExitGame()
    return true
end

--- The kept action, once (the front end's launcher asks): { method, args } or nil.
function TakePending()
    local ok, action = pcall(GetFrontEndData, kPendingKey)
    if ok and type(action) == 'table' and action.method then
        SetFrontEndData(kPendingKey, false)
        return action
    end
    return nil
end

--- The engine: a FAF match is about to start; the battle goes first.
function EndForMatch()
    if InBattle() then
        SetFrontEndData(kPendingKey, false)
        LOG('MENU BATTLE: ending it for a FAF match')
        ExitGame()
    end
end

--- The sim's busiest place (UserSync).
function OnFocus(spot)
    focus = spot
end

--- How many camera cuts this battle had (tests).
function Cuts()
    return cuts
end

--- The camera: on the newest busy place, from a slowly turning heading, a little nearer for a fight.
local function Cut(seconds)
    if not focus then
        return
    end
    local camera = GetCamera('WorldCamera')
    if not camera then
        return
    end
    local terrain = rawget(_G, 'GetTerrainHeight')
    local height = terrain and terrain(focus.x, focus.z) or 0
    cuts = cuts + 1
    LOG(string.format('MENU BATTLE: camera to %.0f, %.0f (%d units%s)', focus.x, focus.z, focus.units or 0,
        focus.fight and ', a fight' or ''))
    local heading = math.mod(cuts * 0.9, 6.28)
    local zoom = focus.fight and 38 or 60
    camera:MoveTo(Vector(focus.x, height, focus.z), { heading, 0.75, 0 }, zoom, seconds)
end

local function Director()
    WaitSeconds(1)
    local GameMain = import('/lua/ui/game/gamemain.lua')
    local hideHud = rawget(GameMain, 'FafreBattleHideHud')
    local ticks = 0
    while InBattle() do
        -- The game's HUD stays hidden (its opening animations show parts again in the first seconds).
        ticks = ticks + 1
        if hideHud and ticks <= 20 and hideHud() then
            LOG('MENU BATTLE: the HUD showed again; hidden')
        end
        local now = GetGameTimeSeconds()
        if focus and now - lastCut >= kCutSeconds then
            lastCut = now
            Cut(cuts == 0 and 0 or 4)
        end
        WaitSeconds(1)
    end
end

--- In the battle's game UI (the gamemain hook): the HUD goes, the launcher comes over the world, the camera starts.
function OnGameUI()
    local Launcher = import('/fafengine/modules/lua/ui/launcher/launcher.lua')
    local ok, why = pcall(Launcher.CreateUI, nil)
    if not ok then
        WARN('MENU BATTLE: the launcher failed over the battle: ' .. tostring(why))
        ExitGame()
        return
    end
    -- Over the game's own controls (some draw above a plain screen group), under in-game dialogs (5000).
    local launcher = Launcher.Current()
    if launcher and launcher.root then
        local frame = GetFrame(0)
        launcher.root.Depth:Set(function() return frame.Depth() + 1000 end)
    end
    lastCut = -100
    ForkThread(Director)
    LOG('MENU BATTLE: the launcher is over the battle')
end
