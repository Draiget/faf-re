-- faf-re: the interface scale (the `ui_scale` option) without a restart, and following the display's scale.
--
-- FAF's Lua reads `ui_scale` once, when /lua/maui/layouthelpers.lua loads, into a local of that module (and of
-- effecthelpers.lua and hotstats.lua). Most layout helpers read that local when a position is computed (AtLeftIn,
-- Below, a bitmap's width), not when the control is built, so a new scale reaches them when every computed position
-- is worked out again: `Apply` sets the new scale, marks every computed value of every control dirty, and in a game
-- runs the HUD's layout pass again (what the layout key does), for the sizes the layouts set once. The hooks of
-- layouthelpers.lua and text.lua make fixed sizes and font sizes computed values, so they follow too.
--
-- "Match the display" (option `ui_scale_auto`): `ui_scale` becomes the step nearest the scale of the display the game
-- window is on (Windows' Scale setting: 150 % gives 1.5), at startup and whenever it changes (the engine calls
-- uimain.lua's OnDisplayScaleChanged). It starts on for players whose `ui_scale` is unset or 100 %, and goes off when
-- the player picks another scale by hand.
--
-- Engine functions are looked up with rawget: FAF's Lua errors on reading a global that doesn't exist.

local Prefs = import('/lua/user/prefs.lua')

--- The steps FAF's options screen offers for `ui_scale`.
Steps = { 0.8, 1.0, 1.25, 1.5, 1.75, 2.0 }

--- The step nearest `scale`; the smaller one when it lies half way.
function Nearest(scale)
    local best = 1.0
    local bestDistance = nil
    for _, step in Steps do
        local distance = math.abs(step - scale)
        if bestDistance == nil or distance < bestDistance - 0.0001 then
            best = step
            bestDistance = distance
        end
    end
    return best
end

--- The scale of the display the game window is on, or nil on an engine without `GetDisplayScale`.
function DisplayScale()
    local get = rawget(_G, 'GetDisplayScale')
    if not get then
        return nil
    end
    local ok, scale = pcall(get)
    if ok and type(scale) == 'number' and scale > 0 then
        return scale
    end
    return nil
end

local function Options()
    return Prefs.GetFromCurrentProfile('options') or {}
end

-- Writes one option of the current profile. Nothing without a profile: FAF's SetToCurrentProfile errors then.
local function SetOption(key, value)
    if not Prefs.GetCurrentProfile() then
        return
    end
    local options = Options()
    if options[key] == value then
        return
    end
    options[key] = value
    Prefs.SetToCurrentProfile('options', options)
    -- Saved at once, as the options screen saves, so a crash doesn't lose it.
    local save = rawget(_G, 'SavePreferences')
    if save then
        save()
    end
end

--- Whether a profile that never had the choice starts following the display: when its `ui_scale` is unset or 100 %,
--- the size nobody has to pick.
function FollowsByDefault()
    local scale = Options().ui_scale
    return scale == nil or scale == 1.0
end

--- Whether `ui_scale` follows the display.
function FollowsDisplay()
    local follow = Options().ui_scale_auto
    if follow == nil then
        return FollowsByDefault()
    end
    return follow == true
end

--- The scale the interface starts with, called when layouthelpers.lua loads (in each Lua state: the menus' and a
--- game's). Following the display, it writes `ui_scale` first, so the modules that read it after this see the same.
function StartupScale()
    local options = Options()
    if options.ui_scale_auto == nil then
        SetOption('ui_scale_auto', FollowsByDefault())
    end
    if FollowsDisplay() then
        local display = DisplayScale()
        if display then
            local scale = Nearest(display)
            SetOption('ui_scale', scale)
            return scale
        end
    end
    return Options().ui_scale or 1
end

local layoutFields = { 'Left', 'Top', 'Right', 'Bottom', 'Width', 'Height' }

-- Marks one lazy var dirty when it is computed, so it is worked out again with the new scale. Slot 4 is the compute
-- function in FAF's lazyvar.lua.
local function Recompute(var)
    if type(var) == 'table' then
        local compute = rawget(var, 4)
        if compute then
            var:SetFunction(compute)
        end
    end
end

local function Refresh(control)
    for _, field in layoutFields do
        Recompute(rawget(control, field))
    end
    local font = rawget(control, '_font')
    if type(font) == 'table' then
        Recompute(rawget(font, '_pointsize'))
    end
    -- ApplyFunction calls the function with the control itself, then with each of its children.
    control:ApplyFunction(function(child)
        if child ~= control then
            Refresh(child)
        end
    end)
end

--- Runs `work` (a layout pass, a resize) with the selection cleared, as FAF's layout key does, and selects the same
--- units again a frame later. The construction panel rebuilds for a selection change seen on a later frame (clearing
--- and selecting again in one frame is no change to it), so it is laid out anew for the window's size and scale.
function KeepSelection(work)
    local selected = GetSelectedUnits()
    if selected and table.getn(selected) > 0 then
        SelectUnits(nil)
    end
    work()
    if selected and table.getn(selected) > 0 then
        ForkThread(function()
            WaitSeconds(0)
            local alive = {}
            for _, unit in selected do
                if not unit:IsDead() then
                    table.insert(alive, unit)
                end
            end
            if table.getn(alive) > 0 then
                SelectUnits(alive)
            end
        end)
    end
end

-- A game's interface is up (not the menus, not the loading screen). Only then is gamemain.lua's layout pass run;
-- importing gamemain.lua in the menus' Lua state would build parts of a game's interface there.
local function GameUiActive()
    return SessionIsActive() and not WorldIsLoading()
end

-- What the main menu shows, as the hook of /lua/ui/menus/main.lua reports it.
local mainMenuVisible = false
local optionsFromMainMenu = false

--- The main menu shows (true after it is built or shown again, false when it hides for another screen).
function SetMainMenuVisible(visible)
    mainMenuVisible = visible
end

--- The options screen was opened from the main menu (until the menu shows again).
function SetOptionsFromMainMenu(fromMenu)
    optionsFromMainMenu = fromMenu
end

-- The main menu works out some sizes once (menus/main.lua: its height from the first button, its column's top where
-- the slide-in stopped), so after a scale change it is built again, as a fresh start at that scale builds it. Only
-- when it, or the options opened from it, is what shows: behind a lobby or the replays a rebuild would close them.
local function RebuildMainMenu()
    if SessionIsActive() or not (mainMenuVisible or optionsFromMainMenu) then
        return false
    end
    local start = rawget(_G, 'EngineStartFrontEndUI')
    if not start then
        return false
    end
    LOG('UI scale: building the main menu again')
    optionsFromMainMenu = false
    start()
    return true
end

--- Sets the interface to `scale` now, without a restart.
function Apply(scale)
    local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
    if math.abs(LayoutHelpers.GetPixelScaleFactor() - scale) < 0.0001 then
        return
    end
    LOG('UI scale: ' .. tostring(LayoutHelpers.GetPixelScaleFactor()) .. ' -> ' .. tostring(scale))
    LayoutHelpers.SetPixelScaleFactor(scale)
    -- A display scale can arrive while the game starts, before the UI layer exists (a Retina display reports 2.0
    -- then): GetNumRootFrames raises until it does. The interface built later reads the layout factor set above,
    -- and effecthelpers.lua, which needs a root frame to load, reads the profile's ui_scale when it first does.
    if not pcall(GetNumRootFrames) then
        return
    end
    local EffectHelpers = import('/lua/maui/effecthelpers.lua')
    if rawget(EffectHelpers, 'SetPixelScaleFactor') then
        EffectHelpers.SetPixelScaleFactor(scale)
    end

    for head = 1, GetNumRootFrames() do
        Refresh(GetFrame(head - 1))
    end

    if GameUiActive() then
        local UIUtil = import('/lua/ui/uiutil.lua')
        local gameMain = import('/lua/ui/game/gamemain.lua')
        KeepSelection(function()
            gameMain.SetLayout(UIUtil.currentLayout)
        end)
    else
        RebuildMainMenu()
    end
end

--- The options screen's `set` of `ui_scale`: the player chose `scale`. Runs a frame later, after the options screen
--- has saved its table (which would overwrite a change made now).
function OnChosen(scale)
    ForkThread(function()
        WaitSeconds(0)
        if FollowsDisplay() then
            local display = DisplayScale()
            if display and Nearest(display) ~= scale then
                SetOption('ui_scale_auto', false)
            end
        end
        Apply(scale)
    end)
end

--- The options screen's `set` of `ui_scale_auto`. Turned on together with a new UI Scale in one apply, following wins:
--- OnChosen's thread (forked first) turns it off for the hand-picked scale, and this one turns it on again.
function OnFollowChosen(follow)
    ForkThread(function()
        WaitSeconds(0)
        if follow then
            SetOption('ui_scale_auto', true)
            local display = DisplayScale()
            if display then
                local scale = Nearest(display)
                SetOption('ui_scale', scale)
                Apply(scale)
            end
        end
    end)
end

--- The display scale changed (the window went to another display, or the system's scale changed).
function OnDisplayScaleChanged(display)
    if not FollowsDisplay() then
        return
    end
    local scale = Nearest(display)
    SetOption('ui_scale', scale)
    Apply(scale)
end
