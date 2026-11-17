-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/menus/main.lua.
--
-- The interface scale without a restart (/fafengine/modules/lua/ui/uiscale.lua): the main menu keeps sizes it worked
-- out once (its height from the first button's height, the column's top where its slide-in stopped), so a new scale
-- leaves it half resized. A scale chosen in the options opened from the main menu therefore builds the menu again
-- (uiscale.lua's Apply calls EngineStartFrontEndUI), as a fresh start at that scale would. Opened anywhere else (a
-- lobby, a game), the options apply the scale in place.
--
-- uiscale.lua is told whether the main menu shows (after CreateUI and MenuShow, not after MenuHide) and whether the
-- options were opened from it; a scale change then (from the options, or the window moving to a display with another
-- scale) builds the menu again. With the menu hidden behind a lobby, the replays or the mod manager it doesn't, as
-- that would close them. ButtonOptions, MenuShow and MenuHide are module globals each CreateUI call defines anew,
-- so they are wrapped after it.

do
    local OldCreateUI = CreateUI
    function CreateUI()
        OldCreateUI()
        local env = getfenv(1)
        local UiScale = import('/fafengine/modules/lua/ui/uiscale.lua')
        local buttonOptions = rawget(env, 'ButtonOptions')
        if buttonOptions then
            rawset(env, 'ButtonOptions', function()
                UiScale.SetOptionsFromMainMenu(true)
                buttonOptions()
            end)
        end
        local menuShow = rawget(env, 'MenuShow')
        if menuShow then
            rawset(env, 'MenuShow', function()
                UiScale.SetOptionsFromMainMenu(false)
                UiScale.SetMainMenuVisible(true)
                menuShow()
            end)
        end
        local menuHide = rawget(env, 'MenuHide')
        if menuHide then
            rawset(env, 'MenuHide', function(callback)
                UiScale.SetMainMenuVisible(false)
                menuHide(callback)
            end)
        end
        UiScale.SetMainMenuVisible(true)
    end
end
