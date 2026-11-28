-- Engine hook (data/fafengine, appended to FAF's /lua/ui/game/tabs.lua, so this file's locals are FAF's): the game's
-- menu tab opens the menu in the launcher's look (/fafengine/modules/lua/ui/game/gamemenu.lua) with FAF's own entries
-- and actions, and its Options and Key bindings open the launcher's options page. /fafmenu keeps FAF's drop-down.
do
    local fafBuildContent = BuildContent
    local fafCollapseWindow = CollapseWindow
    local fafOptions = actions.Options
    local fafKeyBindings = actions.KeyBindings

    local function Wanted()
        return not HasCommandLineArg('/fafmenu')
    end

    local function MenuTab()
        for _, tab in (controls.tabs or {}) do
            if tab.Data and tab.Data.content == 'main' then
                return tab
            end
        end
        return nil
    end

    -- Which of FAF's menus this game has, as FAF's BuildContent picks it.
    local function Entries()
        local tableID = 'singlePlayer'
        if HasCommandLineArg('/gpgnet') then
            tableID = 'gpgnet'
        elseif SessionIsMultiplayer() then
            tableID = 'lan'
        elseif GameMain.GetReplayState() then
            tableID = 'replay'
        end
        local list = {}
        local ranked = sessionInfo and sessionInfo.Options and sessionInfo.Options.Ranked
        for _, entry in (menus.main[tableID] or {}) do
            if not ranked or not entry.hideWhenRanked then
                table.insert(list, entry)
            end
        end
        return list
    end

    function BuildContent(contentID)
        if contentID == 'main' and Wanted() then
            local ok, why = pcall(function()
                local GameMenu = import('/fafengine/modules/lua/ui/game/gamemenu.lua')
                local tab = MenuTab()
                local menu = GameMenu.Open(Entries(), actions, function()
                    local menuTab = MenuTab()
                    if menuTab then
                        menuTab:SetCheck(false, true)
                    end
                end, gameOver)
                if tab then
                    tab:SetCheck(menu and true or false, true)
                end
            end)
            if ok then
                return
            end
            WARN('GAME MENU: falling back to FAF\'s menu: ' .. tostring(why))
        end
        return fafBuildContent(contentID)
    end

    function CollapseWindow(callback)
        local ok, GameMenu = pcall(import, '/fafengine/modules/lua/ui/game/gamemenu.lua')
        local menu = ok and GameMenu.Current()
        if menu then
            menu:Close()
            if callback then
                callback()
            end
            return
        end
        return fafCollapseWindow(callback)
    end

    actions.Options = function()
        if Wanted() and import('/fafengine/modules/lua/ui/game/gamemenu.lua').OpenOptions() then
            return
        end
        fafOptions()
    end
    actions.KeyBindings = function()
        if Wanted() and import('/fafengine/modules/lua/ui/game/gamemenu.lua').OpenOptions('keys') then
            return
        end
        fafKeyBindings()
    end
end
