-- The in-game menu in the launcher's look: FAF's own entries and actions (lua/ui/game/tabs.lua's menus and actions,
-- handed in by the tabs hook) as a dialog over the game instead of the tab's drop-down of textured buttons. Options
-- and Key bindings open the launcher's options page (optionspage.lua, its Key bindings tab) in a dialog, so a game
-- shows the same settings screen as the launcher. FAF's question dialogs ("Are you sure you'd like to quit?") stay as
-- they are. /fafmenu keeps FAF's own menu.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local Anim = import('/fafengine/modules/lua/ui/launcher/anim.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local current = false
local currentOptions = false

-- How each of FAF's actions looks here: the leaving ones in red, Close as a quiet one at the end.
local kDanger = { EndSPGame = true, EndMPGame = true, ExitSPGame = true, ExitMPGame = true }
local kIcons = { Save = 'download', Load = 'upload', LoadReplay = 'replays', Options = 'settings', KeyBindings = 'keyboard',
    Customiser = 'bell', ShowObj = 'info', RestartGame = 'refresh', RestartReplay = 'refresh', RehostGame = 'refresh',
    EndSPGame = 'logout', EndMPGame = 'logout', ExitSPGame = 'close', ExitMPGame = 'close', Return = 'arrowLeft' }

--- Esc runs `handler` while the menu or dialog shows; nil gives Esc back (FAF's uimain keeps one handler; the game's
--- strict globals make a missing name an error, so every name is looked up with rawget).
local function Escape(handler)
    local ok, UiMain = pcall(import, '/lua/ui/uimain.lua')
    local set = ok and rawget(UiMain, 'SetEscapeHandler')
    if set then
        set(handler)
    end
end

--- A layer over the whole game, above its HUD and overlays (the unit preview's panel, chat), for one dialog: the
--- launcher's Modal sits 500 above its root, which in a game is under some of FAF's own controls.
local function Layer()
    local frame = GetFrame(0)
    local layer = Group(frame, 'game menu layer')
    LayoutHelpers.FillParent(layer, frame)
    layer.Width:Set(function() return layer.Right() - layer.Left() end)
    layer.Height:Set(function() return layer.Bottom() - layer.Top() end)
    layer.Depth:Set(function() return frame.Depth() + 5000 end)
    layer:DisableHitTest()
    return layer
end

--- The menu on screen (tests), or false.
function Current()
    return current
end

--- Opens the menu with FAF's `entries` ({action, label, disableOnGameOver}, ...), running `actions[action]` on a
--- click; a second call closes it. onClose runs when it goes (the tab's button unchecks).
function Open(entries, actions, onClose, gameOver)
    if current then
        current:Close()
        return false
    end
    local root = Layer()
    Anim.Attach(root)
    local count = table.getn(entries)
    local cover = Widgets.Modal(root, 400, 96 + count * 46)
    local panel = cover.panel
    local menu = { cover = cover, buttons = {} }
    current = menu
    local title = Theme.Title(panel, 'Game menu', 18, C.text)
    LayoutHelpers.AtLeftTopIn(title, panel, 28, 24)
    local before = nil
    for _, entry in entries do
        local action = entry.action
        local kind = kDanger[action] and 'danger' or (action == 'Return' and 'ghost' or 'secondary')
        local button = Theme.Button(panel, LOC(entry.label), function()
            menu:Close()
            local run = actions[action]
            if run then
                local ok, why = pcall(run)
                if not ok then
                    WARN('GAME MENU: ' .. tostring(action) .. ': ' .. tostring(why))
                end
            end
        end, kind, { width = 344, height = 38, icon = kIcons[action] })
        button.action = action
        LayoutHelpers.AtLeftIn(button, panel, 28)
        local above = before
        button.Top:Set(function() return above and (above.Bottom() + Scale(8)) or (title.Bottom() + Scale(22)) end)
        button:SetEnabled(not (gameOver and entry.disableOnGameOver))
        table.insert(menu.buttons, button)
        before = button
    end

    function menu:Close()
        if current == menu then
            current = false
        end
        Escape(nil)
        root:Destroy()
        if onClose then
            pcall(onClose)
        end
    end

    Escape(function() menu:Close() end)
    LOG('GAME MENU: open, ' .. count .. ' entries')
    return menu
end

--- The launcher's options page in a dialog over the game; `tab` 'keys' opens its Key bindings tab.
function OpenOptions(tab)
    if currentOptions then
        currentOptions:Close()
    end
    local root = Layer()
    Anim.Attach(root)
    local width, height = Widgets.FrameUnits()
    local cover = Widgets.Modal(root, math.min(1400, width - 80), math.min(860, height - 60))
    local panel = cover.panel
    local dialog = { cover = cover }
    currentOptions = dialog
    local page = Group(panel, 'game options')
    LayoutHelpers.AtLeftTopIn(page, panel, 28, 24)
    page.Right:Set(function() return panel.Right() - Scale(28) end)
    page.Bottom:Set(function() return panel.Bottom() - Scale(20) end)
    page.Width:Set(function() return page.Right() - page.Left() end)
    page.Height:Set(function() return page.Bottom() - page.Top() end)
    -- What the options page asks of the launcher: its root, and a screen for FAF's profile dialog.
    local host = { root = root }
    function host:OpenScreen(name, build)
        local screen = Group(root, 'game options ' .. name)
        LayoutHelpers.FillParent(screen, root)
        screen.Depth:Set(function() return cover.Depth() + 50 end)
        build(screen, function() screen:Destroy() end)
    end
    local OptionsPage = import('/fafengine/modules/lua/ui/launcher/optionspage.lua')
    local built, why = pcall(OptionsPage.Build, host, page)
    if not built then
        WARN('GAME MENU: the options page failed: ' .. tostring(why))
        root:Destroy()
        currentOptions = false
        import('/lua/ui/dialogs/options.lua').CreateDialog(GetFrame(0))
        return false
    end
    local view = host.optionsView
    dialog.view = view
    local close = Theme.Button(panel, '', function() dialog:Close() end, 'ghost', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(close, panel, 12, 12)
    close.Depth:Set(function() return page.Depth() + 20 end)
    if tab and view and view.tabs then
        view.tab = tab
        view.top = 1
    end
    if view and view.Refresh then
        view:Refresh()
    end
    -- The page repaints as the launcher's pages do (a few times a second).
    local since = 0
    cover:SetNeedsFrameUpdate(true)
    cover.OnFrame = function(self, delta)
        since = since + delta
        if since > 0.25 and view and view.Refresh then
            since = 0
            pcall(view.Refresh, view)
        end
    end

    function dialog:Close()
        if currentOptions == dialog then
            currentOptions = false
        end
        Escape(nil)
        root:Destroy()
    end

    Escape(function() dialog:Close() end)
    LOG('GAME MENU: options open' .. (tab and (', tab ' .. tab) or ''))
    return dialog
end

--- The options dialog on screen (tests), or false.
function CurrentOptions()
    return currentOptions
end
