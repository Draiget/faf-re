-- The changelog preview's overlay in the game: which copy is which, each change of the changelog with what the
-- preview does with it (put back on the BEFORE copy, or why not), Restart (the fight from the start) and Back to the
-- launcher (Esc too). The scene itself: /fafengine/modules/lua/sim/unitpreview.lua.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Shared = import('/fafengine/modules/lua/sim/unitpreview.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local panel = nil
local kBeforeColor = 'ffff9a3c' -- the BEFORE copy's range ring
local kAfterColor = 'ff3cd3ff'  -- the AFTER copy's

--- The copies' range rings around them, every frame, in the main world view (FAF's WorldView shapes, UI_DrawCircle).
local rings = {}
local ringShape = {
    OnRender = true,
    Render = function(self, delta)
        for _, ring in rings do
            local unit = GetUnitById(ring.id)
            if unit and not unit:IsDead() and ring.range and ring.range > 0 then
                UI_DrawCircle(unit:GetPosition(), ring.range, ring.before and kBeforeColor or kAfterColor, 0.3)
            end
        end
    end,
    Destroy = function(self) end,
}

--- The sim's scene (UserSync hook): which units the rings go around and how far.
function OnScene(scene)
    rings = scene.rings or {}
    local view = import('/lua/ui/game/worldview.lua').viewLeft
    if view and rawget(view, 'AddShape') or (view and view.AddShape) then
        view:AddShape(ringShape, 'fafre_preview_rings')
    end
    LOG('UNIT PREVIEW: ' .. table.getn(rings) .. ' range rings')
end

local function Back()
    LOG('UNIT PREVIEW: back to the launcher')
    ExitGame()
end

function Open(preview)
    local root = GetFrame(0)
    local bp = __blueprints[preview.unit]
    local plan = bp and Shared.Plan(preview, bp) or {}

    panel = Theme.Panel(root, 'f00a141c', C.line)
    Theme.Brackets(panel, C.accent)
    panel.Depth:Set(function() return root.Depth() + 500 end)
    -- On the left under the game's economy and menu bars: the scene stays in sight on the right.
    LayoutHelpers.SetWidth(panel, 470)
    panel.Left:Set(function() return root.Left() + Scale(12) end)
    panel.Top:Set(function() return root.Top() + Scale(150) end)

    local x = 18
    local caption = Theme.Caption(panel, 'Changelog preview' .. (preview.version and ('  -  ' .. preview.version) or ''), C.accent)
    LayoutHelpers.AtLeftTopIn(caption, panel, x, 16)
    local name = Theme.Text(panel, (preview.name or preview.unit or '') .. '  -  ' .. string.upper(preview.unit or ''), 16,
        C.text, true)
    name.Left:Set(caption.Left)
    name.Top:Set(function() return caption.Bottom() + Scale(6) end)
    local legend = Theme.Text(panel, 'BEFORE (top, orange ring): old values put back.  AFTER (bottom, cyan ring): as now.',
        11, C.muted)
    legend.Left:Set(caption.Left)
    legend.Top:Set(function() return name.Bottom() + Scale(6) end)

    local before = legend
    local rows = 0
    for _, item in plan do
        local row = Group(panel)
        row:DisableHitTest()
        row.Left:Set(function() return panel.Left() + Scale(x) end)
        row.Right:Set(function() return panel.Right() - Scale(x) end)
        local after = before
        row.Top:Set(function() return after.Bottom() + Scale(rows == 0 and 12 or 4) end)
        LayoutHelpers.SetHeight(row, 20)
        row.Width:Set(function() return row.Right() - row.Left() end)
        local label = Theme.Text(row, item.label, 12, C.text)
        LayoutHelpers.AtLeftIn(label, row, 0)
        LayoutHelpers.AtVerticalCenterIn(label, row)
        local values = Theme.Text(row, (item.oldText or tostring(item.old)) .. '  ->  ' .. (item.newText or tostring(item.new)),
            12, C.gold)
        values.Left:Set(function() return row.Left() + Scale(120) end)
        LayoutHelpers.AtVerticalCenterIn(values, row)
        local state = Theme.Cell(row, 11, item.shown and C.good or C.subtle)
        state.Left:Set(function() return row.Left() + Scale(220) end)
        state.Right:Set(row.Right)
        LayoutHelpers.AtVerticalCenterIn(state, row)
        Theme.SetText(state, item.shown and 'old value on BEFORE' or item.why or '')
        before = row
        rows = rows + 1
    end
    if rows == 0 then
        local none = Theme.Text(panel, 'This change lists no values the preview can show.', 12, C.subtle)
        none.Left:Set(caption.Left)
        none.Top:Set(function() return legend.Bottom() + Scale(12) end)
        before = none
    end

    local back = Theme.Button(panel, 'Back to launcher', Back, 'primary', { icon = 'arrowLeft', width = 190 })
    local restart = Theme.Button(panel, 'Restart fight', function()
        SimCallback({ Func = 'FafrePreviewRestart', Args = {} })
    end, 'secondary', { icon = 'refresh', width = 150 })
    local last = before
    back.Right:Set(function() return panel.Right() - Scale(x) end)
    back.Top:Set(function() return last.Bottom() + Scale(16) end)
    restart.Right:Set(function() return back.Left() - Scale(10) end)
    restart.Top:Set(back.Top)
    panel.Height:Set(function() return back.Bottom() - panel.Top() + Scale(16) end)

    import('/lua/ui/uimain.lua').SetEscapeHandler(Back)

    local shown = 0
    for _, item in plan do
        shown = shown + (item.shown and 1 or 0)
    end
    LOG('UNIT PREVIEW: overlay for ' .. tostring(preview.unit) .. ': ' .. shown .. ' of ' .. table.getn(plan) ..
        ' changes put back')

    -- The launcher's screens walk (/launcherpreviewtest): a look at the fight, then back to the launcher.
    if GetCommandLineArg('/launcherpreviewtest', 0) then
        ForkThread(function()
            WaitSeconds(14)
            local lines = {}
            for _, item in plan do
                table.insert(lines, item.label .. ' ' .. (item.shown and 'shown' or ('not shown: ' .. tostring(item.why))))
            end
            LOG('UNIT PREVIEW TEST: ' .. table.concat(lines, '; '))
            -- /launchergamemenutest: the game's menu (Esc's tab) in the launcher's look, its Options as the
            -- launcher's options page, the Key bindings tab, closed again.
            if GetCommandLineArg('/launchergamemenutest', 0) then
                local GameMenu = import('/fafengine/modules/lua/ui/game/gamemenu.lua')
                import('/lua/ui/game/tabs.lua').ToggleTab('main')
                WaitSeconds(1.5)
                local menu = GameMenu.Current()
                local labels = {}
                for _, button in (menu and menu.buttons or {}) do
                    table.insert(labels, button.action)
                end
                LOG('GAME MENU TEST: menu ' .. (menu and 'open' or 'not open') .. ': ' .. table.concat(labels, ', '))
                WaitSeconds(2)
                for _, button in (menu and menu.buttons or {}) do
                    if button.action == 'Options' then
                        button.onClick(button)
                    end
                end
                WaitSeconds(2)
                local dialog = GameMenu.CurrentOptions()
                local view = dialog and dialog.view
                LOG('GAME MENU TEST: options ' .. (dialog and 'open' or 'not open') .. ', menu closed ' ..
                    tostring(GameMenu.Current() == false) .. ', tab ' .. tostring(view and view.tab) .. ', rows ' ..
                    tostring(view and view.Shown and view:Shown()))
                WaitSeconds(2)
                if view then
                    view.tab = 'keys'
                    view.top = 1
                    view:Refresh()
                end
                WaitSeconds(2)
                LOG('GAME MENU TEST: keys tab ' .. tostring(view and view.tab) .. ', keys view ' ..
                    tostring(view and view.keysView ~= nil))
                WaitSeconds(2)
                if dialog then
                    dialog:Close()
                end
                WaitSeconds(1)
                LOG('GAME MENU TEST: closed, options ' .. tostring(GameMenu.CurrentOptions() == false))
            end
            SimCallback({ Func = 'FafrePreviewRestart', Args = {} })
            WaitSeconds(4)
            LOG('UNIT PREVIEW TEST: restarted')
            WaitSeconds(2)
            Back()
        end)
    end
end
