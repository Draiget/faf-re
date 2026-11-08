-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered
-- as a hook directory): appended to /lua/ui/game/gamemain.lua.
--
-- A replay gets the timeline bar. The engine's own modules lie under /fafengine/modules, a
-- path no FAF file has, so they are never taken as hooks of FAF's files. FAF's Lua may
-- carry the timeline itself (issue #327, /lua/ui/game/replay_timeline.lua); its own
-- CreateUI then makes the bar, so this doesn't.

local diskGetFileInfo = rawget(_G, 'DiskGetFileInfo')
if diskGetFileInfo and not diskGetFileInfo('/lua/ui/game/replay_timeline.lua') then
    local OldCreateUI = CreateUI
    function CreateUI(isReplay)
        OldCreateUI(isReplay)
        if isReplay then
            import('/fafengine/modules/lua/ui/game/replay_timeline.lua').Create()
        end
    end
end


-- ============================================================================
-- Engine transport drop ghosts integration
-- ============================================================================
-- I:\FaforeverFiles\mods\TransportDropGhosts\hook\lua\ui\game\gamemain.lua
-- Thin FAF gamemain lifecycle hook for Transport Unload Hologram Ghosts mod.

local function SafeWarn(msg)
    local warnFn = rawget(_G, 'WARN')
    if warnFn then
        pcall(warnFn, "TransportDropGhosts: " .. tostring(msg))
    end
end

local function SafeGet(tbl, key)
    if type(tbl) ~= 'table' then
        return nil
    end
    local ok, val = pcall(function() return tbl[key] end)
    if ok then
        return val
    end
    return nil
end

local DropGhostsManager = nil
local DropGhostsSelection = nil
local DropGhostsDispatcher = nil
local DropGhostsBufferMod = nil

-- Shared global drag tracking state across worldview hooks, selection events, and onbeat
local _dragState = rawget(_G, '__DropGhostsDragState')
if not _dragState then
    _dragState = {
        startX = nil,
        startY = nil,
        tracking = false,
        isShift = false,
        view = nil,
    }
    if rawget(_G, 'rawset') then
        rawset(_G, '__DropGhostsDragState', _dragState)
    end
end

local function LoadModModules()
    if not DropGhostsBufferMod then
        local importFn = rawget(_G, 'import')
        if importFn then
            local ok, mod = pcall(importFn, '/fafengine/modules/lua/ui/game/drop_ghosts_buffer.lua')
            if ok and mod then
                DropGhostsBufferMod = SafeGet(mod, 'DropGhostsBuffer') or mod
            end
        end
        if not DropGhostsBufferMod and rawget(_G, 'require') then
            local ok, mod = pcall(require, 'drop_ghosts_buffer')
            if ok and mod then
                DropGhostsBufferMod = SafeGet(mod, 'DropGhostsBuffer') or mod
            end
        end
        if not DropGhostsBufferMod then
            DropGhostsBufferMod = rawget(_G, 'DropGhostsBuffer')
        end
    end

    if not DropGhostsManager then
        local importFn = rawget(_G, 'import')
        if importFn then
            local ok, mod = pcall(importFn, '/fafengine/modules/lua/ui/game/drop_ghosts_manager.lua')
            if ok and mod then
                DropGhostsManager = SafeGet(mod, 'DropGhostsManager') or mod
            end
        end
        if not DropGhostsManager and rawget(_G, 'require') then
            local ok, mod = pcall(require, 'drop_ghosts_manager')
            if ok and mod then
                DropGhostsManager = SafeGet(mod, 'DropGhostsManager') or mod
            end
        end
        if not DropGhostsManager then
            DropGhostsManager = rawget(_G, 'DropGhostsManager')
        end
    end

    if not DropGhostsSelection then
        local importFn = rawget(_G, 'import')
        if importFn then
            local ok, mod = pcall(importFn, '/fafengine/modules/lua/ui/game/drop_ghosts_selection.lua')
            if ok and mod then
                DropGhostsSelection = SafeGet(mod, 'DropGhostsSelection') or mod
            end
        end
        if not DropGhostsSelection and rawget(_G, 'require') then
            local ok, mod = pcall(require, 'drop_ghosts_selection')
            if ok and mod then
                DropGhostsSelection = SafeGet(mod, 'DropGhostsSelection') or mod
            end
        end
        if not DropGhostsSelection then
            DropGhostsSelection = rawget(_G, 'DropGhostsSelection')
        end
    end

    if not DropGhostsDispatcher then
        local importFn = rawget(_G, 'import')
        if importFn then
            local ok, mod = pcall(importFn, '/fafengine/modules/lua/ui/game/drop_ghosts_dispatcher.lua')
            if ok and mod then
                DropGhostsDispatcher = SafeGet(mod, 'DropGhostsDispatcher') or mod
            end
        end
        if not DropGhostsDispatcher and rawget(_G, 'require') then
            local ok, mod = pcall(require, 'drop_ghosts_dispatcher')
            if ok and mod then
                DropGhostsDispatcher = SafeGet(mod, 'DropGhostsDispatcher') or mod
            end
        end
        if not DropGhostsDispatcher then
            DropGhostsDispatcher = rawget(_G, 'DropGhostsDispatcher')
        end
    end

    -- Wire shared singleton buffer and manager instances
    local mgr = nil
    if DropGhostsManager then
        local getMgrFn = SafeGet(DropGhostsManager, 'GetDefaultManager')
        mgr = getMgrFn and getMgrFn() or DropGhostsManager
    end

    local sel = nil
    if DropGhostsSelection then
        local getSelFn = SafeGet(DropGhostsSelection, 'GetDefaultSelection')
        sel = getSelFn and getSelFn() or DropGhostsSelection
    end

    local disp = nil
    if DropGhostsDispatcher then
        local getDispFn = SafeGet(DropGhostsDispatcher, 'GetDefaultDispatcher')
        disp = getDispFn and getDispFn() or DropGhostsDispatcher
    end

    local sharedBuf = nil
    if DropGhostsBufferMod and DropGhostsBufferMod.GetDefaultBuffer then
        sharedBuf = DropGhostsBufferMod.GetDefaultBuffer()
    elseif mgr and mgr.GetBuffer then
        sharedBuf = mgr:GetBuffer()
    end

    if sharedBuf then
        if mgr and mgr.SetBuffer then pcall(mgr.SetBuffer, mgr, sharedBuf) end
        if sel and sel.SetBuffer then pcall(sel.SetBuffer, sel, sharedBuf) end
        if disp and disp.SetBuffer then pcall(disp.SetBuffer, disp, sharedBuf) end
    end

    if mgr then
        mgr._deferOrderClear = true
        if disp and disp.SetManager then
            pcall(disp.SetManager, disp, mgr)
        end
        if sel and sel.SetManager then
            pcall(sel.SetManager, sel, mgr)
        end
    end

    return mgr, sel, disp
end

local function GetPrimaryView()
    local wvMod = rawget(_G, 'import') and import('/lua/ui/game/worldview.lua')
    local worldview = wvMod or rawget(_G, 'worldview')
    if worldview then
        if worldview.viewLeft then
            return worldview.viewLeft
        end
        if worldview.view then
            return worldview.view
        end
        local getViews = SafeGet(worldview, 'GetWorldViews')
        if getViews then
            local ok, views = pcall(getViews)
            if ok and type(views) == 'table' then
                for _, item in pairs(views) do
                    if item then return item end
                end
            end
        end
    end
    return nil
end

local function ResolveDragSelection(endX, endY)
    if not _dragState.tracking or not _dragState.startX or not _dragState.startY then
        return false
    end

    local sX = _dragState.startX
    local sY = _dragState.startY
    local shift = _dragState.isShift
    local v = _dragState.view or GetPrimaryView()

    local eX = endX or sX
    local eY = endY or sY
    local dx = math.abs(eX - sX)
    local dy = math.abs(eY - sY)

    if dx <= 10 and dy <= 10 then
        -- Not enough drag distance yet (or stale cursor pos from dragger); do NOT wipe _dragState so ButtonRelease can resolve it!
        return false
    end

    _dragState.tracking = false
    _dragState.startX = nil
    _dragState.startY = nil

    local _, sel, _ = LoadModModules()
    if sel then
        local dragFn = SafeGet(sel, 'HandleWorldDrag')
        if dragFn then
            local ok, captured = pcall(dragFn, sel, v, sX, sY, eX, eY, shift)
            if ok and captured then
                return true
            end
        end
    end
    return false
end

local function DrawDropGhostLines(view)
    local drawLine = rawget(_G, 'UI_DrawLine')
    if not drawLine then
        return
    end
    local mgr, _, _ = LoadModModules()
    if not mgr then
        return
    end
    local ghosts = (mgr.GetActiveGhosts and mgr:GetActiveGhosts())
        or (mgr.GetGhosts and mgr:GetGhosts())
        or mgr._ghosts
    if not ghosts then
        return
    end
    local buf = (mgr.GetBuffer and mgr:GetBuffer())
        or (DropGhostsBufferMod and DropGhostsBufferMod.GetDefaultBuffer and DropGhostsBufferMod.GetDefaultBuffer())
    if not buf then
        return
    end

    local getSurf = rawget(_G, 'GetSurfaceHeight')

    for gid, ghost in pairs(ghosts) do
        local unit = ghost.realUnit or ghost
        local unitId = (unit.GetEntityId and unit:GetEntityId())
            or unit.id
            or ghost.id
            or gid
        local orders = buf.GetOrders and buf:GetOrders(unitId)
        if orders and table.getn(orders) > 0 then
            local ghostPos = ghost.position
            if ghostPos then
                local gx = ghostPos[1] or ghostPos.x
                local gy = ghostPos[2] or ghostPos.y or 0
                local gz = ghostPos[3] or ghostPos.z
                if getSurf and gx and gz then
                    local gh = getSurf(gx, gz)
                    if gh and gh > gy then
                        gy = gh
                    end
                end

                local prevPos = { gx, gy + 0.4, gz }

                for i = 1, table.getn(orders) do
                    local order = orders[i]
                    local targetData = order.targetData
                    if targetData then
                        local tx = targetData[1] or targetData.x
                        local ty = targetData[2] or targetData.y or 0
                        local tz = targetData[3] or targetData.z
                        if not tx and targetData.Position then
                            tx = targetData.Position[1] or targetData.Position.x
                            ty = targetData.Position[2] or targetData.Position.y or 0
                            tz = targetData.Position[3] or targetData.Position.z
                        end

                        if tx and tz then
                            if getSurf then
                                local th = getSurf(tx, tz)
                                if th and th > ty then
                                    ty = th
                                end
                            end

                            local curPos = { tx, ty + 0.4, tz }
                            local cmd = order.commandType or order.command or 'Move'

                            local color = "ff00e5ff" -- Bright neon cyan for move
                            if cmd == 'Attack' or cmd == 'UNITCOMMAND_Attack' then
                                color = "ffff2222" -- Bright red
                            elseif cmd == 'Patrol' or cmd == 'UNITCOMMAND_Patrol' then
                                color = "ff3388ff" -- Royal blue
                            elseif cmd == 'Build' or cmd == 'UNITCOMMAND_BuildMobile' or cmd == 'BuildMobile' then
                                color = "ffffff00" -- Vibrant yellow
                            elseif cmd == 'Repair' or cmd == 'UNITCOMMAND_Repair' then
                                color = "ff00ff88" -- Bright green
                            elseif cmd == 'Reclaim' or cmd == 'UNITCOMMAND_Reclaim' then
                                color = "ffff8800" -- Orange
                            end

                            pcall(drawLine, prevPos, curPos, color, 0.35)


                            prevPos = curPos
                        end
                    end
                end
            end
        end
    end
end

local function HookView(view)
    if not view then
        return
    end

    if not view._customRenderEnabled and view.SetCustomRender then
        view._customRenderEnabled = true
        pcall(view.SetCustomRender, view, true)
    end

    if not view._dropGhostsRenderHooked then
        view._dropGhostsRenderHooked = true
        local oldInstOnRenderWorld = view.OnRenderWorld
        view.OnRenderWorld = function(self, delta)
            if oldInstOnRenderWorld then
                pcall(oldInstOnRenderWorld, self, delta)
            end
            DrawDropGhostLines(self)
        end
    end

    local wvClass = rawget(_G, 'WorldView')
    if view._dropGhostsHooked or (wvClass and wvClass._dropGhostsClassHooked) then
        return
    end
    view._dropGhostsHooked = true
    SafeWarn("HookView: successfully hooked worldview")
    local oldHandleEvent = view.HandleEvent
    local clickIntercepted = false

    view.HandleEvent = function(self, event)
        if event and event._dropGhostsProcessed then
            if oldHandleEvent then
                return oldHandleEvent(self, event)
            end
            return false
        end

        local _, sel, _ = LoadModModules()
        if sel and event then
            local isLeft = (event.KeyCode == 1 or event.Button == 1 or event.Button == 'Left' or (event.Modifiers and event.Modifiers.Left))
            local isRight = (event.KeyCode == 3 or event.Button == 3 or event.Button == 'Right' or (event.Modifiers and event.Modifiers.Right))
            local isShift = (event.Modifiers and event.Modifiers.Shift == true) or false

            if (event.Type == 'ButtonPress' or event.Type == 'ButtonDClick' or event.Type == 'MouseDown') and isLeft then
                _dragState.startX = event.MouseX
                _dragState.startY = event.MouseY
                _dragState.tracking = true
                _dragState.isShift = isShift
                _dragState.view = self
                clickIntercepted = false

                local clickFn = SafeGet(sel, 'HandleWorldClick')
                if clickFn then
                    local ok, handled = pcall(clickFn, sel, self, event)
                    if ok and handled then
                        event._dropGhostsProcessed = true
                        clickIntercepted = true
                        _dragState.tracking = false
                        _dragState.startX = nil
                        _dragState.startY = nil
                        return true
                    end
                end
            elseif (event.Type == 'ButtonRelease' or event.Type == 'MouseUp') and isLeft then
                if clickIntercepted then
                    clickIntercepted = false
                    _dragState.tracking = false
                    _dragState.startX = nil
                    _dragState.startY = nil
                    event._dropGhostsProcessed = true
                    return true
                end

                if ResolveDragSelection(event.MouseX, event.MouseY) then
                    event._dropGhostsProcessed = true
                    return true
                end

                -- Fallback: If drag distance <= 10, try HandleWorldClick on release
                local sX = _dragState.startX or event.MouseX or 0
                local sY = _dragState.startY or event.MouseY or 0
                local dx = math.abs((event.MouseX or sX) - sX)
                local dy = math.abs((event.MouseY or sY) - sY)
                if dx <= 10 and dy <= 10 then
                    local clickFn = SafeGet(sel, 'HandleWorldClick')
                    if clickFn then
                        local ok, handled = pcall(clickFn, sel, self, event)
                        if ok and handled then
                            event._dropGhostsProcessed = true
                            _dragState.tracking = false
                            _dragState.startX = nil
                            _dragState.startY = nil
                            return true
                        end
                    end
                end

                _dragState.tracking = false
                _dragState.startX = nil
                _dragState.startY = nil
            elseif (event.Type == 'ButtonPress' or event.Type == 'MouseDown') and isRight then
                local clickFn = SafeGet(sel, 'HandleWorldClick')
                if clickFn then
                    local ok, handled = pcall(clickFn, sel, self, event)
                    if ok and handled then
                        event._dropGhostsProcessed = true
                        return true
                    end
                end
            end
        end
        if oldHandleEvent then
            return oldHandleEvent(self, event)
        end
        return false
    end
end

local function HookAllWorldViews()
    local wvMod = rawget(_G, 'import') and import('/lua/ui/game/worldview.lua')
    local worldview = wvMod or rawget(_G, 'worldview')
    if worldview then
        if worldview.viewLeft then HookView(worldview.viewLeft) end
        if worldview.viewRight then HookView(worldview.viewRight) end
        if worldview.view then HookView(worldview.view) end
        local getViews = SafeGet(worldview, 'GetWorldViews')
        if getViews then
            local ok, views = pcall(getViews)
            if ok and type(views) == 'table' then
                for _, item in pairs(views) do
                    if item then HookView(item) end
                end
            end
        end
    end
end

local function OnBeat()
    local ok, err = pcall(function()
        local mgr, _, disp = LoadModModules()
        local focusArmy = -1
        local getFocusArmyFn = rawget(_G, 'GetFocusArmy')
        if getFocusArmyFn then
            local fa = getFocusArmyFn()
            if fa then
                focusArmy = fa
            end
        end

        if mgr and mgr.Update then
            mgr:Update(focusArmy)
        end

        local primaryView = GetPrimaryView()
        if disp then
            if disp.OnBeat then
                disp:OnBeat()
            end
            if disp.UpdateWaypoints then
                disp:UpdateWaypoints(primaryView)
            end
        end

        HookAllWorldViews()
    end)
    if not ok then
        SafeWarn("OnBeat error: " .. tostring(err))
    end
end

local function Cleanup()
    local mgr, sel, disp = LoadModModules()
    local clearSelFn = SafeGet(sel, 'ClearSelection')
    if clearSelFn then
        pcall(clearSelFn, sel)
    end
    local clearDispFn = SafeGet(disp, 'ClearAll')
    if clearDispFn then
        pcall(clearDispFn, disp)
    end
    local clearMgrFn = SafeGet(mgr, 'ClearAll')
    if clearMgrFn then
        pcall(clearMgrFn, mgr)
    end
end

-- Hook OnSelectionChanged to resolve engine drag selection and register user transports
local oldOnSelectionChanged = OnSelectionChanged
function OnSelectionChanged(oldSelection, newSelection, added, removed)
    if oldOnSelectionChanged then
        oldOnSelectionChanged(oldSelection, newSelection, added, removed)
    end

    -- If Maui Dragger just completed an engine selection drag, check if ghosts were captured
    if _dragState.tracking and _dragState.startX and _dragState.startY then
        local getMousePos = rawget(_G, 'GetMouseScreenPos')
        local mousePos = getMousePos and getMousePos()
        local endX = (mousePos and (mousePos[1] or mousePos.x)) or _dragState.startX
        local endY = (mousePos and (mousePos[2] or mousePos.y)) or _dragState.startY
        ResolveDragSelection(endX, endY)
    end

    local selHidden = false
    local selMod = rawget(_G, 'import') and import('/lua/ui/game/selection.lua')
    if selMod then
        local isHMethod = SafeGet(selMod, 'IsHidden')
        if isHMethod then
            local ok, isH = pcall(isHMethod)
            if ok and isH then
                selHidden = true
            end
        end
    end

    if not ignoreSelection and not selHidden and newSelection and table.getn(newSelection) > 0 then
        local mgr, sel, _ = LoadModModules()
        if sel and sel.IsActive and sel:IsActive() then
            sel:ClearSelection()
        end
        if mgr and mgr.RegisterTransport then
            for _, u in ipairs(newSelection) do
                mgr:RegisterTransport(u)
            end
        end
    end
end

-- Hook CreateUI (following Beer / UMT pattern)
local oldCreateUI = CreateUI
function CreateUI(isReplay)
    if oldCreateUI then
        oldCreateUI(isReplay)
    end

    SafeWarn("CreateUI initialized, registering Beat and WorldView hooks")

    local ok, err = pcall(function()
        LoadModModules()
        HookAllWorldViews()

        if AddBeatFunction then
            AddBeatFunction(OnBeat)
        elseif rawget(_G, 'AddBeatFunction') then
            rawget(_G, 'AddBeatFunction')(OnBeat)
        end

        if AddOnUIDestroyedFunction then
            AddOnUIDestroyedFunction(Cleanup)
        elseif rawget(_G, 'AddOnUIDestroyedFunction') then
            rawget(_G, 'AddOnUIDestroyedFunction')(Cleanup)
        end
    end)
    if not ok then
        SafeWarn("CreateUI init error: " .. tostring(err))
    end
end

-- Hook OnDestroy if present in gamemain lifecycle
local oldOnDestroy = rawget(_G, 'OnDestroy')
if oldOnDestroy then
    function OnDestroy()
        pcall(Cleanup)
        oldOnDestroy()
    end
end

-- Support standalone export / test inspections
local DropGhostsGamemain = {
    CreateUI = CreateUI,
    OnBeat = OnBeat,
    OnSelectionChanged = OnSelectionChanged,
    Cleanup = Cleanup,
    HookView = HookView,
    HookAllWorldViews = HookAllWorldViews,
    GetPrimaryView = GetPrimaryView,
    LoadModModules = LoadModModules,
    ResolveDragSelection = ResolveDragSelection,
    GetDragState = function() return _dragState end,
}

if rawget(_G, 'rawset') then
    rawset(_G, 'DropGhostsGamemain', DropGhostsGamemain)
end
