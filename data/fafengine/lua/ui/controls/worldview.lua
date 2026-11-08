-- I:\FaforeverFiles\mods\TransportDropGhosts\hook\lua\ui\controls\worldview.lua
-- Hook WorldView class HandleEvent to intercept mouse clicks and drag selections on transport drop ghosts.

local DropGhostsSelection = nil

local function GetSelectionModule()
    if not DropGhostsSelection then
        local importFn = rawget(_G, 'import')
        if importFn then
            local ok, mod = pcall(importFn, '/fafengine/modules/lua/ui/game/drop_ghosts_selection.lua')
            if ok and mod then
                DropGhostsSelection = (type(mod) == 'table' and (rawget(mod, 'DropGhostsSelection') or mod))
            end
        end
        if not DropGhostsSelection and rawget(_G, 'require') then
            local ok, mod = pcall(require, 'drop_ghosts_selection')
            if ok and mod then
                DropGhostsSelection = (type(mod) == 'table' and (rawget(mod, 'DropGhostsSelection') or mod))
            end
        end
        if not DropGhostsSelection then
            DropGhostsSelection = rawget(_G, 'DropGhostsSelection')
        end
    end
    return DropGhostsSelection
end

local DropGhostsManager = nil
local function GetManagerModule()
    if not DropGhostsManager then
        local importFn = rawget(_G, 'import')
        if importFn then
            local ok, mod = pcall(importFn, '/fafengine/modules/lua/ui/game/drop_ghosts_manager.lua')
            if ok and mod then
                DropGhostsManager = (type(mod) == 'table' and (rawget(mod, 'DropGhostsManager') or mod))
            end
        end
        if not DropGhostsManager and rawget(_G, 'require') then
            local ok, mod = pcall(require, 'drop_ghosts_manager')
            if ok and mod then
                DropGhostsManager = (type(mod) == 'table' and (rawget(mod, 'DropGhostsManager') or mod))
            end
        end
    end
    if DropGhostsManager and DropGhostsManager.GetDefaultManager then
        return DropGhostsManager.GetDefaultManager()
    end
    return DropGhostsManager
end

local function DrawDropGhostLines(view)
    local drawLine = rawget(_G, 'UI_DrawLine')
    if not drawLine then
        return
    end
    local mgr = GetManagerModule()
    if not mgr then
        return
    end
    local ghosts = (mgr.GetActiveGhosts and mgr:GetActiveGhosts())
        or (mgr.GetGhosts and mgr:GetGhosts())
        or mgr._ghosts
    if not ghosts then
        return
    end
    local buf = mgr.GetBuffer and mgr:GetBuffer()
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

local TargetWorldView = rawget(_G, 'WorldView')
if not TargetWorldView then
    local envFn = rawget(_G, 'getfenv')
    local env = envFn and envFn()
    if env and rawget(env, 'WorldView') then
        TargetWorldView = rawget(env, 'WorldView')
    end
end

if TargetWorldView and not TargetWorldView._dropGhostsClassHooked then
    TargetWorldView._dropGhostsClassHooked = true
    local oldWorldViewHandleEvent = TargetWorldView.HandleEvent
    local clickIntercepted = false

    local oldOnRenderWorld = TargetWorldView.OnRenderWorld
    TargetWorldView.OnRenderWorld = function(self, delta)
        if oldOnRenderWorld then
            pcall(oldOnRenderWorld, self, delta)
        end
        DrawDropGhostLines(self)
    end

    TargetWorldView.HandleEvent = function(self, event)
        if not self._customRenderEnabled and self.SetCustomRender then
            self._customRenderEnabled = true
            pcall(self.SetCustomRender, self, true)
        end

        if event and event._dropGhostsProcessed then
            if oldWorldViewHandleEvent then
                return oldWorldViewHandleEvent(self, event)
            end
            return false
        end

        local sel = GetSelectionModule()
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

                local clickFn = rawget(sel, 'HandleWorldClick')
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

                if _dragState.tracking and _dragState.startX and _dragState.startY then
                    local sX = _dragState.startX
                    local sY = _dragState.startY
                    local shift = _dragState.isShift
                    _dragState.tracking = false
                    _dragState.startX = nil
                    _dragState.startY = nil

                    local eX = event.MouseX or sX
                    local eY = event.MouseY or sY
                    local dx = math.abs(eX - sX)
                    local dy = math.abs(eY - sY)
                    if dx > 10 or dy > 10 then
                        local dragFn = rawget(sel, 'HandleWorldDrag')
                        if dragFn then
                            local ok, dragHandled = pcall(dragFn, sel, self, sX, sY, eX, eY, shift)
                            if ok and dragHandled then
                                event._dropGhostsProcessed = true
                                return true
                            end
                        end
                    else
                        local clickFn = rawget(sel, 'HandleWorldClick')
                        if clickFn then
                            local ok, handled = pcall(clickFn, sel, self, event)
                            if ok and handled then
                                event._dropGhostsProcessed = true
                                return true
                            end
                        end
                    end
                end
            elseif event.Type == 'MouseMove' and _dragState.tracking and _dragState.startX and _dragState.startY then
                local isLDown = (event.Modifiers and event.Modifiers.Left == true) or false
                if not isLDown then
                    local sX = _dragState.startX
                    local sY = _dragState.startY
                    local shift = _dragState.isShift
                    _dragState.tracking = false
                    _dragState.startX = nil
                    _dragState.startY = nil

                    local eX = event.MouseX or sX
                    local eY = event.MouseY or sY
                    local dx = math.abs(eX - sX)
                    local dy = math.abs(eY - sY)
                    if dx > 10 or dy > 10 then
                        local dragFn = rawget(sel, 'HandleWorldDrag')
                        if dragFn then
                            local ok, dragHandled = pcall(dragFn, sel, self, sX, sY, eX, eY, shift)
                            if ok and dragHandled then
                                event._dropGhostsProcessed = true
                                return true
                            end
                        end
                    else
                        local clickFn = rawget(sel, 'HandleWorldClick')
                        if clickFn then
                            local ok, handled = pcall(clickFn, sel, self, event)
                            if ok and handled then
                                event._dropGhostsProcessed = true
                                return true
                            end
                        end
                    end
                end
            elseif (event.Type == 'ButtonPress' or event.Type == 'MouseDown') and isRight then
                local clickFn = rawget(sel, 'HandleWorldClick')
                if clickFn then
                    local ok, handled = pcall(clickFn, sel, self, event)
                    if ok and handled then
                        event._dropGhostsProcessed = true
                        return true
                    end
                end
            end
        end

        if oldWorldViewHandleEvent then
            return oldWorldViewHandleEvent(self, event)
        end
        return false
    end
end
