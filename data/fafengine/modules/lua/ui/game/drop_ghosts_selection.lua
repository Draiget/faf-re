-- I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_selection.lua
-- Selection proxy and input interception for transport unload ghost units.

local function SafeWarn(msg)
    local warnFn = rawget(_G, 'WARN')
    if warnFn then
        pcall(warnFn, "TransportDropGhosts: " .. tostring(msg))
    end
end

local function SafeGet(tbl, key)
    if type(tbl) ~= 'table' then return nil end
    local ok, val = pcall(rawget, tbl, key)
    if ok then return val end
    return nil
end

local DropGhostsManager = nil
local DropGhostsBuffer = nil

local function ResolveManagerModule()
    if DropGhostsManager then return DropGhostsManager end
    local mod = nil
    if rawget(_G, 'import') then
        local ok, m = pcall(import, '/fafengine/modules/lua/ui/game/drop_ghosts_manager.lua')
        if ok and type(m) == 'table' then
            mod = m
        else
            pcall(function()
                local m2 = import('drop_ghosts_manager.lua')
                if type(m2) == 'table' then mod = m2 end
            end)
        end
    elseif rawget(_G, 'require') then
        local ok, m = pcall(require, 'drop_ghosts_manager')
        if ok and type(m) == 'table' then mod = m end
    end
    if not mod and rawget(_G, 'DropGhostsManager') then
        mod = rawget(_G, 'DropGhostsManager')
    end
    if mod then
        DropGhostsManager = (type(rawget(mod, 'DropGhostsManager')) == 'table' and rawget(mod, 'DropGhostsManager')) or mod
    end
    return DropGhostsManager
end

local function ResolveBufferModule()
    if DropGhostsBuffer then return DropGhostsBuffer end
    local mod = nil
    if rawget(_G, 'import') then
        local ok, m = pcall(import, '/fafengine/modules/lua/ui/game/drop_ghosts_buffer.lua')
        if ok and type(m) == 'table' then
            mod = m
        else
            pcall(function()
                local m2 = import('drop_ghosts_buffer.lua')
                if type(m2) == 'table' then mod = m2 end
            end)
        end
    elseif rawget(_G, 'require') then
        local ok, m = pcall(require, 'drop_ghosts_buffer')
        if ok and type(m) == 'table' then mod = m end
    end
    if not mod and rawget(_G, 'DropGhostsBuffer') then
        mod = rawget(_G, 'DropGhostsBuffer')
    end
    if mod then
        DropGhostsBuffer = (type(rawget(mod, 'DropGhostsBuffer')) == 'table' and rawget(mod, 'DropGhostsBuffer')) or mod
    end
    return DropGhostsBuffer
end
ResolveManagerModule()
ResolveBufferModule()

local OrdersModule = nil
local ConstructionModule = nil
local CommandModeModule = nil

if rawget(_G, 'import') then
    pcall(function() OrdersModule = import('/lua/ui/game/orders.lua') end)
    pcall(function() ConstructionModule = import('/lua/ui/game/construction.lua') end)
    pcall(function() CommandModeModule = import('/lua/ui/game/commandmode.lua') end)
end

local IsInstance
local GetDefaultSelection
local Create

local function GetOrdersModule(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    return s._ordersModule or OrdersModule or rawget(_G, 'orders')
end

local function GetConstructionModule(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    return s._constructionModule or ConstructionModule or rawget(_G, 'construction')
end

local function GetCommandModeModule(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    local mod = s._commandModeModule or CommandModeModule or rawget(_G, 'commandmode')
    if mod and not mod._dropGhostsEndHooked then
        mod._dropGhostsEndHooked = true
        local oldEnd = mod.EndCommandMode
        if oldEnd then
            mod.EndCommandMode = function(isCancel)
                oldEnd(isCancel)
                local curSel = GetDefaultSelection()
                if curSel and IsActive(curSel) then
                    curSel:_SyncUI()
                end
            end
        end
    end
    return mod
end

local function SetOrdersModule(a, b)
    local s, cls
    if IsInstance(a) then
        s = a
        cls = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        cls = b
    else
        s = GetDefaultSelection()
        cls = a
    end
    s._ordersModule = cls
    OrdersModule = cls
end

local function SetConstructionModule(a, b)
    local s, cls
    if IsInstance(a) then
        s = a
        cls = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        cls = b
    else
        s = GetDefaultSelection()
        cls = a
    end
    s._constructionModule = cls
    ConstructionModule = cls
end

local function SetCommandModeModule(a, b)
    local s, cls
    if IsInstance(a) then
        s = a
        cls = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        cls = b
    else
        s = GetDefaultSelection()
        cls = a
    end
    s._commandModeModule = cls
    CommandModeModule = cls
end

local function ProjectPos(worldView, pos)
    if not worldView or not worldView.Project or not pos then
        return nil
    end
    local targetPos = { pos.x or pos[1] or 0, pos.y or pos[2] or 0, pos.z or pos[3] or 0 }
    local vecFn = rawget(_G, 'Vector')
    if vecFn then
        local okV, vec = pcall(vecFn, targetPos[1], targetPos[2], targetPos[3])
        if okV and vec then
            targetPos = vec
        end
    end
    local ok, proj = pcall(worldView.Project, worldView, targetPos)
    if not ok or not proj then
        ok, proj = pcall(worldView.Project, worldView, pos)
    end
    if ok and proj then
        local px = proj[1] or proj.x
        local py = proj[2] or proj.y
        if px and py then
            local viewLeft = 0
            local viewTop = 0
            pcall(function()
                if worldView.Left then
                    local l = worldView:Left()
                    if type(l) == 'number' then viewLeft = l end
                end
            end)
            pcall(function()
                if worldView.Top then
                    local t = worldView:Top()
                    if type(t) == 'number' then viewTop = t end
                end
            end)
            return { x = px + viewLeft, y = py + viewTop, [1] = px + viewLeft, [2] = py + viewTop }
        end
    end
    return nil
end

local function ResolveTargetPosition(worldView, event)
    if not event then
        event = {}
    end
    if event.TargetPos then
        return event.TargetPos
    end
    if event.Position then
        return event.Position
    end
    if event.Target and type(event.Target) == 'table' and (event.Target.x or event.Target[1]) then
        return event.Target
    end
    if event.WorldPos then
        return event.WorldPos
    end

    local mouseWorldFn = rawget(_G, 'GetMouseWorldPos')
    if mouseWorldFn then
        local ok, pos = pcall(mouseWorldFn)
        if ok and pos and (pos.x or pos[1]) then
            return pos
        end
    end

    local mx = event.MouseX or 0
    local my = event.MouseY or 0

    local unprojectFn = worldView and (worldView.UnProject or worldView.Unproject)
    if worldView and unprojectFn then
        if rawget(_G, 'Vector2') then
            local okV2, v2 = pcall(rawget(_G, 'Vector2'), mx, my)
            if okV2 and v2 then
                local ok, pos = pcall(unprojectFn, worldView, v2)
                if ok and pos and (type(pos.x) == 'number' or type(pos[1]) == 'number') then
                    return pos
                end
            end
        end
        local ok, pos = pcall(unprojectFn, worldView, { mx, my })
        if ok and type(pos) == 'table' and (type(pos.x) == 'number' or type(pos[1]) == 'number') then
            return pos
        end
    end

    return { x = mx, y = 0, z = my, [1] = mx, [2] = 0, [3] = my }
end

local function CloneTargetData(data)
    if type(data) == 'table' then
        local copy = {}
        for k, v in pairs(data) do
            copy[k] = v
        end
        local x = data.x or data[1]
        local y = data.y or data[2] or 0
        local z = data.z or data[3]
        if x and z then
            copy.x = x
            copy.y = y
            copy.z = z
            copy[1] = x
            copy[2] = y
            copy[3] = z
        end
        return copy
    end
    return data
end

local function MapRuleUccToCommand(ruleName)
    if ruleName == 'RULEUCC_Attack' then return 'Attack' end
    if ruleName == 'RULEUCC_Move' then return 'Move' end
    if ruleName == 'RULEUCC_Patrol' then return 'Patrol' end
    if ruleName == 'RULEUCC_Reclaim' then return 'Reclaim' end
    if ruleName == 'RULEUCC_Repair' then return 'Repair' end
    if ruleName == 'RULEUCC_Guard' then return 'Guard' end
    if ruleName == 'RULEUCC_Stop' then return 'Stop' end
    return ruleName or 'Move'
end

DropGhostsSelection = {}
DropGhostsSelection.__index = DropGhostsSelection

local _defaultInstance = nil

local CreateSelection = function(customManager, customBuffer)
    local mgr = customManager
    local mgrMod = ResolveManagerModule()
    if not mgr and mgrMod then
        local getDefFn = SafeGet(mgrMod, 'GetDefaultManager')
        if getDefFn then
            mgr = getDefFn()
        else
            mgr = mgrMod
        end
    end
    if not mgr and rawget(_G, 'DropGhostsManager') then
        mgr = rawget(_G, 'DropGhostsManager')
    end

    local buf = customBuffer
    if not buf and mgr then
        local getBufFn = SafeGet(mgr, 'GetBuffer')
        if getBufFn then
            buf = getBufFn(mgr)
        end
    end
    local bufMod = ResolveBufferModule()
    if not buf and bufMod then
        local getDefFn = SafeGet(bufMod, 'GetDefaultBuffer')
        local createFn = SafeGet(bufMod, 'Create')
        if getDefFn then
            buf = getDefFn()
        elseif createFn then
            buf = createFn()
        end
    end

    local instance = {
        _manager = mgr,
        _buffer = buf,
        _selectedGhosts = {},
        _ordersModule = nil,
        _constructionModule = nil,
        _commandModeModule = nil,
        _hitRadius = 50
    }
    return setmetatable(instance, DropGhostsSelection)
end

GetDefaultSelection = function()
    if not _defaultInstance then
        _defaultInstance = CreateSelection()
    end
    return _defaultInstance
end

IsInstance = function(val)
    return type(val) == 'table' and val ~= DropGhostsSelection and val._selectedGhosts ~= nil
end

local function GetManager(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    if not s._manager then
        local mgrMod = rawget(_G, 'DropGhostsManager')
        if not mgrMod and rawget(_G, 'import') then
            local ok, m = pcall(import, '/fafengine/modules/lua/ui/game/drop_ghosts_manager.lua')
            if ok and m then
                mgrMod = rawget(m, 'DropGhostsManager') or m
            end
        end
        if mgrMod then
            s._manager = (mgrMod.GetDefaultManager and mgrMod.GetDefaultManager()) or mgrMod
        end
    end
    return s._manager
end

local function GetActiveGhosts(a)
    local mgr = GetManager(a)
    if mgr then
        if mgr.GetActiveGhosts then
            return mgr:GetActiveGhosts()
        elseif type(mgr) == 'table' and mgr._ghosts then
            return mgr._ghosts
        end
    end
    return {}
end

local function SetManager(a, b)
    local s, mgr
    if IsInstance(a) then
        s = a
        mgr = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        mgr = b
    else
        s = GetDefaultSelection()
        mgr = a
    end
    s._manager = mgr
    if mgr and mgr.GetBuffer and not s._customBufferExplicit then
        local b = mgr:GetBuffer()
        if b then
            s._buffer = b
        end
    end
end

local function GetBuffer(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    return s._buffer
end

local function SetBuffer(a, b)
    local s, buf
    if IsInstance(a) then
        s = a
        buf = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        buf = b
    else
        s = GetDefaultSelection()
        buf = a
    end
    s._buffer = buf
end

local function SetHitRadius(a, b)
    local s, radius
    if IsInstance(a) then
        s = a
        radius = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        radius = b
    else
        s = GetDefaultSelection()
        radius = a
    end
    s._hitRadius = radius or 25
end

function DropGhostsSelection:_SyncUI()
    local hasGhosts = false
    local selectedUnits = {}
    local availableOrdersMap = {}
    local availableTogglesMap = {}
    local buildableCategoriesMap = {}
    local hasBuildable = false

    for id, ghost in pairs(self._selectedGhosts) do
        hasGhosts = true
        local unit = ghost.realUnit or ghost
        table.insert(selectedUnits, unit)

        local bp = (unit.GetBlueprint and unit:GetBlueprint()) or unit.blueprint or {}
        if bp.General then
            if type(bp.General.CommandCaps) == 'table' then
                for cap, enabled in pairs(bp.General.CommandCaps) do
                    if enabled then
                        availableOrdersMap[cap] = true
                    end
                end
            end
            if type(bp.General.ToggleCaps) == 'table' then
                for cap, enabled in pairs(bp.General.ToggleCaps) do
                    if enabled then
                        availableTogglesMap[cap] = true
                    end
                end
            end
        end

        if bp.Economy and type(bp.Economy.BuildableCategory) == 'table' then
            for _, cat in ipairs(bp.Economy.BuildableCategory) do
                if not buildableCategoriesMap[cat] then
                    buildableCategoriesMap[cat] = true
                    hasBuildable = true
                end
            end
        end
    end

    if not hasGhosts then
        self:ClearSelection()
        return
    end

    local availableOrders = {}
    for cap in pairs(availableOrdersMap) do
        table.insert(availableOrders, cap)
    end

    local availableToggles = {}
    for cap in pairs(availableTogglesMap) do
        table.insert(availableToggles, cap)
    end

    local buildableCategories = {}
    if hasBuildable then
        for cat in pairs(buildableCategoriesMap) do
            table.insert(buildableCategories, cat)
        end
    end

    local getUnitCmdData = rawget(_G, 'GetUnitCommandData')
    if getUnitCmdData and table.getn(selectedUnits) > 0 then
        local ok, ords, toggles, cats = pcall(getUnitCmdData, selectedUnits)
        if ok and ords and table.getn(ords) > 0 then
            availableOrders = ords
            availableToggles = toggles or availableToggles
            buildableCategories = cats or buildableCategories
        end
    end

    if table.getn(availableOrders) == 0 then
        availableOrders = { 'Move', 'Attack', 'Patrol', 'Stop', 'Guard' }
    end

    local ordersMod = self._ordersModule or GetOrdersModule()
    if ordersMod and ordersMod.SetAvailableOrders then
        pcall(ordersMod.SetAvailableOrders, availableOrders, availableToggles, selectedUnits)
    end

    local constructionMod = self._constructionModule or GetConstructionModule()
    if constructionMod and constructionMod.OnSelection then
        pcall(constructionMod.OnSelection, buildableCategories, selectedUnits, false)
    end
end

local function HighlightGhost(ghost, isSelected)
    if not ghost or not ghost.mesh then
        return
    end
    local baseScale = ghost.uniformScale or 1.0
    if isSelected then
        local s = baseScale * 1.15
        if ghost.mesh.SetScale then
            pcall(ghost.mesh.SetScale, ghost.mesh, { s, s, s })
        end
        if ghost.mesh.SetColor then
            pcall(ghost.mesh.SetColor, ghost.mesh, "ffffffff")
        end
    else
        if ghost.mesh.SetScale then
            pcall(ghost.mesh.SetScale, ghost.mesh, { baseScale, baseScale, baseScale })
        end
        if ghost.mesh.SetColor then
            pcall(ghost.mesh.SetColor, ghost.mesh, "80a0d0ff")
        end
    end
end

local function ClearSelection(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    for _, prevG in pairs(s._selectedGhosts) do
        HighlightGhost(prevG, false)
    end
    s._selectedGhosts = {}

    local getSelFn = rawget(_G, 'GetSelectedUnits')
    local curSel = getSelFn and getSelFn()
    if curSel and table.getn(curSel) > 0 then
        local selUnitsFn = rawget(_G, 'SelectUnits')
        if selUnitsFn then
            pcall(selUnitsFn, nil)
        end
    end

    local ordersMod = s._ordersModule or GetOrdersModule()
    if ordersMod and ordersMod.SetAvailableOrders then
        pcall(ordersMod.SetAvailableOrders, {}, {}, {})
    end

    local constructionMod = s._constructionModule or GetConstructionModule()
    if constructionMod and constructionMod.OnSelection then
        pcall(constructionMod.OnSelection, {}, {}, false)
    end
end

local function RemoveGhost(a, b)
    local s, ghostId
    if IsInstance(a) then
        s = a
        ghostId = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        ghostId = b
    else
        s = GetDefaultSelection()
        ghostId = a
    end

    local gid = (type(ghostId) == 'table' and (ghostId.id or ghostId.ghostId)) or ghostId
    if gid and s._selectedGhosts and s._selectedGhosts[gid] then
        local g = s._selectedGhosts[gid]
        HighlightGhost(g, false)
        s._selectedGhosts[gid] = nil
        s:_SyncUI()
    end
end

local function IsActive(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    for _ in pairs(s._selectedGhosts) do
        return true
    end
    return false
end

local function GetSelection(a)
    local s = IsInstance(a) and a or GetDefaultSelection()
    local activeGhosts = GetActiveGhosts(s)

    -- Prune any ghosts that are no longer active
    local pruned = false
    for id, _ in pairs(s._selectedGhosts) do
        if not activeGhosts[id] then
            s._selectedGhosts[id] = nil
            pruned = true
        end
    end
    if pruned and not IsActive(s) then
        ClearSelection(s)
    end

    local res = {}
    local idx = 1
    for id, ghost in pairs(s._selectedGhosts) do
        res[idx] = ghost
        res[id] = ghost
        idx = idx + 1
    end
    return res
end

local function SetSelection(a, b)
    local s, selection
    if IsInstance(a) then
        s = a
        selection = b
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        selection = b
    else
        s = GetDefaultSelection()
        selection = a
    end

    s._selectedGhosts = {}
    if selection then
        for k, v in pairs(selection) do
            local ghost = (type(v) == 'table' and (v.id or v.ghostId)) and v or (type(k) == 'table' and k)
            if ghost and (ghost.id or ghost.ghostId) then
                local gid = ghost.id or ghost.ghostId
                s._selectedGhosts[gid] = ghost
            end
        end
    end
    s:_SyncUI()
end

local function QueuePreOrderNative(s, cmdType, targetData, isShift)
    local issuePreOrderFn = rawget(_G, 'IssueTransportPreOrder')
    if not issuePreOrderFn or not s or not s._selectedGhosts then
        return
    end
    local realUnits = {}
    for _, ghost in pairs(s._selectedGhosts) do
        local rUnit = ghost.realUnit or (ghost.id and tostring(ghost.id)) or ghost
        if rUnit then
            table.insert(realUnits, rUnit)
        end
    end
    if table.getn(realUnits) > 0 then
        local ok, res = pcall(issuePreOrderFn, realUnits, cmdType, targetData, not isShift)
        SafeWarn("QueuePreOrderNative: IssueTransportPreOrder called for " .. tostring(table.getn(realUnits)) .. " units, ok=" .. tostring(ok) .. ", res=" .. tostring(res))
    end
end

local function HandleWorldClick(a, b, c)
    local s, worldView, event
    if IsInstance(a) then
        s = a
        worldView = b
        event = c
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        worldView = b
        event = c
    else
        s = GetDefaultSelection()
        worldView = a
        event = b
    end

    if not event then
        return false
    end

    local isLeft = false
    local isRight = false

    local isPress = (event.Type == 'ButtonPress' or event.Type == 'ButtonDClick' or event.Type == 'MouseDown' or event.Type == 'ButtonDown' or not event.Type)
    if isPress then
        if event.KeyCode == 1 or event.Button == 1 or event.Button == 'Left' or event.LeftClick then
            isLeft = true
        elseif event.KeyCode == 3 or event.Button == 3 or event.Button == 'Right' or event.RightClick then
            isRight = true
        elseif event.Modifiers then
            if event.Modifiers.Left then isLeft = true end
            if event.Modifiers.Right then isRight = true end
        end
    end

    local isShift = (event.Modifiers and event.Modifiers.Shift == true) or false

    -- Check if FAF CommandMode is currently active (e.g. build placement or tactical order)
    local cmdModeMod = GetCommandModeModule(s)
    local cMode = false
    local cData = false
    if cmdModeMod and cmdModeMod.GetCommandMode then
        local okMode, m, d = pcall(cmdModeMod.GetCommandMode)
        if okMode then
            cMode = m
            cData = d
        end
    end

    -- 1. In-Game CommandMode Placement Interception (when ghosts are actively selected)
    if IsActive(s) and cMode and isLeft then
        local targetData = CloneTargetData(ResolveTargetPosition(worldView, event))
        local buf = s._buffer or (s._manager and s._manager:GetBuffer())

        if cMode == 'build' or cMode == 'buildanchored' or event.CommandType == 'UNITCOMMAND_BuildMobile' then
            local bpId = (type(cData) == 'table' and (cData.name or cData.blueprintId or cData.BlueprintId or cData[1]))
                or (type(cData) == 'string' and cData)
                or event.BlueprintId
                or (type(targetData) == 'table' and targetData.blueprintId)
            if bpId and type(targetData) == 'table' then
                targetData.blueprintId = bpId
            end

            local getMouseTargetFn = rawget(_G, 'GetMouseTarget')
            if getMouseTargetFn then
                local okT, targetObj = pcall(getMouseTargetFn)
                if okT and targetObj and targetObj.entity then
                    if type(targetData) == 'table' then
                        targetData.targetEntity = targetObj.entity
                    end
                end
            end

            if buf and buf.AddOrder and bpId then
                for _, ghost in pairs(s._selectedGhosts) do
                    local unit = ghost.realUnit or ghost
                    local unitId = (unit.GetEntityId and unit:GetEntityId())
                        or unit.id
                        or ghost.id
                        or ghost.ghostId
                    buf:AddOrder(unitId, 'UNITCOMMAND_BuildMobile', CloneTargetData(targetData), isShift)
                end
                QueuePreOrderNative(s, 'UNITCOMMAND_BuildMobile', CloneTargetData(targetData), isShift)
            end

            if not isShift and cmdModeMod and cmdModeMod.EndCommandMode then
                pcall(cmdModeMod.EndCommandMode, true)
                s:_SyncUI()
            end
            return true
        elseif cMode == 'order' then
            local orderName = (cData and cData.name) or 'Move'
            local cmdType = MapRuleUccToCommand(orderName)

            if buf and buf.AddOrder then
                for _, ghost in pairs(s._selectedGhosts) do
                    local unit = ghost.realUnit or ghost
                    local unitId = (unit.GetEntityId and unit:GetEntityId())
                        or unit.id
                        or ghost.id
                        or ghost.ghostId
                    buf:AddOrder(unitId, cmdType, CloneTargetData(targetData), isShift)
                end
                QueuePreOrderNative(s, cmdType, CloneTargetData(targetData), isShift)
            end

            if not isShift and cmdModeMod and cmdModeMod.EndCommandMode then
                pcall(cmdModeMod.EndCommandMode, true)
            end
            return true
        end
    end

    -- 2. Right Click Handling (Interception of Orders)
    if isRight then
        if not IsActive(s) then
            return false
        end

        -- If CommandMode was active (e.g. build placement mode), exit it cleanly on right-click
        if cMode and cmdModeMod and cmdModeMod.EndCommandMode then
            pcall(cmdModeMod.EndCommandMode, true)
            s:_SyncUI()
        end

        local commandType = event.CommandType or 'Move'
        local targetData = CloneTargetData(ResolveTargetPosition(worldView, event))
        if type(targetData) == 'table' then
            if not targetData.blueprintId and event.BlueprintId then
                targetData.blueprintId = event.BlueprintId
            end
            if not targetData.blueprint and event.Blueprint then
                targetData.blueprint = event.Blueprint
            end
            if not targetData.count and event.Count then
                targetData.count = event.Count
            end
        end

        local getMouseTargetFn = rawget(_G, 'GetMouseTarget')
        if getMouseTargetFn then
            local okT, targetObj = pcall(getMouseTargetFn)
            if okT and targetObj and targetObj.entity then
                local ent = targetObj.entity
                if type(targetData) == 'table' then
                    targetData.targetEntity = ent
                end
                local isEnemy = ent.GetArmy and rawget(_G, 'GetFocusArmy') and (ent:GetArmy() ~= GetFocusArmy())
                if isEnemy then
                    commandType = 'Attack'
                end
            end
        end

        local count = 0
        local buf = s._buffer or (s._manager and s._manager:GetBuffer())
        if buf and buf.AddOrder then
            for _, ghost in pairs(s._selectedGhosts) do
                count = count + 1
                local unit = ghost.realUnit or ghost
                local unitId = (unit.GetEntityId and unit:GetEntityId())
                    or unit.id
                    or ghost.id
                    or ghost.ghostId
                buf:AddOrder(unitId, commandType, CloneTargetData(targetData), isShift)
            end
            QueuePreOrderNative(s, commandType, CloneTargetData(targetData), isShift)
        end

        SafeWarn("HandleWorldClick: right click queued order " .. tostring(commandType) .. " for " .. tostring(count) .. " selected ghosts")
        return true
    end

    -- 3. Left Click Handling (Ghost Selection & Hit-testing)
    if isLeft then
        local activeGhosts = GetActiveGhosts(s)
        local mx = event.MouseX or 0
        local my = event.MouseY or 0
        local closestGhost = nil
        local closestScreenDist = 999999
        local closestWorldDist = 999999
        local hitScreenGhost = nil
        local hitWorldGhost = nil
        local ghostCount = 0

        -- 3.1. Query current 3D mouse ground coordinate
        local mouseWorldPos = nil
        local getMousePosFn = rawget(_G, 'GetMouseWorldPos')
        if getMousePosFn then
            local ok, mPos = pcall(getMousePosFn)
            if ok and mPos and (mPos[1] or mPos.x) then
                mouseWorldPos = { mPos[1] or mPos.x, mPos[2] or mPos.y or 0, mPos[3] or mPos.z }
            end
        end

        for id, ghost in pairs(activeGhosts) do
            ghostCount = ghostCount + 1
            if ghost and ghost.position then
                local gx = ghost.position.x or ghost.position[1]
                local gy = ghost.position.y or ghost.position[2] or 0
                local gz = ghost.position.z or ghost.position[3]

                -- Test A: World-space ground distance (radius 5.0 world units)
                if mouseWorldPos and gx and gz then
                    local wdx = gx - mouseWorldPos[1]
                    local wdz = gz - mouseWorldPos[3]
                    local wdist = math.sqrt(wdx * wdx + wdz * wdz)
                    if wdist <= 8.0 and wdist < closestWorldDist then
                        closestWorldDist = wdist
                        hitWorldGhost = ghost
                    end
                end

                -- Test B: Screen-space projection distance (radius 50 pixels)
                local proj = ProjectPos(worldView, ghost.position)
                if proj then
                    local px = proj.x or proj[1]
                    local py = proj.y or proj[2]
                    if px and py then
                        local sdx = px - mx
                        local sdy = py - my
                        local sdist = math.sqrt(sdx * sdx + sdy * sdy)
                        local effectiveRadius = math.max(s._hitRadius or 50, 50)
                        if sdist <= effectiveRadius and sdist < closestScreenDist then
                            closestScreenDist = sdist
                            hitScreenGhost = ghost
                        end
                    end
                end
            end
        end

        closestGhost = hitScreenGhost or hitWorldGhost

        local isDClick = (event.Type == 'ButtonDClick' or event.DClick == true)
        SafeWarn("HandleWorldClick: left click at (" .. tostring(mx) .. "," .. tostring(my) .. "), ghosts=" .. tostring(ghostCount) .. ", hit=" .. tostring(closestGhost and (closestGhost.id or closestGhost.ghostId)) .. (isDClick and " [DCLICK]" or ""))

        if closestGhost then
            if isDClick then
                -- Double click: pick all active ghosts from this transport (or all active ghosts)
                SafeWarn("HandleWorldClick: double-click selecting all active ghosts in formation!")
                for _, prevG in pairs(s._selectedGhosts) do
                    HighlightGhost(prevG, false)
                end
                s._selectedGhosts = {}
                local targetTransport = closestGhost.transport
                for id, ghost in pairs(activeGhosts) do
                    if not targetTransport or ghost.transport == targetTransport then
                        local gid = ghost.id or ghost.ghostId or id
                        s._selectedGhosts[gid] = ghost
                        HighlightGhost(ghost, true)
                    end
                end
            elseif isShift then
                local gid = closestGhost.id or closestGhost.ghostId
                if s._selectedGhosts[gid] then
                    s._selectedGhosts[gid] = nil
                    HighlightGhost(closestGhost, false)
                else
                    s._selectedGhosts[gid] = closestGhost
                    HighlightGhost(closestGhost, true)
                end
            else
                for _, prevG in pairs(s._selectedGhosts) do
                    HighlightGhost(prevG, false)
                end
                s._selectedGhosts = {}
                local gid = closestGhost.id or closestGhost.ghostId
                s._selectedGhosts[gid] = closestGhost
                HighlightGhost(closestGhost, true)
            end

            -- Clear engine real-unit selection so selection focuses cleanly on ghosts.
            -- Do NOT pass attached cargo units to SelectUnits, as stock engine redirects
            -- attached units to the parent transport, wiping ghost selection and orders!
            local selUnitsFn = rawget(_G, 'SelectUnits')
            if selUnitsFn then
                pcall(selUnitsFn, nil)
            end

            s:_SyncUI()
            return true
        else
            -- Click landed on empty terrain or real world entity
            if not isShift and IsActive(s) then
                s:ClearSelection()
            end
            return false
        end
    end

    return false
end

local function HandleWorldDrag(a, b, c, d, e, f, g)
    local s, worldView, minX, minY, maxX, maxY, isShift
    if IsInstance(a) then
        s = a
        worldView = b
        minX = c
        minY = d
        maxX = e
        maxY = f
        isShift = g
    elseif a == DropGhostsSelection then
        s = GetDefaultSelection()
        worldView = b
        minX = c
        minY = d
        maxX = e
        maxY = f
        isShift = g
    else
        s = GetDefaultSelection()
        worldView = a
        minX = b
        minY = c
        maxX = d
        maxY = e
        isShift = f
    end

    local x1 = math.min(minX, maxX) - 15
    local x2 = math.max(minX, maxX) + 15
    local y1 = math.min(minY, maxY) - 15
    local y2 = math.max(minY, maxY) + 15

    local activeGhosts = GetActiveGhosts(s)

    local captured = {}
    local ghostCount = 0
    for id, ghost in pairs(activeGhosts) do
        ghostCount = ghostCount + 1
        if ghost and ghost.position then
            local proj = ProjectPos(worldView, ghost.position)
            if proj then
                local px = proj.x or proj[1]
                local py = proj.y or proj[2]
                if px and py and px >= x1 and px <= x2 and py >= y1 and py <= y2 then
                    table.insert(captured, ghost)
                end
            end
        end
    end

    SafeWarn("HandleWorldDrag: box (" .. tostring(x1) .. "," .. tostring(y1) .. ") - (" .. tostring(x2) .. "," .. tostring(y2) .. "), ghosts=" .. tostring(ghostCount) .. ", captured=" .. tostring(table.getn(captured)))

    if table.getn(captured) > 0 then
        if not isShift then
            for _, prevG in pairs(s._selectedGhosts) do
                HighlightGhost(prevG, false)
            end
            s._selectedGhosts = {}
        end
        for _, ghost in ipairs(captured) do
            local gid = ghost.id or ghost.ghostId
            s._selectedGhosts[gid] = ghost
            HighlightGhost(ghost, true)
        end

        -- Clear engine real-unit selection so selection focuses cleanly on ghosts.
        local selUnitsFn = rawget(_G, 'SelectUnits')
        if selUnitsFn then
            pcall(selUnitsFn, nil)
        end

        s:_SyncUI()
        return true
    end

    return false
end

-- Export functions on DropGhostsSelection metatable/table
DropGhostsSelection.Create = CreateSelection
DropGhostsSelection.GetDefaultSelection = GetDefaultSelection
DropGhostsSelection.HandleWorldClick = HandleWorldClick
DropGhostsSelection.HandleWorldDrag = HandleWorldDrag
DropGhostsSelection.GetSelection = GetSelection
DropGhostsSelection.SetSelection = SetSelection
DropGhostsSelection.ClearSelection = ClearSelection
DropGhostsSelection.RemoveGhost = RemoveGhost
DropGhostsSelection.IsActive = IsActive
DropGhostsSelection.GetManager = GetManager
DropGhostsSelection.SetManager = SetManager
DropGhostsSelection.GetBuffer = GetBuffer
DropGhostsSelection.SetBuffer = SetBuffer
DropGhostsSelection.SetHitRadius = SetHitRadius
DropGhostsSelection.SetOrdersModule = SetOrdersModule
DropGhostsSelection.SetConstructionModule = SetConstructionModule
DropGhostsSelection.SetCommandModeModule = SetCommandModeModule
DropGhostsSelection.DropGhostsSelection = DropGhostsSelection

HandleWorldClick = HandleWorldClick
HandleWorldDrag = HandleWorldDrag
ClearSelection = ClearSelection
RemoveGhost = RemoveGhost
GetDefaultSelection = GetDefaultSelection
Create = function(customManager, customBuffer)
    return CreateSelection(customManager, customBuffer)
end

if rawget(_G, 'rawset') then
    rawset(_G, 'DropGhostsSelection', DropGhostsSelection)
end

return DropGhostsSelection
