-- I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_dispatcher.lua
-- Waypoint path rendering and automatic order dispatcher upon transport cargo touchdown.

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

local DropGhostsBuffer = nil
local DropGhostsManager = nil

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
ResolveBufferModule()
ResolveManagerModule()

local WorldMeshClass = nil
if rawget(_G, 'import') then
    local ok, wmModule = pcall(import, '/lua/ui/controls/worldmesh.lua')
    if ok and wmModule and wmModule.WorldMesh then
        WorldMeshClass = wmModule.WorldMesh
    end
end

local ImportedCommandMeshes = nil
if rawget(_G, 'import') then
    local ok, cmModule = pcall(import, '/lua/ui/game/commandmeshes.lua')
    if ok and cmModule then
        ImportedCommandMeshes = cmModule
    end
end

local DefaultCommandMeshResources = {
    Move = { '/meshes/game/Move_lod0.scm', '/meshes/game/Move_albedo.dds' },
    Attack = { '/meshes/game/Attack_lod0.scm', '/meshes/game/Attack_albedo.dds' },
    AggressiveMove = { '/meshes/game/Attack_lod0.scm', '/meshes/game/Attack_albedo.dds' },
    Guard = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' },
    Assist = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' },
    Capture = { '/meshes/game/Capture_lod0.scm', '/meshes/game/Capture_albedo.dds' },
    Ferry = { '/meshes/game/Ferry_lod0.scm', '/meshes/game/Ferry_albedo.dds' },
    Nuke = { '/meshes/game/Launch_Missile02_lod0.scm', '/meshes/game/Launch_Missile02_albedo.dds' },
    Tactical = { '/meshes/game/Launch_Missile01_lod0.scm', '/meshes/game/Launch_Missile01_albedo.dds' },
    TransportLoadUnits = { '/meshes/game/Load_lod0.scm', '/meshes/game/Load_albedo.dds' },
    TransportReverseLoadUnits = { '/meshes/game/Load_lod0.scm', '/meshes/game/Load_albedo.dds' },
    TransportUnloadUnits = { '/meshes/game/Unload_lod0.scm', '/meshes/game/Unload_albedo.dds' },
    OverCharge = { '/meshes/game/Overcharge_lod0.scm', '/meshes/game/Overcharge_albedo.dds' },
    Patrol = { '/meshes/game/Patrol_lod0.scm', '/meshes/game/Patrol_albedo.dds' },
    Reclaim = { '/meshes/game/Reclaim_lod0.scm', '/meshes/game/Reclaim_albedo.dds' },
    Repair = { '/meshes/game/Repair_lod0.scm', '/meshes/game/Repair_albedo.dds' },
    Sacrifice = { '/meshes/game/Sacrifice_lod0.scm', '/meshes/game/Sacrifice_albedo.dds' },
    Teleport = { '/meshes/game/Teleport_lod0.scm', '/meshes/game/Teleport_albedo.dds' },
    Build = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' },
    UNITCOMMAND_BuildMobile = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' },
    UNITCOMMAND_BuildFactory = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' },
    UNITCOMMAND_Upgrade = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' }
}

local CustomCommandMeshResources = nil

local function GetCommandMeshResources()
    if CustomCommandMeshResources then
        return CustomCommandMeshResources
    end
    local rawRes = rawget(_G, 'commandMeshResources')
    if rawRes then
        return rawRes
    end
    if ImportedCommandMeshes and ImportedCommandMeshes.commandMeshResources then
        return ImportedCommandMeshes.commandMeshResources
    end
    return DefaultCommandMeshResources
end

local function SetCommandMeshResources(res)
    CustomCommandMeshResources = res
end

local function GetWorldMeshClass()
    return WorldMeshClass or rawget(_G, 'WorldMesh')
end

local function SetWorldMeshClass(cls)
    WorldMeshClass = cls
end

local function GetCargoUnits(transport)
    if not transport then
        return {}
    end
    local getAttachedFn = rawget(_G, 'GetAttachedUnitsList')
    if getAttachedFn then
        local ok, units = pcall(getAttachedFn, { transport })
        if ok and type(units) == 'table' then
            return units
        end
    end
    if transport.GetCargo then
        local ok, units = pcall(transport.GetCargo, transport)
        if ok and type(units) == 'table' then
            return units
        end
    end
    if transport.attachedUnits then
        return transport.attachedUnits
    end
    return {}
end

local function ResolveTargetPosition(order)
    if not order then
        return nil
    end
    local td = order.targetData
    if not td then
        return nil
    end

    if td.GetPosition then
        local ok, pos = pcall(td.GetPosition, td)
        if ok and pos then
            return pos
        end
    end
    if td.Position then
        return td.Position
    end
    if td.TargetPos then
        return td.TargetPos
    end
    if type(td) == 'table' and (td.x or td[1]) then
        local x = td.x or td[1] or 0
        local y = td.y or td[2] or 0
        local z = td.z or td[3] or 0
        return {
            x = x,
            y = y,
            z = z,
            [1] = x,
            [2] = y,
            [3] = z
        }
    end
    return nil
end

DropGhostsDispatcher = {}
DropGhostsDispatcher.__index = DropGhostsDispatcher

local _defaultInstance = nil

local function CreateDispatcher(customManager, customBuffer)
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
        _trackedUnits = {},
        _waypointMeshes = {},
        _dispatchFn = nil,
        _blueprintDispatchFn = nil,
    }
    return setmetatable(instance, DropGhostsDispatcher)
end

function GetDefaultDispatcher()
    if not _defaultInstance then
        _defaultInstance = CreateDispatcher()
    end
    return _defaultInstance
end

local function IsInstance(val)
    return type(val) == 'table' and val ~= DropGhostsDispatcher and val._trackedUnits ~= nil
end

local function GetManager(a)
    local s = IsInstance(a) and a or GetDefaultDispatcher()
    return s._manager
end

local function SetManager(a, b)
    local s, mgr
    if IsInstance(a) then
        s = a
        mgr = b
    elseif a == DropGhostsDispatcher then
        s = GetDefaultDispatcher()
        mgr = b
    else
        s = GetDefaultDispatcher()
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
    local s = IsInstance(a) and a or GetDefaultDispatcher()
    return s._buffer
end

local function SetBuffer(a, b)
    local s, buf
    if IsInstance(a) then
        s = a
        buf = b
    elseif a == DropGhostsDispatcher then
        s = GetDefaultDispatcher()
        buf = b
    else
        s = GetDefaultDispatcher()
        buf = a
    end
    s._buffer = buf
end

local function GetTrackedUnits(a)
    local s = IsInstance(a) and a or GetDefaultDispatcher()
    return s._trackedUnits
end

local function _ClearWaypointMeshesForUnit(s, unitId)
    local list = s._waypointMeshes[unitId]
    if list then
        for i = 1, table.getn(list) do
            local item = list[i]
            if item and item.mesh then
                if item.mesh.SetHidden then
                    pcall(item.mesh.SetHidden, item.mesh, true)
                end
                if item.mesh.Destroy then
                    pcall(item.mesh.Destroy, item.mesh)
                end
                item.isDestroyed = true
            end
        end
        s._waypointMeshes[unitId] = nil
    end
end

local function _DispatchOrderInternal(s, unit, order)
    if not unit or not order then
        return
    end

    if rawget(_G, 'IssueTransportPreOrder') then
        SafeWarn("Order already dispatched natively by engine on touchdown")
        return
    end

    local cmdType = order.commandType or order.command or 'Move'
    local targetData = order.targetData
    local isClear = false
    local units = { unit }

    local targetPos = ResolveTargetPosition(order)
    local targetParam = targetData
    if targetPos then
        local vecFn = rawget(_G, 'Vector')
        if vecFn then
            local okV, vec = pcall(vecFn, targetPos[1] or targetPos.x, targetPos[2] or targetPos.y or 0, targetPos[3] or targetPos.z)
            if okV and vec then
                targetParam = vec
            end
        end
    end

    local isBuildCmd = (cmdType == 'UNITCOMMAND_BuildMobile' or cmdType == 'UNITCOMMAND_BuildFactory' or cmdType == 'Build' or (targetData and (targetData.blueprintId or targetData.blueprint)))
    if isBuildCmd then
        local bpId = targetData and (targetData.blueprintId or targetData.blueprint)
        local count = targetData and (targetData.count or 1) or 1

        if s._blueprintDispatchFn then
            s._blueprintDispatchFn(units, cmdType, bpId, count, isClear, targetPos)
            return
        end

        local bpCmdFn = rawget(_G, 'IssueBlueprintCommandToUnits')
        if bpCmdFn then
            local ok = pcall(bpCmdFn, units, cmdType, bpId, count, isClear)
            if ok then
                SafeWarn("Dispatched blueprint build " .. tostring(bpId) .. " to unit via IssueBlueprintCommandToUnits")
                return
            end
        end

        local oldSelection = rawget(_G, 'GetSelectedUnits') and GetSelectedUnits()
        local selUnitsFn = rawget(_G, 'SelectUnits')
        if selUnitsFn then
            pcall(selUnitsFn, units)
        end
        local issueBpCmd = rawget(_G, 'IssueBlueprintCommand')
        if issueBpCmd then
            pcall(issueBpCmd, cmdType, bpId, count, isClear)
            SafeWarn("Dispatched blueprint build " .. tostring(bpId) .. " to unit via IssueBlueprintCommand")
        end
        if selUnitsFn then
            pcall(selUnitsFn, oldSelection)
        end
        return
    end

    if s._dispatchFn then
        s._dispatchFn(units, cmdType, targetParam, isClear)
        return
    end

    if rawget(_G, 'IssueTransportPreOrder') then
        SafeWarn("Order already dispatched natively by engine on touchdown")
        return
    end

    local issued = false
    local issueCmdFn = rawget(_G, 'IssueUnitCommand')
    if issueCmdFn then
        local ok = pcall(issueCmdFn, units, cmdType, targetParam, isClear)
        if ok then
            issued = true
        end
    end

    if not issued then
        local issueSingleCmdFn = rawget(_G, 'IssueUnitCommandToUnit')
        if issueSingleCmdFn then
            local ok = pcall(issueSingleCmdFn, unit, cmdType, targetParam, isClear)
            if ok then
                issued = true
            end
        end
    end

    if not issued then
        -- Selection fallback guarantees native engine command reception
        local oldSelection = rawget(_G, 'GetSelectedUnits') and GetSelectedUnits()
        local selUnitsFn = rawget(_G, 'SelectUnits')
        if selUnitsFn then
            pcall(selUnitsFn, units)
        end
        local issueCmd = rawget(_G, 'IssueCommand')
        if issueCmd then
            pcall(issueCmd, cmdType, targetParam, isClear)
        end
        if selUnitsFn then
            pcall(selUnitsFn, oldSelection)
        end
    end

    SafeWarn("Dispatched order " .. tostring(cmdType) .. " to unit " .. tostring(unit.GetEntityId and unit:GetEntityId() or unit))
end

local function DispatchOrder(a, b, c)
    local s, unit, order
    if IsInstance(a) then
        s = a
        unit = b
        order = c
    elseif a == DropGhostsDispatcher then
        s = GetDefaultDispatcher()
        unit = b
        order = c
    else
        s = GetDefaultDispatcher()
        unit = a
        order = b
    end
    _DispatchOrderInternal(s, unit, order)
end

local function OnBeat(a)
    local s = IsInstance(a) and a or GetDefaultDispatcher()

    local activeGhosts = {}
    if s._manager then
        if s._manager.GetActiveGhosts then
            activeGhosts = s._manager:GetActiveGhosts()
        elseif type(s._manager) == 'table' and s._manager._ghosts then
            activeGhosts = s._manager._ghosts
        end
    end

    -- 1. Register active ghosts into tracked units
    for ghostId, ghost in pairs(activeGhosts) do
        local unit = ghost.realUnit or ghost
        local unitId = (unit.GetEntityId and unit:GetEntityId())
            or unit.id
            or ghost.id
            or ghostId

        if not s._trackedUnits[unitId] then
            s._trackedUnits[unitId] = {
                unit = unit,
                ghostId = ghostId,
                transport = ghost.transport,
                hasGhost = true,
            }
        else
            s._trackedUnits[unitId].hasGhost = true
            s._trackedUnits[unitId].ghostId = ghostId
            if ghost.transport then
                s._trackedUnits[unitId].transport = ghost.transport
            end
        end
    end

    -- 2. Check each tracked unit for touchdown (disembarkation) or destruction
    local disembarked = {}
    local deadUnits = {}
    local cancelledUnits = {}

    for unitId, tracked in pairs(s._trackedUnits) do
        local unit = tracked.unit
        local ghostId = tracked.ghostId
        local transport = tracked.transport

        local isDead = false
        if unit then
            if unit.IsDead then
                local ok, d = pcall(unit.IsDead, unit)
                if ok and d then
                    isDead = true
                end
            end
            if not isDead and unit.BeenDestroyed then
                local ok, bd = pcall(unit.BeenDestroyed, unit)
                if ok and bd then
                    isDead = true
                end
            end
        end

        if isDead then
            table.insert(deadUnits, unitId)
        else
            local isAttached = nil

            -- Check Sim unit state 'Attached'
            if unit and unit.IsUnitState then
                local ok, att = pcall(unit.IsUnitState, unit, 'Attached')
                if ok and type(att) == 'boolean' then
                    isAttached = att
                end
            end

            -- Also check transport cargo list if transport is known
            if transport then
                local transportDead = false
                if transport.IsDead then
                    local ok, td = pcall(transport.IsDead, transport)
                    if ok and td then
                        transportDead = true
                    end
                end

                if transportDead then
                    -- Transport was destroyed in flight: discard orders, do not dispatch to dead cargo
                    table.insert(deadUnits, unitId)
                else
                    local cargo = GetCargoUnits(transport)
                    local inCargo = false
                    for _, cUnit in ipairs(cargo) do
                        local cid = (cUnit.GetEntityId and cUnit:GetEntityId()) or cUnit.id or tostring(cUnit)
                        if cUnit == unit or cid == unitId then
                            inCargo = true
                            break
                        end
                    end
                    if not inCargo then
                        isAttached = false
                    elseif isAttached == nil then
                        isAttached = true
                    end

                    if isAttached == false then
                        table.insert(disembarked, unitId)
                    end
                end
            else
                if isAttached == false then
                    table.insert(disembarked, unitId)
                end
            end
        end
    end

    -- Process dead units
    for _, unitId in ipairs(deadUnits) do
        local tracked = s._trackedUnits[unitId]
        local ghostId = tracked and tracked.ghostId or unitId
        if s._buffer and s._buffer.ClearUnitOrders then
            s._buffer:ClearUnitOrders(unitId)
        end
        if s._manager and s._manager.DestroyGhost then
            s._manager:DestroyGhost(ghostId)
        end
        _ClearWaypointMeshesForUnit(s, unitId)
        s._trackedUnits[unitId] = nil
    end

    -- Process disembarked units (touchdown on the ground!)
    for _, unitId in ipairs(disembarked) do
        local tracked = s._trackedUnits[unitId]
        if tracked then
            local unit = tracked.unit
            local ghostId = tracked.ghostId or unitId

            local orders = {}
            if s._buffer and s._buffer.GetOrders then
                local bufOrders = s._buffer:GetOrders(unitId)
                if bufOrders then
                    for _, ord in ipairs(bufOrders) do
                        table.insert(orders, ord)
                    end
                end
            end

            tracked.disembarkBeat = (tracked.disembarkBeat or 0) + 1

            if tracked.disembarkBeat == 1 then
                SafeWarn("Unit " .. tostring(unitId) .. " disembarked! Orders to dispatch: " .. tostring(table.getn(orders)))
            end

            -- Dispatch all buffered orders to the real unit
            for _, order in ipairs(orders) do
                _DispatchOrderInternal(s, unit, order)
            end

            -- Check if unit has accepted orders in its command queue
            local queue = (unit and unit.GetCommandQueue and unit:GetCommandQueue()) or {}
            local accepted = (table.getn(queue) > 0)

            -- Complete tracking when orders are accepted, when no orders exist, or after 15 beats (~1.5s max touchdown window)
            if accepted or tracked.disembarkBeat >= 15 or table.getn(orders) == 0 then
                if accepted then
                    SafeWarn("Unit " .. tostring(unitId) .. " accepted orders! Queue length: " .. tostring(table.getn(queue)))
                end

                -- Clear buffered orders for that unit
                if s._buffer and s._buffer.ClearUnitOrders then
                    s._buffer:ClearUnitOrders(unitId)
                end

                -- Clean up ghost from the manager
                if s._manager and s._manager.DestroyGhost then
                    s._manager:DestroyGhost(ghostId)
                end

                -- Clean up waypoint meshes
                _ClearWaypointMeshesForUnit(s, unitId)

                -- Clear tracked record
                s._trackedUnits[unitId] = nil
            end
        end
    end
end

local function UpdateWaypoints(a, b)
    local s, worldView
    if IsInstance(a) then
        s = a
        worldView = b
    elseif a == DropGhostsDispatcher then
        s = GetDefaultDispatcher()
        worldView = b
    else
        s = GetDefaultDispatcher()
        worldView = a
    end

    local activeGhosts = {}
    if s._manager then
        if s._manager.GetActiveGhosts then
            activeGhosts = s._manager:GetActiveGhosts()
        elseif type(s._manager) == 'table' and s._manager._ghosts then
            activeGhosts = s._manager._ghosts
        end
    end

    local resources = GetCommandMeshResources()
    local MeshCtor = GetWorldMeshClass()

    local activeUnitIds = {}

    for gid, ghost in pairs(activeGhosts) do
        local unit = ghost.realUnit or ghost
        local unitId = (unit.GetEntityId and unit:GetEntityId())
            or unit.id
            or ghost.id
            or gid
        activeUnitIds[unitId] = true

        local orders = {}
        if s._buffer and s._buffer.GetOrders then
            orders = s._buffer:GetOrders(unitId) or {}
        end

        local unitMeshes = s._waypointMeshes[unitId] or {}
        s._waypointMeshes[unitId] = unitMeshes

        local orderCount = table.getn(orders)
        for i = 1, orderCount do
            local order = orders[i]
            local cmdType = order.commandType or order.command or 'Move'
            local targetPos = ResolveTargetPosition(order)

            if targetPos then
                local res = resources[cmdType] or resources['Move'] or DefaultCommandMeshResources['Move']
                local meshName = res and res[1] or '/meshes/game/Move_lod0.scm'
                local textureName = res and res[2] or '/meshes/game/Move_albedo.dds'

                local existing = unitMeshes[i]
                if existing and existing.mesh and not existing.isDestroyed then
                    if existing.cmdType ~= cmdType then
                        if existing.mesh.SetMesh then
                            existing.mesh:SetMesh({
                                MeshName = meshName,
                                TextureName = textureName,
                                ShaderName = 'RallyPoint',
                                UniformScale = 0.15,
                                LODCutoff = 1000.0,
                            })
                        end
                        existing.cmdType = cmdType
                    end
                    if existing.mesh.SetStance then
                        existing.mesh:SetStance(targetPos)
                    end
                    existing.position = targetPos
                else
                    if MeshCtor then
                        local ok, m = pcall(MeshCtor)
                        if ok and m then
                            if m.SetMesh then
                                m:SetMesh({
                                    MeshName = meshName,
                                    TextureName = textureName,
                                    ShaderName = 'RallyPoint',
                                    UniformScale = 0.15,
                                    LODCutoff = 1000.0,
                                })
                            end
                            if m.SetLifetimeParameter then
                                pcall(m.SetLifetimeParameter, m, 10)
                            end
                            if m.SetStance then
                                m:SetStance(targetPos)
                            end
                            if m.SetHidden then
                                pcall(m.SetHidden, m, false)
                            end
                            unitMeshes[i] = {
                                mesh = m,
                                cmdType = cmdType,
                                position = targetPos,
                                isDestroyed = false,
                            }
                        end
                    end
                end
            end
        end

        -- Clean up excess meshes if queue has shrunk
        local currentMeshCount = table.getn(unitMeshes)
        if currentMeshCount > orderCount then
            for i = orderCount + 1, currentMeshCount do
                local item = unitMeshes[i]
                if item and item.mesh then
                    if item.mesh.Destroy then
                        pcall(item.mesh.Destroy, item.mesh)
                    end
                    item.isDestroyed = true
                end
                unitMeshes[i] = nil
            end
        end
    end

    -- Clean up meshes for units that are no longer active ghosts
    local staleUnits = {}
    for uid, _ in pairs(s._waypointMeshes) do
        if not activeUnitIds[uid] then
            table.insert(staleUnits, uid)
        end
    end
    for _, uid in ipairs(staleUnits) do
        _ClearWaypointMeshesForUnit(s, uid)
    end

    -- Render connecting path lines if worldView or engine provides line drawing hook
    local lineDrawFn = (worldView and worldView.DrawLine) or rawget(_G, 'DrawLine')
    if lineDrawFn then
        for gid, ghost in pairs(activeGhosts) do
            local unit = ghost.realUnit or ghost
            local unitId = (unit.GetEntityId and unit:GetEntityId())
                or unit.id
                or ghost.id
                or gid
            local unitMeshes = s._waypointMeshes[unitId]
            if unitMeshes and table.getn(unitMeshes) > 0 then
                local prevPos = ghost.position
                for _, wm in ipairs(unitMeshes) do
                    if wm and wm.position and prevPos then
                        pcall(lineDrawFn, worldView, prevPos, wm.position, 'ff00ff00')
                        prevPos = wm.position
                    end
                end
            end
        end
    end
end

local function DrawWaypoints(a, b)
    return UpdateWaypoints(a, b)
end

local function ClearAll(a)
    local s = IsInstance(a) and a or GetDefaultDispatcher()
    for uid, _ in pairs(s._waypointMeshes) do
        _ClearWaypointMeshesForUnit(s, uid)
    end
    s._waypointMeshes = {}
    s._trackedUnits = {}
end

local function GetWaypoints(a, b)
    local s, unitId
    if IsInstance(a) then
        s = a
        unitId = b
    elseif a == DropGhostsDispatcher then
        s = GetDefaultDispatcher()
        unitId = b
    else
        s = GetDefaultDispatcher()
        unitId = a
    end

    if unitId then
        return s._waypointMeshes[unitId] or {}
    end
    return s._waypointMeshes
end

-- Export methods to DropGhostsDispatcher and module environment
DropGhostsDispatcher.Create = CreateDispatcher
DropGhostsDispatcher.GetDefaultDispatcher = GetDefaultDispatcher
Create = function(customManager, customBuffer)
    return CreateDispatcher(customManager, customBuffer)
end
DropGhostsDispatcher.OnBeat = OnBeat
DropGhostsDispatcher.UpdateWaypoints = UpdateWaypoints
DropGhostsDispatcher.DrawWaypoints = DrawWaypoints
DropGhostsDispatcher.DispatchOrder = DispatchOrder
DropGhostsDispatcher.ClearAll = ClearAll
DropGhostsDispatcher.GetWaypoints = GetWaypoints
DropGhostsDispatcher.GetTrackedUnits = GetTrackedUnits
DropGhostsDispatcher.GetManager = GetManager
DropGhostsDispatcher.SetManager = SetManager
DropGhostsDispatcher.GetBuffer = GetBuffer
DropGhostsDispatcher.SetBuffer = SetBuffer
DropGhostsDispatcher.SetWorldMeshClass = SetWorldMeshClass
DropGhostsDispatcher.SetCommandMeshResources = SetCommandMeshResources
DropGhostsDispatcher.DropGhostsDispatcher = DropGhostsDispatcher

GetDefaultDispatcher = GetDefaultDispatcher
Create = function(customManager, customBuffer)
    return CreateDispatcher(customManager, customBuffer)
end

if rawget(_G, 'rawset') then
    rawset(_G, 'DropGhostsDispatcher', DropGhostsDispatcher)
end

return DropGhostsDispatcher
