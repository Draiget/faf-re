-- I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_manager.lua
-- Visual manager for 3D hologram ghost units representing cargo at planned transport drop locations.

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
ResolveBufferModule()

local WorldMeshClass = nil
if rawget(_G, 'import') then
    local ok, wmModule = pcall(import, '/lua/ui/controls/worldmesh.lua')
    if ok and wmModule and wmModule.WorldMesh then
        WorldMeshClass = wmModule.WorldMesh
    end
end

local function GetWorldMeshClass()
    if not WorldMeshClass and rawget(_G, 'import') then
        local ok, wmModule = pcall(import, '/lua/ui/controls/worldmesh.lua')
        if ok and wmModule and wmModule.WorldMesh then
            WorldMeshClass = wmModule.WorldMesh
        end
    end
    return WorldMeshClass or (rawget(_G, 'WorldMesh'))
end

function SetWorldMeshClass(cls)
    WorldMeshClass = cls
end

local function GetCargoUnits(transport)
    local rawAttached = nil
    if transport and transport.GetCargoUnits then
        local ok, units = pcall(transport.GetCargoUnits, transport)
        if ok and type(units) == 'table' and table.getn(units) > 0 then
            rawAttached = units
        end
    end
    if not rawAttached then
        local fn = rawget(_G, 'GetAttachedUnitsList')
        if fn then
            local ok, units = pcall(fn, { transport })
            if ok and type(units) == 'table' then
                rawAttached = units
            end
        end
    end
    if not rawAttached and transport.GetCargo then
        local ok, units = pcall(transport.GetCargo, transport)
        if ok and type(units) == 'table' then
            rawAttached = units
        end
    end
    if not rawAttached and transport.attachedUnits then
        rawAttached = transport.attachedUnits
    end
    if not rawAttached then
        return {}
    end

    local filterDown = rawget(_G, 'EntityCategoryFilterDown')
    local cats = rawget(_G, 'categories')
    if filterDown and cats and cats.MOBILE then
        local ok, filtered = pcall(filterDown, cats.MOBILE, rawAttached)
        if ok and type(filtered) == 'table' then
            return filtered
        end
    end
    return rawAttached
end

local function ScanPlayerTransports()
    local gameMain = rawget(_G, 'import') and import('/lua/ui/game/gamemain.lua')
    local commandMode = rawget(_G, 'import') and import('/lua/ui/game/commandmode.lua')
    local selectionMod = rawget(_G, 'import') and import('/lua/ui/game/selection.lua')
    local selByCategory = (selectionMod and selectionMod.UISelectionByCategory) or rawget(_G, 'UISelectionByCategory')
    local getSelected = rawget(_G, 'GetSelectedUnits')
    local selectUnits = rawget(_G, 'SelectUnits')

    if not selByCategory or not getSelected or not selectUnits then
        return nil
    end

    local oldSelection = getSelected()
    if commandMode and commandMode.CacheAndClearCommandMode then
        commandMode.CacheAndClearCommandMode()
    end
    if gameMain and gameMain.SetIgnoreSelection then
        gameMain.SetIgnoreSelection(true)
    end

    selByCategory("TRANSPORTATION", false, false, false, false)
    local found = getSelected()

    selectUnits(oldSelection)
    if gameMain and gameMain.SetIgnoreSelection then
        gameMain.SetIgnoreSelection(false)
    end
    if commandMode and commandMode.RestoreCommandMode then
        commandMode.RestoreCommandMode(true)
    end

    return found
end

local function CalculateRadialOffset(index, totalCount, radius)
    if totalCount <= 1 then
        return 0, 0
    end
    local r = radius or math.max(2.5, 0.8 * totalCount)
    local angle = (index - 1) * (2 * math.pi / totalCount)
    local dx = r * math.cos(angle)
    local dz = r * math.sin(angle)
    return dx, dz
end

local function BuildMeshDescriptor(bp)
    local bpId = bp and (bp.BlueprintId or bp.id)
    local uniformScale = 1.0
    if bp and bp.Display and bp.Display.UniformScale then
        uniformScale = bp.Display.UniformScale
    end

    local meshName = nil
    local textureName = nil

    if bp and bp.Display then
        if bp.Display.Mesh and bp.Display.Mesh.LODs and bp.Display.Mesh.LODs[1] then
            local lod = bp.Display.Mesh.LODs[1]
            if lod.MeshName and lod.MeshName ~= '' then
                meshName = lod.MeshName
            end
            textureName = lod.AlbedoName or lod.TextureName
        end
        if not meshName and bp.Display.MeshBlueprint then
            local getMeshBp = rawget(_G, 'GetMeshBlueprintByName')
            local mbp = getMeshBp and getMeshBp(bp.Display.MeshBlueprint)
            if mbp and mbp.LODs and mbp.LODs[1] then
                meshName = mbp.LODs[1].MeshName
                textureName = mbp.LODs[1].AlbedoName or mbp.LODs[1].TextureName
            end
        end
    end

    if not meshName and bpId and bpId ~= '' then
        local lowerId = string.lower(bpId)
        meshName = '/units/' .. lowerId .. '/' .. lowerId .. '_lod0.scm'
        textureName = '/units/' .. lowerId .. '/' .. lowerId .. '_albedo.dds'
    end

    if not meshName then
        meshName = '/env/Common/Props/sphere_lod0.scm'
    end
    if not textureName then
        textureName = '/meshes/game/Assist_albedo.dds'
    end

    return {
        MeshName = meshName,
        TextureName = textureName,
        ShaderName = 'FakeRings',
        UniformScale = uniformScale,
        LODCutoff = 1000.0,
    }
end

DropGhostsManager = {}
DropGhostsManager.__index = DropGhostsManager

local _defaultInstance = nil

local function CreateManager(customBuffer)
    local buf = customBuffer
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
        _buffer = buf,
        _ghosts = {},
        _transportLastPositions = {},
        _trackedTransports = {},
        _censusBeatCount = 0
    }
    return setmetatable(instance, DropGhostsManager)
end

function GetDefaultManager()
    if not _defaultInstance then
        _defaultInstance = CreateManager()
    end
    return _defaultInstance
end

local function IsInstance(val)
    return type(val) == 'table' and val ~= DropGhostsManager and val._ghosts ~= nil
end

function GetBuffer(a)
    local s = IsInstance(a) and a or GetDefaultManager()
    return s._buffer
end

function SetBuffer(a, b)
    local s, buf
    if IsInstance(a) then
        s = a
        buf = b
    elseif a == DropGhostsManager then
        s = GetDefaultManager()
        buf = b
    else
        s = GetDefaultManager()
        buf = a
    end
    s._buffer = buf
end

function GetActiveGhosts(a)
    local s = IsInstance(a) and a or GetDefaultManager()
    return s._ghosts
end

function GetGhosts(a)
    return GetActiveGhosts(a)
end

function DestroyGhost(a, b)
    local s, ghostId
    if IsInstance(a) then
        s = a
        ghostId = b
    elseif a == DropGhostsManager then
        s = GetDefaultManager()
        ghostId = b
    else
        s = GetDefaultManager()
        ghostId = a
    end

    if type(ghostId) == 'table' and ghostId.id then
        ghostId = ghostId.id
    end
    if not ghostId then
        return
    end

    local ghost = s._ghosts[ghostId]
    if not ghost then
        return
    end

    SafeWarn("DestroyGhost: destroying ghost " .. tostring(ghostId))

    -- Notify selection module to remove this ghost if currently selected
    local selMod = rawget(_G, 'DropGhostsSelection')
    if selMod then
        local getSelFn = selMod.GetDefaultSelection
        local sel = getSelFn and getSelFn() or selMod
        if sel and sel.RemoveGhost then
            pcall(sel.RemoveGhost, sel, ghostId)
        end
    end

    if ghost.mesh then
        if ghost.mesh.SetHidden then
            pcall(ghost.mesh.SetHidden, ghost.mesh, true)
        end
        if type(ghost.mesh.Destroy) == 'function' then
            pcall(ghost.mesh.Destroy, ghost.mesh)
        end
        ghost.mesh = nil
    end

    s._ghosts[ghostId] = nil
end

function ClearAll(a)
    local s = IsInstance(a) and a or GetDefaultManager()
    SafeWarn("ClearAll: destroying all ghosts")
    for ghostId, ghost in pairs(s._ghosts) do
        if ghost and ghost.mesh then
            if ghost.mesh.SetHidden then
                pcall(ghost.mesh.SetHidden, ghost.mesh, true)
            end
            if type(ghost.mesh.Destroy) == 'function' then
                pcall(ghost.mesh.Destroy, ghost.mesh)
            end
            ghost.mesh = nil
        end
    end
    s._ghosts = {}
    s._transportLastPositions = {}
    s._trackedTransports = {}
    if s._buffer and s._buffer.ClearAll then
        s._buffer:ClearAll()
    end
end

function RegisterTransport(a, b)
    local s, transport
    if IsInstance(a) then
        s = a
        transport = b
    elseif a == DropGhostsManager or (type(a) == 'table' and rawget(a, 'GetDefaultManager')) then
        s = GetDefaultManager()
        transport = b
    else
        s = GetDefaultManager()
        transport = a
    end
    if not s._trackedTransports then
        s._trackedTransports = {}
    end
    if transport then
        local isValid = (not transport.IsDead or not transport:IsDead())
        if isValid then
            local tid = (transport.GetEntityId and transport:GetEntityId()) or tostring(transport)
            s._trackedTransports[tid] = transport
        end
    end
end

function SetTrackedTransports(a, b)
    local s, list
    if IsInstance(a) then
        s = a
        list = b
    elseif a == DropGhostsManager or (type(a) == 'table' and rawget(a, 'GetDefaultManager')) then
        s = GetDefaultManager()
        list = b
    else
        s = GetDefaultManager()
        list = a
    end
    s._trackedTransports = {}
    if list then
        for _, t in ipairs(list) do
            local tid = (t.GetEntityId and t:GetEntityId()) or tostring(t)
            s._trackedTransports[tid] = t
        end
    end
end

function Update(a, b, c)
    local s, focusArmy, playerTransports
    if IsInstance(a) then
        s = a
        focusArmy = b
        playerTransports = c
    elseif a == DropGhostsManager or (type(a) == 'table' and rawget(a, 'GetDefaultManager')) then
        s = GetDefaultManager()
        focusArmy = b
        playerTransports = c
    else
        s = GetDefaultManager()
        focusArmy = a
        playerTransports = b
    end
    if type(focusArmy) == 'table' then
        focusArmy = -1
    end

    -- Periodic census of transports using HiddenSelect pattern (every 30 beats ~ 3s)
    s._censusBeatCount = (s._censusBeatCount or 0) + 1
    local hasTracked = false
    if s._trackedTransports then
        for _, _ in pairs(s._trackedTransports) do
            hasTracked = true
            break
        end
    end

    if (s._censusBeatCount >= 30) or not hasTracked then
        s._censusBeatCount = 0
        local ok, scanned = pcall(ScanPlayerTransports)
        if ok and scanned and type(scanned) == 'table' then
            for _, tr in ipairs(scanned) do
                if tr and (not tr.IsDead or not tr:IsDead()) then
                    local tid = (tr.GetEntityId and tr:GetEntityId()) or tostring(tr)
                    s._trackedTransports[tid] = tr
                end
            end
        end
    end

    local getTransportsFn = rawget(_G, 'GetPlayerTransports')
    if (not playerTransports or table.getn(playerTransports) == 0) and getTransportsFn then
        local ok, tp = pcall(getTransportsFn)
        if ok and type(tp) == 'table' then
            playerTransports = tp
        end
    end

    if not playerTransports or table.getn(playerTransports) == 0 then
        if s._trackedTransports then
            local list = {}
            local deadIds = {}
            for tid, t in pairs(s._trackedTransports) do
                if t and (not t.IsDead or not t:IsDead()) then
                    table.insert(list, t)
                else
                    table.insert(deadIds, tid)
                end
            end
            for _, deadId in ipairs(deadIds) do
                s._trackedTransports[deadId] = nil
            end
            if table.getn(list) > 0 then
                playerTransports = list
            end
        end
    end

    playerTransports = playerTransports or {}
    local seenGhosts = {}

    for _, transport in ipairs(playerTransports) do
        local isValid = transport and (not transport.IsDead or not transport:IsDead())
        if isValid then
            local army = transport.GetArmy and transport:GetArmy()
            if not focusArmy or focusArmy == -1 or not army or army == focusArmy then
                local transportId = (transport.GetEntityId and transport:GetEntityId()) or tostring(transport)
                local queue = (transport.GetCommandQueue and transport:GetCommandQueue()) or {}

                -- Find first unload waypoint
                local unloadCmd = nil
                for _, cmd in ipairs(queue) do
                    local ct = cmd.type or cmd.commandType
                    if ct == 'TransportUnloadUnits' or ct == 'TransportUnloadSpecificUnits' or
                       ct == 'UNITCOMMAND_TransportUnloadUnits' or ct == 'UNITCOMMAND_TransportUnloadSpecificUnits' or
                       (type(ct) == 'string' and string.find(ct, 'Unload') ~= nil) then
                        unloadCmd = cmd
                        break
                    end
                end

                if unloadCmd and unloadCmd.position then
                    local cargo = GetCargoUnits(transport)
                    local cargoCount = table.getn(cargo)

                    if cargoCount > 0 then
                        local cx = unloadCmd.position.x or unloadCmd.position[1] or 0
                        local cy = unloadCmd.position.y or unloadCmd.position[2] or 0
                        local cz = unloadCmd.position.z or unloadCmd.position[3] or 0

                        local lastPos = s._transportLastPositions[transportId]
                        local dx, dy, dz = 0, 0, 0
                        local hasMoved = false

                        if lastPos then
                            dx = cx - lastPos.x
                            dy = cy - lastPos.y
                            dz = cz - lastPos.z
                            if math.abs(dx) > 0.001 or math.abs(dy) > 0.001 or math.abs(dz) > 0.001 then
                                hasMoved = true
                            end
                        end

                        for i = 1, cargoCount do
                            local unit = cargo[i]
                            if unit and (not unit.IsDead or not unit:IsDead()) then
                                local ghostId = (unit.GetEntityId and unit:GetEntityId()) or tostring(unit)
                                seenGhosts[ghostId] = true

                                local existingGhost = s._ghosts[ghostId]
                                if existingGhost then
                                    if hasMoved then
                                        existingGhost.position.x = existingGhost.position.x + dx
                                        existingGhost.position.y = (existingGhost.position.y or 0) + dy
                                        existingGhost.position.z = existingGhost.position.z + dz
                                        existingGhost.position[1] = existingGhost.position.x
                                        existingGhost.position[2] = existingGhost.position.y
                                        existingGhost.position[3] = existingGhost.position.z

                                        if existingGhost.mesh and existingGhost.mesh.SetStance then
                                            pcall(existingGhost.mesh.SetStance, existingGhost.mesh, existingGhost.position)
                                        end
                                        if existingGhost.mesh and existingGhost.mesh.SetHidden then
                                            pcall(existingGhost.mesh.SetHidden, existingGhost.mesh, false)
                                        end
                                    end
                                else
                                    -- Spawn new ghost hologram
                                    local offX, offZ = CalculateRadialOffset(i, cargoCount, 3.0)
                                    local gx = cx + offX
                                    local gz = cz + offZ
                                    local getSurf = rawget(_G, 'GetSurfaceHeight')
                                    local gy = cy
                                    if getSurf and gx and gz then
                                        local gh = getSurf(gx, gz)
                                        if gh and gh > 0 then
                                            gy = gh
                                        end
                                    end

                                    local ghostPos = {
                                        x = gx,
                                        y = gy,
                                        z = gz,
                                        [1] = gx,
                                        [2] = gy,
                                        [3] = gz
                                    }

                                    local bp = (unit.GetBlueprint and unit:GetBlueprint()) or {}
                                    local desc = BuildMeshDescriptor(bp)
                                    local uScale = (desc and desc.UniformScale) or 1.0

                                    local mesh = nil
                                    local MeshCtor = GetWorldMeshClass()
                                    if MeshCtor then
                                        local ok, m = pcall(MeshCtor)
                                        if ok and m then
                                            mesh = m
                                            if mesh.SetMesh then
                                                pcall(mesh.SetMesh, mesh, desc)
                                            end
                                            if mesh.SetScale then
                                                pcall(mesh.SetScale, mesh, { uScale, uScale, uScale })
                                            end
                                            if mesh.SetColor then
                                                pcall(mesh.SetColor, mesh, "80a0d0ff")
                                            end
                                            if mesh.SetFractionCompleteParameter then
                                                pcall(mesh.SetFractionCompleteParameter, mesh, 1.0)
                                            end
                                            if mesh.SetLifetimeParameter then
                                                pcall(mesh.SetLifetimeParameter, mesh, 10.0)
                                            end
                                            if mesh.SetStance then
                                                pcall(mesh.SetStance, mesh, ghostPos)
                                            end
                                            if mesh.SetHidden then
                                                pcall(mesh.SetHidden, mesh, false)
                                            end
                                        else
                                            SafeWarn("Failed to create WorldMesh instance: " .. tostring(m))
                                        end
                                    else
                                        SafeWarn("GetWorldMeshClass returned nil")
                                    end

                                    s._ghosts[ghostId] = {
                                        id = ghostId,
                                        ghostId = ghostId,
                                        realUnit = unit,
                                        transport = transport,
                                        position = ghostPos,
                                        mesh = mesh,
                                        uniformScale = uScale
                                    }

                                    SafeWarn("Spawned ghost " .. tostring(ghostId) .. " at (" .. tostring(gx) .. ", " .. tostring(gy) .. ", " .. tostring(gz) .. ")")
                                end
                            end
                        end

                        if hasMoved and s._buffer and s._buffer.ShiftPositions then
                            s._buffer:ShiftPositions({ x = dx, y = dy, z = dz })
                        end

                        s._transportLastPositions[transportId] = { x = cx, y = cy, z = cz }
                    else
                        s._transportLastPositions[transportId] = nil
                    end
                else
                    s._transportLastPositions[transportId] = nil
                end
            end
        end
    end

    -- Destroy any ghosts no longer active/attached/ordered
    local toDestroy = {}
    for gid, _ in pairs(s._ghosts) do
        if not seenGhosts[gid] then
            table.insert(toDestroy, gid)
        end
    end

    for _, gid in ipairs(toDestroy) do
        DestroyGhost(s, gid)
    end
end

-- Export functions on DropGhostsManager metatable/table
DropGhostsManager.Create = CreateManager
DropGhostsManager.GetDefaultManager = GetDefaultManager

function Create(buf)
    return CreateManager(buf)
end
DropGhostsManager.Update = Update
DropGhostsManager.GetActiveGhosts = GetActiveGhosts
DropGhostsManager.GetGhosts = GetGhosts
DropGhostsManager.DestroyGhost = DestroyGhost
DropGhostsManager.ClearAll = ClearAll
DropGhostsManager.GetBuffer = GetBuffer
DropGhostsManager.SetBuffer = SetBuffer
DropGhostsManager.RegisterTransport = RegisterTransport
DropGhostsManager.SetTrackedTransports = SetTrackedTransports
DropGhostsManager.SetWorldMeshClass = SetWorldMeshClass
DropGhostsManager.DropGhostsManager = DropGhostsManager

if rawget(_G, 'rawset') then
    rawset(_G, 'DropGhostsManager', DropGhostsManager)
end

return DropGhostsManager
