-- data/fafengine/modules/lua/ui/game/transport_holograms.lua
-- Clean, lightweight 3D hologram preview for cargo units at transport unload waypoints.
-- Directly delegates selection to C++ SelectCargoUnits, preserving native CommandMode and Sim determinism.
-- Order lines and waypoint markers are rendered natively by the C++ engine UICommandGraph.

local WorldMesh = nil
local function GetWorldMeshClass()
    if not WorldMesh then
        local ok, mod = pcall(import, '/lua/ui/controls/worldmesh.lua')
        if ok and type(mod) == 'table' and rawget(mod, 'WorldMesh') then
            WorldMesh = mod.WorldMesh
        end
    end
    return WorldMesh
end

local function SafeGet(tbl, key)
    if type(tbl) ~= 'table' then return nil end
    local ok, val = pcall(function() return tbl[key] end)
    return ok and val or nil
end

local function GetSurfaceY(x, z, defaultY)
    local getSurf = rawget(_G, 'GetSurfaceHeight') or rawget(_G, 'GetTerrainHeight')
    if getSurf and x and z then
        local ok, h = pcall(getSurf, x, z)
        if ok and type(h) == 'number' then return h end
    end
    return defaultY or 0
end

local function GetCargoUnits(transport)
    if not transport then return {} end
    local getAttached = rawget(_G, 'GetAttachedUnitsList')
    if getAttached then
        local ok, list = pcall(getAttached, { transport })
        if ok and type(list) == 'table' then
            return list
        end
    end
    local getCargo = SafeGet(transport, 'GetCargo')
    if getCargo then
        local ok, list = pcall(getCargo, transport)
        if ok and type(list) == 'table' then
            return list
        end
    end
    return {}
end

local function FindUnloadWaypoint(transport)
    if not transport or not transport.GetCommandQueue then return nil end
    local queue = transport:GetCommandQueue()
    if not queue then return nil end
    for _, cmd in ipairs(queue) do
        local cmdType = cmd.type or cmd.commandType
        if cmdType == 'Unload' or cmdType == 'TransportUnloadUnits' or cmdType == 'TransportUnloadSpecificUnits' or cmdType == 'DetachFromTransport' or cmdType == 'UnitCommandUnload' then
            local pos = cmd.position or cmd.target
            if pos then
                local px = pos[1] or pos.x
                local py = pos[2] or pos.y or 0
                local pz = pos[3] or pos.z
                if px and pz then
                    return { px, py, pz }
                end
            end
        end
    end
    return nil
end

TransportHolograms = {
    _trackedTransports = {}, -- [entityId] = transport UserUnit
    _activeHolograms = {},   -- [hologramId] = { mesh, unit, transport, position = {x,y,z}, radius }
    _nextHologramId = 1,
}

function TransportHolograms:RegisterTransport(transport)
    if not transport or not transport.GetEntityId then return end
    local id = transport:GetEntityId()
    if id and not self._trackedTransports[id] then
        self._trackedTransports[id] = transport
    end
end

function TransportHolograms:UnregisterTransport(transportId)
    self._trackedTransports[transportId] = nil
    self:ClearHologramsForTransport(transportId)
end

function TransportHolograms:ClearHologramsForTransport(transportId)
    for hid, holo in pairs(self._activeHolograms) do
        if holo.transportId == transportId then
            if holo.unit and holo.unit.ClearSelectionBracketPositionOverride then
                pcall(holo.unit.ClearSelectionBracketPositionOverride, holo.unit)
            end
            if holo.mesh and holo.mesh.Destroy then
                pcall(holo.mesh.Destroy, holo.mesh)
            end
            self._activeHolograms[hid] = nil
        end
    end
end

function TransportHolograms:ClearAll()
    for _, holo in pairs(self._activeHolograms) do
        if holo.unit and holo.unit.ClearSelectionBracketPositionOverride then
            pcall(holo.unit.ClearSelectionBracketPositionOverride, holo.unit)
        end
        if holo.mesh and holo.mesh.Destroy then
            pcall(holo.mesh.Destroy, holo.mesh)
        end
    end
    self._activeHolograms = {}
    self._trackedTransports = {}
end

function TransportHolograms:CreateHologramMesh(unit, worldPos)
    local WM = GetWorldMeshClass()
    if not WM then return nil end

    local bpId = nil
    if unit.GetUnitId then
        local ok, id = pcall(unit.GetUnitId, unit)
        if ok and id then bpId = id end
    end
    if not bpId and unit.GetBlueprint then
        local ok, bp = pcall(unit.GetBlueprint, unit)
        if ok and bp then
            bpId = bp.BlueprintId or bp.id or bp.Source
        end
    end
    if not bpId then return nil end

    local mesh = WM()
    if not mesh then return nil end

    local ok, err = pcall(function()
        mesh:SetMesh({
            BlueprintID = bpId,
            Color = '7733ccff',
        })
    end)
    if not ok then
        pcall(mesh.Destroy, mesh)
        return nil
    end

    -- Translucent holographic cyan tint (ARGB: 0x7733ccff)
    if mesh.SetColor then
        pcall(mesh.SetColor, mesh, '7733ccff')
    end
    if mesh.SetStance then
        pcall(mesh.SetStance, mesh, worldPos)
    end
    if mesh.SetHidden then
        pcall(mesh.SetHidden, mesh, false)
    end

    return mesh
end

function TransportHolograms:Update()
    local focusArmy = -1
    local getFocusArmy = rawget(_G, 'GetFocusArmy')
    if getFocusArmy then
        focusArmy = getFocusArmy()
    end

    -- 1. Validate tracked transports
    for tid, transport in pairs(self._trackedTransports) do
        local isDead = (transport.IsDead and transport:IsDead())
            or (transport.DestroyQueued and transport:DestroyQueued())
        local army = (transport.GetArmy and transport:GetArmy()) or -1

        if isDead or (focusArmy >= 0 and army ~= focusArmy) then
            self:UnregisterTransport(tid)
        else
            local unloadPos = FindUnloadWaypoint(transport)
            if not unloadPos then
                self:ClearHologramsForTransport(tid)
            else
                local cargo = GetCargoUnits(transport)
                if table.getn(cargo) == 0 then
                    self:ClearHologramsForTransport(tid)
                else
                    self:SyncHologramsForTransport(tid, transport, cargo, unloadPos)
                end
            end
        end
    end

    -- 2. Highlight holograms whose real units are selected
    local getSelected = rawget(_G, 'GetSelectedUnits')
    local selectedUnits = getSelected and getSelected() or {}
    local selectedSet = {}
    if type(selectedUnits) == 'table' then
        for _, u in ipairs(selectedUnits) do
            local uid = u.GetEntityId and u:GetEntityId()
            if uid then selectedSet[uid] = true end
        end
    end

    for _, holo in pairs(self._activeHolograms) do
        local uid = holo.unit and holo.unit.GetEntityId and holo.unit:GetEntityId()
        local isSel = uid and selectedSet[uid] or false

        if holo.mesh and holo.mesh.SetColor then
            if isSel then
                pcall(holo.mesh.SetColor, holo.mesh, 'ddffff66') -- Bright golden cyan for selected
            else
                pcall(holo.mesh.SetColor, holo.mesh, '7733ccff') -- Normal cyan hologram
            end
        end
    end
end

function TransportHolograms:SyncHologramsForTransport(tid, transport, cargo, unloadPos)
    local count = table.getn(cargo)
    local radius = (count > 1) and (1.8 + 0.4 * math.sqrt(count)) or 0.0

    -- Existing holograms for this transport
    local existing = {}
    for hid, holo in pairs(self._activeHolograms) do
        if holo.transportId == tid then
            local uid = holo.unit and holo.unit.GetEntityId and holo.unit:GetEntityId()
            if uid then existing[uid] = hid end
        end
    end

    local currentCargoIds = {}
    for i, unit in ipairs(cargo) do
        local uid = unit.GetEntityId and unit:GetEntityId()
        if uid then
            currentCargoIds[uid] = true

            -- Calculate world position
            local angle = (count > 1) and (2.0 * math.pi * (i - 1) / count) or 0.0
            local gx = unloadPos[1] + radius * math.cos(angle)
            local gz = unloadPos[3] + radius * math.sin(angle)
            local gy = GetSurfaceY(gx, gz, unloadPos[2]) + 0.1
            local worldPos = { gx, gy, gz }

            -- Set selection bracket override so C++ SelectionBracketRenderer draws the selection square at worldPos
            if unit.SetSelectionBracketPositionOverride then
                pcall(unit.SetSelectionBracketPositionOverride, unit, worldPos)
            end

            local hid = existing[uid]
            if hid and self._activeHolograms[hid] then
                -- Update position
                local holo = self._activeHolograms[hid]
                holo.position = worldPos
                if holo.mesh and holo.mesh.SetStance then
                    pcall(holo.mesh.SetStance, holo.mesh, worldPos)
                end
            else
                -- Spawn new hologram
                local mesh = self:CreateHologramMesh(unit, worldPos)
                if mesh then
                    self._nextHologramId = self._nextHologramId + 1
                    local newHid = self._nextHologramId
                    self._activeHolograms[newHid] = {
                        mesh = mesh,
                        unit = unit,
                        transport = transport,
                        transportId = tid,
                        position = worldPos,
                        radius = 2.0,
                    }
                end
            end
        end
    end

    -- Remove any disembarked / destroyed cargo holograms
    for uid, hid in pairs(existing) do
        if not currentCargoIds[uid] then
            local holo = self._activeHolograms[hid]
            if holo then
                if holo.unit and holo.unit.ClearSelectionBracketPositionOverride then
                    pcall(holo.unit.ClearSelectionBracketPositionOverride, holo.unit)
                end
                if holo.mesh and holo.mesh.Destroy then
                    pcall(holo.mesh.Destroy, holo.mesh)
                end
            end
            self._activeHolograms[hid] = nil
        end
    end
end

function TransportHolograms:HandleWorldClick(view, event)
    if not view or not view.Project or not event then return false end
    if event.Type ~= 'ButtonPress' or (event.Modifiers and event.Modifiers.Right) then
        return false
    end

    local mx = event.MouseX
    local my = event.MouseY
    if not mx or not my then return false end

    local bestHolo = nil
    local bestDistSq = 900 -- 30 pixels radius squared

    for _, holo in pairs(self._activeHolograms) do
        if holo.position then
            local ok, screenPos = pcall(view.Project, view, holo.position)
            if ok and screenPos and screenPos[1] and screenPos[2] then
                local sx = screenPos[1]
                local sy = screenPos[2]
                if sx >= 0 and sy >= 0 then
                    local dx = sx - mx
                    local dy = sy - my
                    local d2 = dx * dx + dy * dy
                    if d2 < bestDistSq then
                        bestDistSq = d2
                        bestHolo = holo
                    end
                end
            end
        end
    end

    if bestHolo and bestHolo.unit then
        local isShift = (event.Modifiers and event.Modifiers.Shift == true) or false
        local selectCargo = rawget(_G, 'SelectCargoUnits')
        if selectCargo then
            selectCargo({ bestHolo.unit }, isShift)
            return true
        end
        local selectUnits = rawget(_G, 'SelectUnits')
        if selectUnits then
            selectUnits({ bestHolo.unit }, true)
            return true
        end
    end

    return false
end

function TransportHolograms:HandleWorldDrag(view, minX, minY, maxX, maxY, isShift)
    if not view or not view.Project then return false end
    if not minX or not minY or not maxX or not maxY then return false end

    if minX > maxX then minX, maxX = maxX, minX end
    if minY > maxY then minY, maxY = maxY, minY end

    local capturedUnits = {}
    for _, holo in pairs(self._activeHolograms) do
        if holo.position and holo.unit then
            local ok, screenPos = pcall(view.Project, view, holo.position)
            if ok and screenPos and screenPos[1] and screenPos[2] then
                local sx = screenPos[1]
                local sy = screenPos[2]
                if sx >= minX and sx <= maxX and sy >= minY and sy <= maxY then
                    table.insert(capturedUnits, holo.unit)
                end
            end
        end
    end

    if table.getn(capturedUnits) > 0 then
        local selectCargo = rawget(_G, 'SelectCargoUnits')
        if selectCargo then
            selectCargo(capturedUnits, isShift)
            return true
        end
        local selectUnits = rawget(_G, 'SelectUnits')
        if selectUnits then
            selectUnits(capturedUnits, true)
            return true
        end
    end

    return false
end

-- Export module functions directly to module table
function Update()
    TransportHolograms:Update()
end

function HandleWorldClick(view, event)
    return TransportHolograms:HandleWorldClick(view, event)
end

function HandleWorldDrag(view, minX, minY, maxX, maxY, isShift)
    return TransportHolograms:HandleWorldDrag(view, minX, minY, maxX, maxY, isShift)
end

function RegisterTransport(transport)
    TransportHolograms:RegisterTransport(transport)
end

function ClearAll()
    TransportHolograms:ClearAll()
end
