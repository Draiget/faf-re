-- I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_buffer.lua
-- Buffer storing queued pre-orders for units while inside transports.

DropGhostsBuffer = {}
DropGhostsBuffer.__index = DropGhostsBuffer

local _defaultBuffer = nil

local function CreateBuffer()
    local instance = {
        _ordersByUnit = {}
    }
    return setmetatable(instance, DropGhostsBuffer)
end

local function GetDefaultBuffer()
    if not _defaultBuffer then
        _defaultBuffer = CreateBuffer()
    end
    return _defaultBuffer
end

function DropGhostsBuffer:AddOrder(unitEntityId, commandType, targetData, appendQueue)
    if not self._ordersByUnit[unitEntityId] or not appendQueue then
        self._ordersByUnit[unitEntityId] = {}
    end
    table.insert(self._ordersByUnit[unitEntityId], {
        commandType = commandType,
        targetData = targetData
    })
end

function DropGhostsBuffer:GetOrders(unitEntityId)
    return self._ordersByUnit[unitEntityId] or {}
end

function DropGhostsBuffer:ClearUnitOrders(unitEntityId)
    self._ordersByUnit[unitEntityId] = nil
end

function DropGhostsBuffer:ClearAll()
    self._ordersByUnit = {}
end

function DropGhostsBuffer:ShiftPositions(offset)
    if not offset or (offset.x == 0 and offset.z == 0) then
        return
    end
    for _, queue in pairs(self._ordersByUnit) do
        for _, order in ipairs(queue) do
            if type(order.targetData) == 'table' and order.targetData.x and order.targetData.z then
                order.targetData.x = order.targetData.x + (offset.x or 0)
                if offset.y and order.targetData.y then
                    order.targetData.y = order.targetData.y + offset.y
                end
                order.targetData.z = order.targetData.z + (offset.z or 0)
            end
        end
    end
end

DropGhostsBuffer.Create = CreateBuffer
DropGhostsBuffer.GetDefaultBuffer = GetDefaultBuffer

function GetDefaultBuffer()
    return DropGhostsBuffer.GetDefaultBuffer()
end

function Create()
    return DropGhostsBuffer.Create()
end

if rawget(_G, 'rawset') then
    rawset(_G, 'DropGhostsBuffer', DropGhostsBuffer)
end

return DropGhostsBuffer
