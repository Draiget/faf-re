-- tests/lua/test_drop_ghosts_buffer.lua
table.getn = table.getn or function(t) return #t end

package.path = package.path .. ";I:/FaforeverFiles/mods/TransportDropGhosts/modules/?.lua;modules/?.lua"
local Buffer = require('drop_ghosts_buffer')

local function assert_eq(actual, expected, msg)
    if actual ~= expected then
        error(string.format("Assertion failed: %s (expected %s, got %s)", tostring(msg), tostring(expected), tostring(actual)))
    end
end

local buf = Buffer.Create()

-- Test 1: Single command add
buf:AddOrder('u100', 'Move', { x = 10, y = 0, z = 20 }, false)
local orders = buf:GetOrders('u100')
assert_eq(table.getn(orders), 1, "Single order count")
assert_eq(orders[1].commandType, 'Move', "Command type")
assert_eq(orders[1].targetData.x, 10, "Target X")

-- Test 2: Append with Shift (appendQueue = true)
buf:AddOrder('u100', 'Attack', { x = 30, y = 0, z = 40 }, true)
orders = buf:GetOrders('u100')
assert_eq(table.getn(orders), 2, "Appended order count")
assert_eq(orders[2].commandType, 'Attack', "Second command type")

-- Test 3: Replace without Shift (appendQueue = false)
buf:AddOrder('u100', 'Patrol', { x = 50, y = 0, z = 60 }, false)
orders = buf:GetOrders('u100')
assert_eq(table.getn(orders), 1, "Replaced order count")
assert_eq(orders[1].commandType, 'Patrol', "New command type")

-- Test 4: Shift positions
buf:ShiftPositions({ x = 5, y = 0, z = -5 })
orders = buf:GetOrders('u100')
assert_eq(orders[1].targetData.x, 55, "Shifted Target X")
assert_eq(orders[1].targetData.z, 55, "Shifted Target Z")

-- Test 5: Shift positions with non-coordinate targets (e.g. Unit target / entity ID)
buf:AddOrder('u100', 'Assist', 'target-entity-123', true)
buf:ShiftPositions({ x = 10, y = 5, z = 10 })
orders = buf:GetOrders('u100')
assert_eq(orders[1].targetData.x, 65, "Shifted Target X with mixed targets")
assert_eq(orders[2].targetData, 'target-entity-123', "Non-table target unchanged")

-- Test 6: Clear unit orders
buf:ClearUnitOrders('u100')
assert_eq(table.getn(buf:GetOrders('u100')), 0, "Cleared orders count")

-- Test 7: Nonexistent unit returns empty table
assert_eq(table.getn(buf:GetOrders('nonexistent')), 0, "Nonexistent unit orders count")

-- Test 8: ClearAll wipes multiple units
buf:AddOrder('u101', 'Move', { x = 1, y = 0, z = 1 }, false)
buf:AddOrder('u102', 'Move', { x = 2, y = 0, z = 2 }, false)
assert_eq(table.getn(buf:GetOrders('u101')), 1, "u101 has 1 order")
assert_eq(table.getn(buf:GetOrders('u102')), 1, "u102 has 1 order")
buf:ClearAll()
assert_eq(table.getn(buf:GetOrders('u101')), 0, "ClearAll unit 1")
assert_eq(table.getn(buf:GetOrders('u102')), 0, "ClearAll unit 2")

print("test_drop_ghosts_buffer: ALL PASSED")
