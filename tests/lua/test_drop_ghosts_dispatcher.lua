-- tests/lua/test_drop_ghosts_dispatcher.lua
table.getn = table.getn or function(t) return #t end

package.path = package.path .. ";I:/FaforeverFiles/mods/TransportDropGhosts/modules/?.lua;modules/?.lua"

local function assert_true(cond, msg)
    if not cond then
        error("Assertion failed: " .. tostring(msg))
    end
end

local function assert_false(cond, msg)
    if cond then
        error("Assertion failed (expected false): " .. tostring(msg))
    end
end

local function assert_eq(actual, expected, msg)
    if actual ~= expected then
        error(string.format("Assertion failed: %s (expected %s, got %s)", tostring(msg), tostring(expected), tostring(actual)))
    end
end

-- Mock WorldMesh
local createdMeshes = {}
local MockWorldMesh = {}
MockWorldMesh.__index = MockWorldMesh

function MockWorldMesh.New()
    local m = {
        meshDescriptor = nil,
        stance = nil,
        lifetime = nil,
        hidden = false,
        isDestroyed = false
    }
    table.insert(createdMeshes, m)
    return setmetatable(m, MockWorldMesh)
end

function MockWorldMesh:SetMesh(desc)
    self.meshDescriptor = desc
end

function MockWorldMesh:SetStance(pos, ori)
    self.stance = pos
    self.orientation = ori
end

function MockWorldMesh:SetLifetimeParameter(param)
    self.lifetime = param
end

function MockWorldMesh:SetHidden(hidden)
    self.hidden = hidden
end

function MockWorldMesh:Destroy()
    self.isDestroyed = true
end

_G.WorldMesh = MockWorldMesh.New

-- Mock Command Execution Capture
local issuedUnitCommands = {}
local issuedBlueprintCommands = {}

_G.IssueUnitCommandToUnit = function(unit, command, luaParams, clear)
    table.insert(issuedUnitCommands, {
        unit = unit,
        command = command,
        luaParams = luaParams,
        clear = clear
    })
end

_G.IssueBlueprintCommandToUnits = function(units, command, blueprintId, count, clear)
    table.insert(issuedBlueprintCommands, {
        units = units,
        command = command,
        blueprintId = blueprintId,
        count = count,
        clear = clear
    })
end

local function ResetCommandCaptures()
    issuedUnitCommands = {}
    issuedBlueprintCommands = {}
end

-- Mock Unit & Transport Helpers
local function CreateMockUnit(id, army, isAttached)
    return {
        _id = id,
        _army = army or 1,
        _attached = (isAttached ~= false),
        _dead = false,
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        IsDead = function(self) return self._dead end,
        SetDead = function(self, d) self._dead = d end,
        IsUnitState = function(self, state)
            if state == 'Attached' then
                return self._attached
            end
            return false
        end,
        SetAttached = function(self, att)
            self._attached = att
        end
    }
end

local function CreateMockTransport(id, army, cargo)
    local t = {
        _id = id,
        _army = army or 1,
        _dead = false,
        attachedUnits = cargo or {},
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        IsDead = function(self) return self._dead end,
        SetDead = function(self, d) self._dead = d end,
        GetCargo = function(self) return self.attachedUnits end
    }
    return t
end

-- Load Modules
local BufferModule = require('drop_ghosts_buffer')
local ManagerModule = require('drop_ghosts_manager')
local DispatcherModule = require('drop_ghosts_dispatcher')

assert_true(DispatcherModule ~= nil, "Dispatcher module loaded")
assert_true(DispatcherModule.Create ~= nil, "DispatcherModule.Create exists")
assert_true(DispatcherModule.OnBeat ~= nil, "DispatcherModule.OnBeat exists")
assert_true(DispatcherModule.UpdateWaypoints ~= nil, "DispatcherModule.UpdateWaypoints exists")
assert_true(DispatcherModule.DrawWaypoints ~= nil, "DispatcherModule.DrawWaypoints exists")

--------------------------------------------------------------------------------
-- Test 1: Detection of Disembarked Units on Beat & Standard Order Dispatch
--------------------------------------------------------------------------------
print("Running Test 1: Disembark detection & standard order dispatch...")
ResetCommandCaptures()

local buf1 = BufferModule.Create()
local mgr1 = ManagerModule.Create(buf1)
local disp1 = DispatcherModule.Create(mgr1, buf1)

local u1 = CreateMockUnit('u101', 1, true)
local t1 = CreateMockTransport('t101', 1, { u1 })

-- Setup ghost in manager
mgr1._ghosts['u101'] = {
    id = 'u101',
    ghostId = 'u101',
    realUnit = u1,
    transport = t1,
    position = { x = 100, y = 20, z = 100, [1] = 100, [2] = 20, [3] = 100 }
}

-- Add queued orders into buffer
buf1:AddOrder('u101', 'Move', { x = 110, y = 20, z = 110 }, false)
buf1:AddOrder('u101', 'Attack', { x = 150, y = 20, z = 150 }, true)

-- Beat 1: Unit is still attached in cargo -> no orders dispatched yet
disp1:OnBeat()
assert_eq(#issuedUnitCommands, 0, "No commands dispatched while still attached")
local tracked = disp1:GetTrackedUnits()
assert_true(tracked['u101'] ~= nil, "u101 is being tracked")

-- Unit touches down! Unit state 'Attached' becomes false, and removed from transport cargo
u1:SetAttached(false)
t1.attachedUnits = {}

-- Beat 2: Unit disembarked -> orders dispatched!
disp1:OnBeat()
assert_eq(#issuedUnitCommands, 2, "Both queued orders dispatched on disembark")
assert_eq(issuedUnitCommands[1].unit, u1, "First command unit")
assert_eq(issuedUnitCommands[1].command, 'Move', "First command type")
assert_eq(issuedUnitCommands[1].luaParams.x, 110, "First command target X")
assert_eq(issuedUnitCommands[1].clear, false, "First command clear flag")

assert_eq(issuedUnitCommands[2].unit, u1, "Second command unit")
assert_eq(issuedUnitCommands[2].command, 'Attack', "Second command type")
assert_eq(issuedUnitCommands[2].luaParams.x, 150, "Second command target X")

-- Buffer should be cleared for u101
assert_eq(#buf1:GetOrders('u101'), 0, "Buffer cleared for u101 after touchdown dispatch")

-- Ghost in manager should be destroyed
assert_true(mgr1:GetActiveGhosts()['u101'] == nil, "Ghost removed from manager after touchdown")

-- Unit removed from dispatcher tracking
assert_true(disp1:GetTrackedUnits()['u101'] == nil, "u101 removed from tracking")
print("Test 1 Passed.")

--------------------------------------------------------------------------------
-- Test 2: Detection via Cargo List Absence (Transport Cargo Removal)
--------------------------------------------------------------------------------
print("Running Test 2: Detection via Cargo List Absence...")
ResetCommandCaptures()

local buf2 = BufferModule.Create()
local mgr2 = ManagerModule.Create(buf2)
local disp2 = DispatcherModule.Create(mgr2, buf2)

local u2 = CreateMockUnit('u102', 1, true)
local t2 = CreateMockTransport('t102', 1, { u2 })

mgr2._ghosts['u102'] = {
    id = 'u102',
    ghostId = 'u102',
    realUnit = u2,
    transport = t2,
    position = { x = 200, y = 10, z = 200 }
}

buf2:AddOrder('u102', 'Patrol', { x = 250, y = 10, z = 250 }, false)

-- Initial beat tracks u2
disp2:OnBeat()
assert_eq(#issuedUnitCommands, 0, "Not dispatched while in cargo")

-- Transport drops u2 (cargo list empty, even if IsUnitState is not called or delayed)
t2.attachedUnits = {}

disp2:OnBeat()
assert_eq(#issuedUnitCommands, 1, "Dispatched because absent from cargo list")
assert_eq(issuedUnitCommands[1].command, 'Patrol', "Patrol dispatched")
assert_eq(#buf2:GetOrders('u102'), 0, "Buffer cleared")
print("Test 2 Passed.")

--------------------------------------------------------------------------------
-- Test 3: Blueprint Construction Order Dispatch
--------------------------------------------------------------------------------
print("Running Test 3: Blueprint Build Order Dispatch...")
ResetCommandCaptures()

local buf3 = BufferModule.Create()
local mgr3 = ManagerModule.Create(buf3)
local disp3 = DispatcherModule.Create(mgr3, buf3)

local eng = CreateMockUnit('eng1', 1, true)
local t3 = CreateMockTransport('t103', 1, { eng })

mgr3._ghosts['eng1'] = {
    id = 'eng1',
    ghostId = 'eng1',
    realUnit = eng,
    transport = t3,
    position = { x = 50, y = 5, z = 50 }
}

-- Queue building orders: mobile build and factory build
buf3:AddOrder('eng1', 'UNITCOMMAND_BuildMobile', { blueprintId = 'ueb0101', count = 1, x = 60, z = 60 }, false)
buf3:AddOrder('eng1', 'Build', { blueprint = 'ueb1103', count = 2, x = 70, z = 70 }, true)

disp3:OnBeat()
assert_eq(#issuedBlueprintCommands, 0, "No blueprint commands yet")

-- Touchdown
eng:SetAttached(false)
t3.attachedUnits = {}

disp3:OnBeat()
assert_eq(#issuedBlueprintCommands, 2, "Both blueprint commands dispatched")
assert_eq(issuedBlueprintCommands[1].units[1], eng, "Blueprint unit 1")
assert_eq(issuedBlueprintCommands[1].command, 'UNITCOMMAND_BuildMobile', "Blueprint command 1")
assert_eq(issuedBlueprintCommands[1].blueprintId, 'ueb0101', "Blueprint ID 1")
assert_eq(issuedBlueprintCommands[1].count, 1, "Blueprint count 1")
assert_eq(issuedBlueprintCommands[1].clear, false, "Blueprint clear 1")

assert_eq(issuedBlueprintCommands[2].units[1], eng, "Blueprint unit 2")
assert_eq(issuedBlueprintCommands[2].blueprintId, 'ueb1103', "Blueprint ID 2")
assert_eq(issuedBlueprintCommands[2].count, 2, "Blueprint count 2")
print("Test 3 Passed.")

--------------------------------------------------------------------------------
-- Test 4: Dead Unit Cleanup Without Dispatching Orders
--------------------------------------------------------------------------------
print("Running Test 4: Dead Unit Cleanup (Shot Down)...")
ResetCommandCaptures()

local buf4 = BufferModule.Create()
local mgr4 = ManagerModule.Create(buf4)
local disp4 = DispatcherModule.Create(mgr4, buf4)

local deadUnit = CreateMockUnit('uDead', 1, true)
local t4 = CreateMockTransport('t104', 1, { deadUnit })

mgr4._ghosts['uDead'] = {
    id = 'uDead',
    ghostId = 'uDead',
    realUnit = deadUnit,
    transport = t4,
    position = { x = 0, y = 0, z = 0 }
}
buf4:AddOrder('uDead', 'Move', { x = 10, y = 0, z = 10 }, false)

disp4:OnBeat()
assert_true(disp4:GetTrackedUnits()['uDead'] ~= nil, "Tracked before death")

-- Transport shot down and unit dies
deadUnit:SetDead(true)
disp4:OnBeat()

assert_eq(#issuedUnitCommands, 0, "No commands dispatched for dead unit")
assert_eq(#buf4:GetOrders('uDead'), 0, "Buffer cleared for dead unit")
assert_true(disp4:GetTrackedUnits()['uDead'] == nil, "Removed from tracking")
print("Test 4 Passed.")

--------------------------------------------------------------------------------
-- Test 5: Waypoint Mesh Lifecycle (Create, Update Stance/Mesh, Shrink, Destroy)
--------------------------------------------------------------------------------
print("Running Test 5: Waypoint Mesh Lifecycle...")
createdMeshes = {}

local buf5 = BufferModule.Create()
local mgr5 = ManagerModule.Create(buf5)
local disp5 = DispatcherModule.Create(mgr5, buf5)

local u5 = CreateMockUnit('u105', 1, true)
local t5 = CreateMockTransport('t105', 1, { u5 })

mgr5._ghosts['u105'] = {
    id = 'u105',
    ghostId = 'u105',
    realUnit = u5,
    transport = t5,
    position = { x = 100, y = 0, z = 100 }
}

-- Add 2 orders
buf5:AddOrder('u105', 'Move', { x = 110, y = 0, z = 110 }, false)
buf5:AddOrder('u105', 'Attack', { x = 130, y = 0, z = 130 }, true)

disp5:UpdateWaypoints()

local wpList = disp5:GetWaypoints('u105')
assert_eq(#wpList, 2, "2 waypoint meshes created for 2 queued orders")
assert_eq(wpList[1].cmdType, 'Move', "Mesh 1 command type")
assert_true(wpList[1].mesh ~= nil, "Mesh 1 instance exists")
assert_false(wpList[1].mesh.isDestroyed, "Mesh 1 is active")
assert_eq(wpList[1].position.x, 110, "Mesh 1 stance X")

assert_eq(wpList[2].cmdType, 'Attack', "Mesh 2 command type")
assert_eq(wpList[2].position.x, 130, "Mesh 2 stance X")

-- Queue shrinks: replace with single patrol order
buf5:AddOrder('u105', 'Patrol', { x = 160, y = 0, z = 160 }, false)
disp5:UpdateWaypoints()

wpList = disp5:GetWaypoints('u105')
assert_eq(#wpList, 1, "Waypoint meshes shrunk to 1")
assert_eq(wpList[1].cmdType, 'Patrol', "Updated to Patrol command")
assert_eq(wpList[1].position.x, 160, "Updated stance to 160")

-- Unit disembarks: meshes should be destroyed
u5:SetAttached(false)
t5.attachedUnits = {}
disp5:OnBeat()

wpList = disp5:GetWaypoints('u105')
assert_eq(#wpList, 0, "Waypoint meshes cleared upon disembark")
assert_true(createdMeshes[1].isDestroyed, "Underlying WorldMesh destroyed")
print("Test 5 Passed.")

--------------------------------------------------------------------------------
-- Test 6: ClearAll Frees All Meshes & State
--------------------------------------------------------------------------------
print("Running Test 6: ClearAll...")
local buf6 = BufferModule.Create()
local mgr6 = ManagerModule.Create(buf6)
local disp6 = DispatcherModule.Create(mgr6, buf6)

local u6 = CreateMockUnit('u106', 1, true)
local t6 = CreateMockTransport('t106', 1, { u6 })

mgr6._ghosts['u106'] = {
    id = 'u106',
    ghostId = 'u106',
    realUnit = u6,
    transport = t6,
    position = { x = 0, y = 0, z = 0 }
}
buf6:AddOrder('u106', 'Move', { x = 20, y = 0, z = 20 }, false)

disp6:OnBeat()
disp6:UpdateWaypoints()

assert_eq(#disp6:GetWaypoints('u106'), 1, "Waypoint exists before ClearAll")
assert_true(disp6:GetTrackedUnits()['u106'] ~= nil, "Tracked before ClearAll")

disp6:ClearAll()
assert_eq(#disp6:GetWaypoints('u106'), 0, "Waypoints empty after ClearAll")
assert_true(disp6:GetTrackedUnits()['u106'] == nil, "Tracking empty after ClearAll")
print("Test 6 Passed.")

--------------------------------------------------------------------------------
-- Test 7: Static Dot-Syntax Calling Convention & Export Compatibility
--------------------------------------------------------------------------------
print("Running Test 7: Static Dot-Syntax Calling Convention...")
ResetCommandCaptures()

local defBuf = DispatcherModule.GetBuffer()
local defMgr = DispatcherModule.GetManager()
assert_true(defBuf ~= nil, "Default buffer initialized")
assert_true(defMgr ~= nil, "Default manager initialized")

local u7 = CreateMockUnit('u107', 1, true)
local t7 = CreateMockTransport('t107', 1, { u7 })

defMgr._ghosts['u107'] = {
    id = 'u107',
    ghostId = 'u107',
    realUnit = u7,
    transport = t7,
    position = { x = 500, y = 0, z = 500 }
}
defBuf:AddOrder('u107', 'AggressiveMove', { x = 550, y = 0, z = 550 }, false)

-- Call statically via DropGhostsDispatcher.OnBeat()
DispatcherModule.OnBeat()
assert_eq(#issuedUnitCommands, 0, "Not dispatched while attached")

u7:SetAttached(false)
t7.attachedUnits = {}

DispatcherModule.OnBeat()
assert_eq(#issuedUnitCommands, 1, "Dispatched via static OnBeat()")
assert_eq(issuedUnitCommands[1].command, 'AggressiveMove', "AggressiveMove command")

-- Static ClearAll()
DispatcherModule.ClearAll()
assert_eq(#DispatcherModule.GetWaypoints('u107'), 0, "Cleaned via static ClearAll()")
print("Test 7 Passed.")

--------------------------------------------------------------------------------
-- Test 8: Path Line Rendering via WorldView Mock
--------------------------------------------------------------------------------
print("Running Test 8: Path Line Rendering Hook...")
local buf8 = BufferModule.Create()
local mgr8 = ManagerModule.Create(buf8)
local disp8 = DispatcherModule.Create(mgr8, buf8)

local u8 = CreateMockUnit('u108', 1, true)
local t8 = CreateMockTransport('t108', 1, { u8 })

mgr8._ghosts['u108'] = {
    id = 'u108',
    ghostId = 'u108',
    realUnit = u8,
    transport = t8,
    position = { x = 10, y = 0, z = 10 }
}
buf8:AddOrder('u108', 'Move', { x = 20, y = 0, z = 20 }, false)
buf8:AddOrder('u108', 'Attack', { x = 30, y = 0, z = 30 }, true)

local drawnLines = {}
local mockWorldView = {
    DrawLine = function(self, p1, p2, color)
        table.insert(drawnLines, { p1 = p1, p2 = p2, color = color })
    end
}

disp8:DrawWaypoints(mockWorldView)
assert_eq(#drawnLines, 2, "2 line segments rendered (ghost->wp1, wp1->wp2)")
assert_eq(drawnLines[1].p1.x, 10, "Line 1 starts at ghost position")
assert_eq(drawnLines[1].p2.x, 20, "Line 1 ends at wp 1")
assert_eq(drawnLines[2].p1.x, 20, "Line 2 starts at wp 1")
assert_eq(drawnLines[2].p2.x, 30, "Line 2 ends at wp 2")
print("Test 8 Passed.")

print("test_drop_ghosts_dispatcher: ALL PASSED")
