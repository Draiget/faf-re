-- tests/lua/test_drop_ghosts_manager.lua
table.getn = table.getn or function(t) return #t end

package.path = package.path .. ";I:/FaforeverFiles/mods/TransportDropGhosts/modules/?.lua;modules/?.lua"

local function assert_true(cond, msg)
    if not cond then
        error("Assertion failed: " .. tostring(msg))
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

function MockWorldMesh:Destroy()
    self.isDestroyed = true
end

_G.WorldMesh = MockWorldMesh.New

-- Mock Unit & Transport helpers
local function CreateMockUnit(id, army, blueprint)
    return {
        _id = id,
        _army = army or 1,
        _bp = blueprint or {
            BlueprintId = id,
            Display = {
                MeshBlueprint = '/units/' .. id .. '/' .. id .. '_mesh',
                UniformScale = 0.1
            }
        },
        _dead = false,
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        GetBlueprint = function(self) return self._bp end,
        IsDead = function(self) return self._dead end,
        GetPosition = function(self) return { 0, 0, 0 } end
    }
end

local function CreateMockTransport(id, army, cargoUnits, commandQueue)
    local t = {
        _id = id,
        _army = army or 1,
        _cargo = cargoUnits or {},
        _queue = commandQueue or {},
        _dead = false,
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        GetCommandQueue = function(self) return self._queue end,
        IsDead = function(self) return self._dead end
    }
    return t
end

_G.GetAttachedUnitsList = function(args)
    local transport = args[1]
    if transport and transport._cargo then
        return transport._cargo
    end
    return {}
end

local Manager = require('drop_ghosts_manager')
local BufferModule = require('drop_ghosts_buffer')

-- Test 1: Manager initialization
local customBuf = BufferModule.Create()
local mgr = Manager.Create(customBuf)
assert_true(mgr ~= nil, "Manager instance created")
assert_true(mgr:GetBuffer() == customBuf, "Manager uses custom buffer")

-- Test 2: Ghost spawning for attached cargo with TransportUnloadUnits
local u1 = CreateMockUnit('u101', 1)
local u2 = CreateMockUnit('u102', 1)
local transport = CreateMockTransport('t1', 1, { u1, u2 }, {
    {
        type = 'TransportUnloadUnits',
        position = { x = 100, y = 10, z = 200, [1] = 100, [2] = 10, [3] = 200 }
    }
})

mgr:Update(1, { transport })
local activeGhosts = mgr:GetActiveGhosts()
local count = 0
for _ in pairs(activeGhosts) do count = count + 1 end
assert_eq(count, 2, "Two ghosts spawned")

local g1 = activeGhosts['u101']
local g2 = activeGhosts['u102']
assert_true(g1 ~= nil, "Ghost u101 exists")
assert_true(g2 ~= nil, "Ghost u102 exists")
assert_true(g1.mesh ~= nil, "Ghost u101 has mesh")
assert_true(g1.mesh.meshDescriptor ~= nil, "Ghost u101 has mesh descriptor")
assert_eq(g1.mesh.meshDescriptor.ShaderName, 'FakeRings', "Ghost shader is FakeRings")
assert_true(g1.position ~= nil, "Ghost u101 has position")
assert_true(g2.position ~= nil, "Ghost u102 has position")

-- Ensure radial offset gives distinct coordinates
local dist = math.sqrt((g1.position.x - g2.position.x)^2 + (g1.position.z - g2.position.z)^2)
assert_true(dist > 0.1, "Radial formation produces distinct positions")

-- Test 3: Waypoint movement shifts ghost stances and notifies buffer
customBuf:AddOrder('u101', 'Move', { x = 100, y = 10, z = 200 }, false)

-- Move unload waypoint by dx = 15, dz = -20
transport._queue[1].position = { x = 115, y = 10, z = 180, [1] = 115, [2] = 10, [3] = 180 }
local prevG1X = g1.position.x
local prevG1Z = g1.position.z

mgr:Update(1, { transport })

assert_eq(g1.position.x, prevG1X + 15, "Ghost X shifted by 15")
assert_eq(g1.position.z, prevG1Z - 20, "Ghost Z shifted by -20")
assert_eq(g1.mesh.stance.x, prevG1X + 15, "Mesh stance X updated")

local orders = customBuf:GetOrders('u101')
assert_eq(orders[1].targetData.x, 115, "Buffer order X shifted")
assert_eq(orders[1].targetData.z, 180, "Buffer order Z shifted")

-- Test 4: Disembarkation of one unit destroys corresponding ghost
local m1 = g1.mesh
transport._cargo = { u2 } -- u1 disembarked
mgr:Update(1, { transport })

activeGhosts = mgr:GetActiveGhosts()
assert_true(activeGhosts['u101'] == nil, "Disembarked unit ghost removed")
assert_true(activeGhosts['u102'] ~= nil, "Remaining cargo unit ghost remains")
assert_true(m1.isDestroyed, "Disembarked unit mesh destroyed")
assert_eq(table.getn(customBuf:GetOrders('u101')), 0, "Buffer orders cleared for dropped unit")

-- Test 5: Dropping all units destroys remaining ghosts
local m2 = g2.mesh
transport._cargo = {}
mgr:Update(1, { transport })
activeGhosts = mgr:GetActiveGhosts()
count = 0
for _ in pairs(activeGhosts) do count = count + 1 end
assert_eq(count, 0, "All ghosts removed when cargo is empty")
assert_true(m2.isDestroyed, "Unit 2 mesh destroyed")

-- Test 6: Transport cancelling unload command destroys ghosts
local u3 = CreateMockUnit('u103', 1)
transport._cargo = { u3 }
transport._queue = {
    {
        type = 'TransportUnloadUnits',
        position = { x = 50, y = 5, z = 50, [1] = 50, [2] = 5, [3] = 50 }
    }
}
mgr:Update(1, { transport })
assert_true(mgr:GetActiveGhosts()['u103'] ~= nil, "Ghost u103 spawned")

-- Cancel unload command
transport._queue = { { type = 'Move', position = { x = 0, y = 0, z = 0 } } }
mgr:Update(1, { transport })
assert_true(mgr:GetActiveGhosts()['u103'] == nil, "Ghost u103 destroyed on unload cancel")

-- Test 7: Transport death destroys ghosts
transport._queue = {
    {
        type = 'TransportUnloadUnits',
        position = { x = 50, y = 5, z = 50, [1] = 50, [2] = 5, [3] = 50 }
    }
}
mgr:Update(1, { transport })
assert_true(mgr:GetActiveGhosts()['u103'] ~= nil, "Ghost u103 re-spawned")
local g3 = mgr:GetActiveGhosts()['u103']
local m3 = g3.mesh

transport._dead = true
mgr:Update(1, { transport })
assert_true(mgr:GetActiveGhosts()['u103'] == nil, "Ghost destroyed on transport death")
assert_true(m3.isDestroyed, "Mesh destroyed on transport death")

-- Test 8: Enemy transport is ignored
local enemyTransport = CreateMockTransport('t_enemy', 2, { CreateMockUnit('u_enemy', 2) }, {
    { type = 'TransportUnloadUnits', position = { x = 10, y = 0, z = 10 } }
})
mgr:Update(1, { enemyTransport })
count = 0
for _ in pairs(mgr:GetActiveGhosts()) do count = count + 1 end
assert_eq(count, 0, "Enemy transport produces no ghosts")

-- Test 9: ClearAll cleanly wipes state
local u4 = CreateMockUnit('u104', 1)
local transport2 = CreateMockTransport('t2', 1, { u4 }, {
    { type = 'TransportUnloadUnits', position = { x = 10, y = 0, z = 10 } }
})
mgr:Update(1, { transport2 })
assert_true(mgr:GetActiveGhosts()['u104'] ~= nil, "Ghost u104 spawned")
local g4 = mgr:GetActiveGhosts()['u104']
local m4 = g4.mesh

mgr:ClearAll()
count = 0
for _ in pairs(mgr:GetActiveGhosts()) do count = count + 1 end
assert_eq(count, 0, "ClearAll emptied active ghosts")
assert_true(m4.isDestroyed, "ClearAll destroyed mesh")

print("test_drop_ghosts_manager: ALL PASSED")
