-- tests/lua/test_drop_ghosts_integration.lua
-- End-to-end integration test validating the entire Transport Unload Ghosts pipeline:
-- 1. Lifecycle hook in gamemain.lua initializes modules and hooks worldview.
-- 2. Transport with cargo (tank & engineer) receives unload order.
-- 3. DropGhostsManager spawns 3D hologram ghosts at drop location.
-- 4. DropGhostsSelection handles click to select ghost units and syncs UI.
-- 5. Player issues move order to tank and build order to engineer.
-- 6. DropGhostsDispatcher renders waypoints.
-- 7. Transport lands (touchdown): cargo is detached, orders dispatched to real units.
-- 8. Clean UI shutdown cleans up all ghosts, waypoints, and buffers.

table.getn = table.getn or function(t) return #t end

package.path = package.path .. ";I:/FaforeverFiles/mods/TransportDropGhosts/modules/?.lua;I:/FaforeverFiles/mods/TransportDropGhosts/hook/lua/ui/game/?.lua;modules/?.lua"

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

-- ============================================================================
-- 1. Engine & Environment Mocks
-- ============================================================================

local createdMeshes = {}
local MockWorldMesh = {}
MockWorldMesh.__index = MockWorldMesh

function MockWorldMesh.New()
    local m = {
        meshDescriptor = nil,
        stance = nil,
        orientation = nil,
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

-- Command Execution Spies
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

-- Focus Army
local currentFocusArmy = 1
_G.GetFocusArmy = function()
    return currentFocusArmy
end

-- Gamemain lifecycle hooks
local registeredBeatFunctions = {}
_G.AddBeatFunction = function(fn)
    table.insert(registeredBeatFunctions, fn)
end

_G.OnDestroyFuncs = {}

-- Mock UI Orders & Construction modules
local mockOrders
mockOrders = {
    callCount = 0,
    lastAvailableOrders = nil,
    SetAvailableOrders = function(orders, toggles, units)
        mockOrders.callCount = mockOrders.callCount + 1
        mockOrders.lastAvailableOrders = orders
    end
}

local mockConstruction
mockConstruction = {
    callCount = 0,
    lastBuildableCategories = nil,
    OnSelection = function(buildable, units, isOld)
        mockConstruction.callCount = mockConstruction.callCount + 1
        mockConstruction.lastBuildableCategories = buildable
    end
}

-- Mock WorldView
local MockWorldView = {}
MockWorldView.__index = MockWorldView

function MockWorldView.New()
    local wv = {
        Left = function() return 0 end,
        Top = function() return 0 end,
        Width = function() return 1920 end,
        Height = function() return 1080 end,
        HandleEvent = function(self, event)
            -- Default unhooked handler returns false
            return false
        end
    }
    return setmetatable(wv, MockWorldView)
end

function MockWorldView:Project(pos)
    local px = (pos.x or pos[1] or 0) * 2
    local py = (pos.z or pos[3] or 0) * 2
    return { x = px, y = py, [1] = px, [2] = py }
end

function MockWorldView:Unproject(screenX, screenY)
    return { x = screenX / 2, y = 20, z = screenY / 2, [1] = screenX / 2, [2] = 20, [3] = screenY / 2 }
end

local mockPrimaryView = MockWorldView.New()
local mockWorldviewModule = {
    viewInitial1 = mockPrimaryView,
    viewLeft = mockPrimaryView,
    GetWorldViews = function()
        return { mockPrimaryView }
    end
}

-- Mock FAF import function
local modulesCache = {}
_G.import = function(path)
    if path == '/lua/ui/game/worldview.lua' then
        return mockWorldviewModule
    elseif path == '/lua/ui/game/orders.lua' then
        return mockOrders
    elseif path == '/lua/ui/game/construction.lua' then
        return mockConstruction
    elseif path == '/lua/ui/controls/worldmesh.lua' then
        return { WorldMesh = MockWorldMesh.New }
    elseif path == '/lua/ui/game/commandmeshes.lua' then
        return {
            commandMeshResources = {
                Move = { '/meshes/game/Move_lod0.scm', '/meshes/game/Move_albedo.dds' },
                Build = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' },
                UNITCOMMAND_BuildMobile = { '/meshes/game/Assist_lod0.scm', '/meshes/game/Assist_albedo.dds' }
            }
        }
    elseif path == '/mods/TransportDropGhosts/modules/drop_ghosts_buffer.lua' or path == 'drop_ghosts_buffer.lua' then
        if not modulesCache['buffer'] then
            modulesCache['buffer'] = require('drop_ghosts_buffer')
        end
        return modulesCache['buffer']
    elseif path == '/mods/TransportDropGhosts/modules/drop_ghosts_manager.lua' or path == 'drop_ghosts_manager.lua' then
        if not modulesCache['manager'] then
            modulesCache['manager'] = require('drop_ghosts_manager')
        end
        return modulesCache['manager']
    elseif path == '/mods/TransportDropGhosts/modules/drop_ghosts_selection.lua' or path == 'drop_ghosts_selection.lua' then
        if not modulesCache['selection'] then
            modulesCache['selection'] = require('drop_ghosts_selection')
        end
        return modulesCache['selection']
    elseif path == '/mods/TransportDropGhosts/modules/drop_ghosts_dispatcher.lua' or path == 'drop_ghosts_dispatcher.lua' then
        if not modulesCache['dispatcher'] then
            modulesCache['dispatcher'] = require('drop_ghosts_dispatcher')
        end
        return modulesCache['dispatcher']
    end
    error("Mock import could not resolve: " .. tostring(path))
end

-- ============================================================================
-- 2. Mock Units Creation Helper
-- ============================================================================

local function CreateMockUnit(id, army, bp)
    local u = {
        _id = id,
        _army = army or 1,
        _bp = bp,
        _attached = true,
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        GetBlueprint = function(self) return self._bp end,
        IsDead = function(self) return false end,
        GetPosition = function(self) return { 100, 20, 100 } end
    }
    return u
end

local function CreateMockTransport(id, army, cargoUnits, queue)
    local t = {
        _id = id,
        _army = army or 1,
        _cargo = cargoUnits or {},
        _queue = queue or {},
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        GetCommandQueue = function(self) return self._queue end,
        GetCargo = function(self) return self._cargo end,
        IsDead = function(self) return false end
    }
    return t
end

-- Wire GetAttachedUnitsList
local attachedByTransport = {}
_G.GetAttachedUnitsList = function(transports)
    local res = {}
    for _, t in ipairs(transports or {}) do
        local tid = t:GetEntityId()
        if attachedByTransport[tid] then
            for _, u in ipairs(attachedByTransport[tid]) do
                table.insert(res, u)
            end
        end
    end
    return res
end

-- ============================================================================
-- 3. Execution: Load Gamemain Hook and CreateUI
-- ============================================================================

print("--- Running Drop Ghosts End-to-End Integration Test ---")

dofile("I:/FaforeverFiles/mods/TransportDropGhosts/hook/lua/ui/game/gamemain.lua")
local GamemainHook = _G.DropGhostsGamemain or DropGhostsGamemain
assert_true(GamemainHook ~= nil, "GamemainHook module loaded successfully")

-- Initialize UI
GamemainHook.CreateUI(false)

assert_eq(#registeredBeatFunctions, 1, "AddBeatFunction registered 1 OnBeat callback")
assert_true(#_G.OnDestroyFuncs >= 1, "OnDestroyFuncs registered cleanup callback")

-- Ensure WorldView HandleEvent was hooked
assert_true(mockPrimaryView._dropGhostsHooked == true, "mockPrimaryView was hooked by gamemain")

local ManagerModule = _G.DropGhostsManager or import('/mods/TransportDropGhosts/modules/drop_ghosts_manager.lua')
local SelectionModule = _G.DropGhostsSelection or import('/mods/TransportDropGhosts/modules/drop_ghosts_selection.lua')
local DispatcherModule = _G.DropGhostsDispatcher or import('/mods/TransportDropGhosts/modules/drop_ghosts_dispatcher.lua')
local BufferModule = import('/mods/TransportDropGhosts/modules/drop_ghosts_buffer.lua')
local BufferInstance = ManagerModule.GetBuffer()

SelectionModule.SetOrdersModule(mockOrders)
SelectionModule.SetConstructionModule(mockConstruction)

-- ============================================================================
-- 4. Setup Transport with Tank and Engineer
-- ============================================================================

local tank = CreateMockUnit(201, 1, {
    BlueprintId = 'uel0201',
    General = {
        CommandCaps = { RULEUCC_Move = true, RULEUCC_Attack = true },
        ToggleCaps = {}
    },
    Display = { MeshBlueprint = '/units/uel0201/uel0201_mesh', UniformScale = 0.1 }
})

local engineer = CreateMockUnit(202, 1, {
    BlueprintId = 'uel0105',
    General = {
        CommandCaps = { RULEUCC_Move = true },
        ToggleCaps = {}
    },
    Economy = {
        BuildableCategory = { 'BUILTBYTIER1ENGINEER UEF' }
    },
    Display = { MeshBlueprint = '/units/uel0105/uel0105_mesh', UniformScale = 0.1 }
})

local transport = CreateMockTransport(100, 1, { tank, engineer }, {
    {
        type = 'TransportUnloadUnits',
        commandType = 'TransportUnloadUnits',
        position = { 200, 20, 300 }
    }
})

attachedByTransport[100] = { tank, engineer }
ManagerModule.RegisterTransport(transport)

-- ============================================================================
-- 5. Beat 1: Manager Spawns 3D Ghosts
-- ============================================================================

print("Step 1: Beat update spawns 3D ghosts at unload waypoint...")
registeredBeatFunctions[1]()

local activeGhosts = ManagerModule.GetActiveGhosts()
local ghostCount = 0
local tankGhost = nil
local engGhost = nil

for id, ghost in pairs(activeGhosts) do
    ghostCount = ghostCount + 1
    local unit = ghost.realUnit or ghost
    if unit:GetEntityId() == 201 then
        tankGhost = ghost
    elseif unit:GetEntityId() == 202 then
        engGhost = ghost
    end
end

assert_eq(ghostCount, 2, "DropGhostsManager spawned exactly 2 ghosts")
assert_true(tankGhost ~= nil, "Tank ghost was created")
assert_true(engGhost ~= nil, "Engineer ghost was created")
assert_true(tankGhost.mesh ~= nil, "Tank ghost has 3D WorldMesh")
assert_true(engGhost.mesh ~= nil, "Engineer ghost has 3D WorldMesh")
print("Step 1 Passed: 2 ghosts spawned with 3D meshes at drop location.")

-- ============================================================================
-- 6. Player Selects Tank Ghost via WorldView Click
-- ============================================================================

print("Step 2: WorldView click selects Tank ghost...")
local tankScreen = mockPrimaryView:Project(tankGhost.position)
local leftClickTankEvent = {
    Type = 'ButtonPress',
    MouseX = tankScreen.x,
    MouseY = tankScreen.y,
    Modifiers = { Left = true }
}

local handled = mockPrimaryView:HandleEvent(leftClickTankEvent)
assert_true(handled, "Tank click event was handled/consumed by DropGhostsSelection")
assert_true(SelectionModule.IsActive(), "SelectionModule reports active ghost selection")

local currentSel = SelectionModule.GetSelection()
assert_true(currentSel[201] ~= nil or currentSel[1] ~= nil, "Tank ghost is in active selection")
assert_true(mockOrders.lastAvailableOrders ~= nil, "Orders UI was synced")
print("Step 2 Passed: Tank ghost selected and UI synced with available commands.")

-- ============================================================================
-- 7. Player Issues Move Order to Tank
-- ============================================================================

print("Step 3: Player issues Move order to Tank ghost...")
local rightClickMoveEvent = {
    Type = 'ButtonPress',
    MouseX = 500,
    MouseY = 500,
    Modifiers = { Right = true },
    CommandType = 'Move',
    TargetPos = { x = 250, y = 20, z = 350 }
}

local moveHandled = mockPrimaryView:HandleEvent(rightClickMoveEvent)
assert_true(moveHandled, "Right click move order was handled/consumed")

local tankOrders = BufferInstance:GetOrders(201)
assert_eq(#tankOrders, 1, "Tank has 1 buffered pending order")
assert_eq(tankOrders[1].commandType, 'Move', "Buffered order is Move")
assert_eq(tankOrders[1].targetData.x, 250, "Move target x is 250")
assert_eq(tankOrders[1].targetData.z, 350, "Move target z is 350")
print("Step 3 Passed: Move order buffered for tank.")

-- ============================================================================
-- 8. Player Selects Engineer Ghost via WorldView Click
-- ============================================================================

print("Step 4: WorldView click selects Engineer ghost...")
local engScreen = mockPrimaryView:Project(engGhost.position)
local leftClickEngEvent = {
    Type = 'ButtonPress',
    MouseX = engScreen.x,
    MouseY = engScreen.y,
    Modifiers = { Left = true }
}

local engHandled = mockPrimaryView:HandleEvent(leftClickEngEvent)
assert_true(engHandled, "Engineer click event was handled/consumed")

local engSel = SelectionModule.GetSelection()
assert_true(engSel[202] ~= nil or engSel[1] ~= nil, "Engineer ghost is now selected")
assert_true(mockConstruction.lastBuildableCategories ~= nil, "Construction UI was synced")
assert_eq(mockConstruction.lastBuildableCategories[1], 'BUILTBYTIER1ENGINEER UEF', "Buildable categories synced correctly")
print("Step 4 Passed: Engineer ghost selected and construction palette synced.")

-- ============================================================================
-- 9. Player Issues Build Order to Engineer
-- ============================================================================

print("Step 5: Player issues Build order to Engineer ghost...")
local rightClickBuildEvent = {
    Type = 'ButtonPress',
    MouseX = 600,
    MouseY = 600,
    Modifiers = { Right = true },
    CommandType = 'UNITCOMMAND_BuildMobile',
    BlueprintId = 'ueb3101',
    TargetPos = { x = 210, y = 20, z = 310, blueprintId = 'ueb3101' }
}

local buildHandled = mockPrimaryView:HandleEvent(rightClickBuildEvent)
assert_true(buildHandled, "Right click build order was handled/consumed")

local engOrders = BufferInstance:GetOrders(202)
assert_eq(#engOrders, 1, "Engineer has 1 buffered pending order")
assert_eq(engOrders[1].commandType, 'UNITCOMMAND_BuildMobile', "Buffered order is UNITCOMMAND_BuildMobile")
assert_eq(engOrders[1].targetData.blueprintId, 'ueb3101', "Buffered blueprintId is ueb3101")
print("Step 5 Passed: Build order buffered for engineer.")

-- ============================================================================
-- 10. Beat 2: Dispatcher Renders Waypoint Meshes
-- ============================================================================

print("Step 6: Beat update renders waypoints while flight is in progress...")
registeredBeatFunctions[1]()

local tankWaypoints = DispatcherModule.GetWaypoints(201)
local engWaypoints = DispatcherModule.GetWaypoints(202)

assert_eq(#tankWaypoints, 1, "Tank has 1 waypoint mesh rendered")
assert_eq(#engWaypoints, 1, "Engineer has 1 waypoint mesh rendered")
assert_false(tankWaypoints[1].mesh.isDestroyed, "Tank waypoint mesh is active")
assert_false(engWaypoints[1].mesh.isDestroyed, "Engineer waypoint mesh is active")

-- Verify no orders dispatched while still in flight
assert_eq(#issuedUnitCommands, 0, "No unit commands dispatched while in flight")
assert_eq(#issuedBlueprintCommands, 0, "No blueprint commands dispatched while in flight")
print("Step 6 Passed: Waypoint meshes rendered for queued orders without early dispatch.")

-- ============================================================================
-- 11. Touchdown: Cargo Unloaded, Orders Dispatched to Real Units
-- ============================================================================

print("Step 7: Transport unloads cargo (touchdown); orders dispatch to real units...")
-- Units disembark from transport
attachedByTransport[100] = {}
transport._cargo = {}

registeredBeatFunctions[1]()

-- Verify dispatch to real units
assert_eq(#issuedUnitCommands, 1, "1 unit command dispatched")
assert_eq(issuedUnitCommands[1].unit, tank, "Unit command dispatched to real Tank")
assert_eq(issuedUnitCommands[1].command, 'Move', "Dispatched command was Move")
assert_eq(issuedUnitCommands[1].luaParams.x, 250, "Move destination x is 250")
assert_eq(issuedUnitCommands[1].luaParams.z, 350, "Move destination z is 350")

assert_eq(#issuedBlueprintCommands, 1, "1 blueprint command dispatched")
assert_eq(issuedBlueprintCommands[1].units[1], engineer, "Blueprint command dispatched to real Engineer")
assert_eq(issuedBlueprintCommands[1].command, 'UNITCOMMAND_BuildMobile', "Dispatched command was UNITCOMMAND_BuildMobile")
assert_eq(issuedBlueprintCommands[1].blueprintId, 'ueb3101', "Dispatched blueprintId was ueb3101")

-- Verify waypoints cleaned up on touchdown
local remainingTankWaypoints = DispatcherModule.GetWaypoints(201)
local remainingEngWaypoints = DispatcherModule.GetWaypoints(202)
assert_eq(#remainingTankWaypoints, 0, "Tank waypoints cleared after touchdown")
assert_eq(#remainingEngWaypoints, 0, "Engineer waypoints cleared after touchdown")
print("Step 7 Passed: Real tank and engineer received their queued orders upon landing.")

-- ============================================================================
-- 12. Full Cleanup on Session Teardown
-- ============================================================================

print("Step 8: Session teardown cleanup...")
GamemainHook.Cleanup()

assert_false(SelectionModule.IsActive(), "Selection cleared")
assert_eq(#BufferInstance:GetOrders(201), 0, "Tank buffer cleared")
assert_eq(#BufferInstance:GetOrders(202), 0, "Engineer buffer cleared")

local postCleanupGhosts = ManagerModule.GetActiveGhosts()
local remainingCount = 0
for _ in pairs(postCleanupGhosts) do
    remainingCount = remainingCount + 1
end
assert_eq(remainingCount, 0, "All active ghosts destroyed on cleanup")

print("Step 8 Passed: Complete clean teardown verified.")

print("test_drop_ghosts_integration: ALL PASSED")
