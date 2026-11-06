-- tests/lua/test_drop_ghosts_selection.lua
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

-- Mock WorldView
local MockWorldView = {}
MockWorldView.__index = MockWorldView

function MockWorldView.New(projectionMap, unprojectFn)
    local wv = {
        _projections = projectionMap or {},
        _unprojectFn = unprojectFn
    }
    return setmetatable(wv, MockWorldView)
end

function MockWorldView:Project(pos)
    local key = string.format("%.1f,%.1f,%.1f", pos.x or pos[1] or 0, pos.y or pos[2] or 0, pos.z or pos[3] or 0)
    if self._projections[key] then
        return self._projections[key]
    end
    -- Default simple projection: screen X = world X, screen Y = world Z
    return { x = pos.x or pos[1] or 0, y = pos.z or pos[3] or 0, [1] = pos.x or pos[1] or 0, [2] = pos.z or pos[3] or 0 }
end

function MockWorldView:Unproject(screenX, screenY)
    if self._unprojectFn then
        return self._unprojectFn(screenX, screenY)
    end
    return { x = screenX, y = 0, z = screenY, [1] = screenX, [2] = 0, [3] = screenY }
end

-- Mock Unit & Blueprint helpers
local function CreateMockUnit(id, army, commandCaps, buildableCategories)
    return {
        _id = id,
        _army = army or 1,
        _bp = {
            BlueprintId = id,
            General = {
                CommandCaps = commandCaps or {
                    RULEUCC_Move = true,
                    RULEUCC_Attack = true,
                    RULEUCC_Stop = true
                },
                ToggleCaps = {
                    RULEUTC_WeaponToggle = false
                }
            },
            Economy = {
                BuildableCategory = buildableCategories or nil
            }
        },
        GetEntityId = function(self) return self._id end,
        GetArmy = function(self) return self._army end,
        GetBlueprint = function(self) return self._bp end,
        IsDead = function(self) return false end
    }
end

-- Mock Orders & Construction modules for spying UI updates
local mockOrders
mockOrders = {
    callCount = 0,
    lastAvailableOrders = nil,
    lastAvailableToggles = nil,
    lastSelectedUnits = nil,
    SetAvailableOrders = function(orders, toggles, units)
        mockOrders.callCount = mockOrders.callCount + 1
        mockOrders.lastAvailableOrders = orders
        mockOrders.lastAvailableToggles = toggles
        mockOrders.lastSelectedUnits = units
    end,
    Reset = function()
        mockOrders.callCount = 0
        mockOrders.lastAvailableOrders = nil
        mockOrders.lastAvailableToggles = nil
        mockOrders.lastSelectedUnits = nil
    end
}

local mockConstruction
mockConstruction = {
    callCount = 0,
    lastBuildableCategories = nil,
    lastSelectedUnits = nil,
    lastIsOldSelection = nil,
    OnSelection = function(buildable, units, isOld)
        mockConstruction.callCount = mockConstruction.callCount + 1
        mockConstruction.lastBuildableCategories = buildable
        mockConstruction.lastSelectedUnits = units
        mockConstruction.lastIsOldSelection = isOld
    end,
    Reset = function()
        mockConstruction.callCount = 0
        mockConstruction.lastBuildableCategories = nil
        mockConstruction.lastSelectedUnits = nil
        mockConstruction.lastIsOldSelection = nil
    end
}

-- Load modules
local BufferModule = require('drop_ghosts_buffer')
local SelectionModule = require('drop_ghosts_selection')

SelectionModule.SetOrdersModule(mockOrders)
SelectionModule.SetConstructionModule(mockConstruction)

-- Mock Manager
local MockManager = {}
MockManager.__index = MockManager

function MockManager.New(buffer)
    return setmetatable({
        _ghosts = {},
        _buffer = buffer
    }, MockManager)
end

function MockManager:GetActiveGhosts()
    return self._ghosts
end

function MockManager:GetBuffer()
    return self._buffer
end

-- ========================================================================
-- Test 1: Click hit-test on projected coordinates (hit vs miss)
-- ========================================================================
local buf1 = BufferModule.Create()
local mgr1 = MockManager.New(buf1)
local sel1 = SelectionModule.Create(mgr1, buf1)

local u1 = CreateMockUnit('u_combat_1', 1)
mgr1._ghosts['u_combat_1'] = {
    id = 'u_combat_1',
    ghostId = 'u_combat_1',
    realUnit = u1,
    position = { x = 100, y = 10, z = 200, [1] = 100, [2] = 10, [3] = 200 }
}

local wv1 = MockWorldView.New({
    ['100.0,10.0,200.0'] = { x = 300, y = 400, [1] = 300, [2] = 400 }
})

mockOrders.Reset()
mockConstruction.Reset()

-- Miss: click at (100, 100) -> distance to (300, 400) is ~360 px > hitRadius 25
local missEvent = {
    Type = 'ButtonPress',
    MouseX = 100,
    MouseY = 100,
    Modifiers = { Left = true, Right = false, Shift = false }
}
local handledMiss = sel1:HandleWorldClick(wv1, missEvent)
assert_false(handledMiss, "Miss event is not handled")
assert_false(sel1:IsActive(), "Selection remains inactive on miss")
assert_eq(mockOrders.callCount, 0, "Orders not updated on miss")

-- Hit: click at (310, 410) -> distance sqrt(100+100)=14.14 px <= 25 px
local hitEvent = {
    Type = 'ButtonPress',
    MouseX = 310,
    MouseY = 410,
    Modifiers = { Left = true, Right = false, Shift = false }
}
local handledHit = sel1:HandleWorldClick(wv1, hitEvent)
assert_true(handledHit, "Hit event handled successfully")
assert_true(sel1:IsActive(), "Selection is now active")
local selGhosts = sel1:GetSelection()
assert_eq(#selGhosts, 1, "One ghost selected")
assert_true(selGhosts['u_combat_1'] ~= nil, "Ghost u_combat_1 is selected")
assert_true(mockOrders.callCount > 0, "Orders panel synced on hit")
assert_true(mockConstruction.callCount > 0, "Construction panel synced on hit")

-- Verify command caps populated
local hasMoveCap = false
for _, cap in ipairs(mockOrders.lastAvailableOrders) do
    if cap == 'RULEUCC_Move' then hasMoveCap = true end
end
assert_true(hasMoveCap, "RULEUCC_Move available in orders")

-- ========================================================================
-- Test 2: Single click selection vs Shift-click toggle
-- ========================================================================
local u2 = CreateMockUnit('u_combat_2', 1)
mgr1._ghosts['u_combat_2'] = {
    id = 'u_combat_2',
    ghostId = 'u_combat_2',
    realUnit = u2,
    position = { x = 120, y = 10, z = 220, [1] = 120, [2] = 10, [3] = 220 }
}
wv1._projections['120.0,10.0,220.0'] = { x = 350, y = 450, [1] = 350, [2] = 450 }

-- Shift-click on u_combat_2 -> adds to selection (both u1 and u2 selected)
local shiftAddEvent = {
    Type = 'ButtonPress',
    MouseX = 352,
    MouseY = 448,
    Modifiers = { Left = true, Right = false, Shift = true }
}
local handledShiftAdd = sel1:HandleWorldClick(wv1, shiftAddEvent)
assert_true(handledShiftAdd, "Shift-click add handled")
selGhosts = sel1:GetSelection()
assert_eq(#selGhosts, 2, "Both ghosts selected with Shift-click")
assert_true(selGhosts['u_combat_1'] ~= nil, "u_combat_1 still selected")
assert_true(selGhosts['u_combat_2'] ~= nil, "u_combat_2 now selected")

-- Shift-click again on u_combat_1 -> toggles OFF u_combat_1 (only u2 remains)
local shiftRemoveEvent = {
    Type = 'ButtonPress',
    MouseX = 302,
    MouseY = 401,
    Modifiers = { Left = true, Right = false, Shift = true }
}
local handledShiftRemove = sel1:HandleWorldClick(wv1, shiftRemoveEvent)
assert_true(handledShiftRemove, "Shift-click toggle-off handled")
selGhosts = sel1:GetSelection()
assert_eq(#selGhosts, 1, "Only 1 ghost selected after toggle-off")
assert_true(selGhosts['u_combat_1'] == nil, "u_combat_1 toggled off")
assert_true(selGhosts['u_combat_2'] ~= nil, "u_combat_2 still selected")

-- Single click (no Shift) on u_combat_1 -> replaces selection (only u1 selected)
local singleClickEvent = {
    Type = 'ButtonPress',
    MouseX = 299,
    MouseY = 400,
    Modifiers = { Left = true, Right = false, Shift = false }
}
sel1:HandleWorldClick(wv1, singleClickEvent)
selGhosts = sel1:GetSelection()
assert_eq(#selGhosts, 1, "Only 1 ghost selected after single click replace")
assert_true(selGhosts['u_combat_1'] ~= nil, "u_combat_1 is selected")
assert_true(selGhosts['u_combat_2'] == nil, "u_combat_2 is deselected")

-- ========================================================================
-- Test 3: Box drag multi-selection
-- ========================================================================
-- Drag rectangle covering both ghosts (bounds: [280, 380] to [370, 470])
local handledDrag = sel1:HandleWorldDrag(wv1, 280, 380, 370, 470)
assert_true(handledDrag, "Box drag enclosing ghosts returned true")
selGhosts = sel1:GetSelection()
assert_eq(#selGhosts, 2, "Box drag captured both ghosts")
assert_true(selGhosts['u_combat_1'] ~= nil, "u1 captured by drag")
assert_true(selGhosts['u_combat_2'] ~= nil, "u2 captured by drag")

-- Drag rectangle on empty space (bounds: [0, 0] to [50, 50])
local handledEmptyDrag = sel1:HandleWorldDrag(wv1, 0, 0, 50, 50)
assert_false(handledEmptyDrag, "Box drag enclosing nothing returned false")

-- Drag with inverted coordinates (min/max swapped)
local handledInvertedDrag = sel1:HandleWorldDrag(wv1, 370, 470, 280, 380)
assert_true(handledInvertedDrag, "Inverted box drag handled successfully")
assert_eq(#sel1:GetSelection(), 2, "Inverted box drag captured ghosts")

-- ========================================================================
-- Test 4: Right-click order interception and buffering into DropGhostsBuffer
-- ========================================================================
-- Right-click when ghosts are selected -> intercepted and buffered!
local rightClickEvent = {
    Type = 'ButtonPress',
    MouseX = 500,
    MouseY = 600,
    Modifiers = { Left = false, Right = true, Shift = false },
    CommandType = 'Move'
}
local handledRightClick = sel1:HandleWorldClick(wv1, rightClickEvent)
assert_true(handledRightClick, "Right-click order intercepted")

local ordersU1 = buf1:GetOrders('u_combat_1')
local ordersU2 = buf1:GetOrders('u_combat_2')
assert_eq(#ordersU1, 1, "u1 received 1 buffered order")
assert_eq(#ordersU2, 1, "u2 received 1 buffered order")
assert_eq(ordersU1[1].commandType, 'Move', "u1 order type is Move")
assert_eq(ordersU1[1].targetData.x, 500, "u1 order target X via unproject")
assert_eq(ordersU1[1].targetData.z, 600, "u1 order target Z via unproject")

-- Right-click with Shift -> appends queue
local rightClickShiftEvent = {
    Type = 'ButtonPress',
    MouseX = 550,
    MouseY = 650,
    Modifiers = { Left = false, Right = true, Shift = true },
    CommandType = 'Attack'
}
sel1:HandleWorldClick(wv1, rightClickShiftEvent)
ordersU1 = buf1:GetOrders('u_combat_1')
assert_eq(#ordersU1, 2, "u1 has 2 orders after shift right-click")
assert_eq(ordersU1[2].commandType, 'Attack', "u1 second order type is Attack")
assert_eq(ordersU1[2].targetData.x, 550, "u1 second order target X")

-- Right-click without Shift -> replaces queue
local rightClickReplaceEvent = {
    Type = 'ButtonPress',
    MouseX = 700,
    MouseY = 800,
    Modifiers = { Left = false, Right = true, Shift = false },
    CommandType = 'Patrol'
}
sel1:HandleWorldClick(wv1, rightClickReplaceEvent)
ordersU1 = buf1:GetOrders('u_combat_1')
assert_eq(#ordersU1, 1, "u1 orders replaced without shift")
assert_eq(ordersU1[1].commandType, 'Patrol', "u1 new order type is Patrol")

-- ========================================================================
-- Test 5: Clear selection & Inactive state right-click pass-through
-- ========================================================================
mockOrders.Reset()
mockConstruction.Reset()

sel1:ClearSelection()
assert_false(sel1:IsActive(), "Selection is inactive after ClearSelection")
assert_eq(#sel1:GetSelection(), 0, "GetSelection is empty")
assert_eq(mockOrders.callCount, 1, "Orders reset called on ClearSelection")
assert_eq(#mockOrders.lastAvailableOrders, 0, "Available orders empty on clear")
assert_eq(mockConstruction.callCount, 1, "Construction reset called on ClearSelection")
assert_eq(#mockConstruction.lastBuildableCategories, 0, "Buildable categories empty on clear")

-- Right-click when NO ghosts selected -> NOT intercepted (returns false)
local passThroughRight = sel1:HandleWorldClick(wv1, rightClickEvent)
assert_false(passThroughRight, "Right-click passes through when no ghosts selected")

-- ========================================================================
-- Test 6: Engineer Ghost Selection & Construction Palette Sync
-- ========================================================================
local engCategories = { 'BUILTBYTIER1ENGINEER UEF', 'BUILTBYTIER1FIELD UEF' }
local uEng = CreateMockUnit('u_eng_1', 1, {
    RULEUCC_Move = true,
    RULEUCC_Reclaim = true,
    RULEUCC_Repair = true,
    RULEUCC_Capture = true
}, engCategories)

mgr1._ghosts['u_eng_1'] = {
    id = 'u_eng_1',
    ghostId = 'u_eng_1',
    realUnit = uEng,
    position = { x = 50, y = 0, z = 50, [1] = 50, [2] = 0, [3] = 50 }
}
wv1._projections['50.0,0.0,50.0'] = { x = 100, y = 100, [1] = 100, [2] = 100 }

mockOrders.Reset()
mockConstruction.Reset()

local engClick = {
    Type = 'ButtonPress',
    MouseX = 100,
    MouseY = 100,
    Modifiers = { Left = true, Right = false, Shift = false }
}
sel1:HandleWorldClick(wv1, engClick)
assert_true(sel1:IsActive(), "Engineer ghost selected")
assert_true(mockConstruction.callCount > 0, "Construction panel updated for engineer")
assert_true(#mockConstruction.lastBuildableCategories >= 2, "Buildable categories provided to construction")

local foundEngCategory = false
for _, cat in ipairs(mockConstruction.lastBuildableCategories) do
    if cat == 'BUILTBYTIER1ENGINEER UEF' then foundEngCategory = true end
end
assert_true(foundEngCategory, "BUILTBYTIER1ENGINEER UEF passed to construction.OnSelection")

-- ========================================================================
-- Test 7: Static dot-syntax API compatibility
-- ========================================================================
SelectionModule.SetManager(mgr1)
SelectionModule.SetBuffer(buf1)
SelectionModule.ClearSelection()
assert_false(SelectionModule.IsActive(), "Static IsActive is false after ClearSelection")

-- Static HandleWorldClick
local staticHandled = SelectionModule.HandleWorldClick(wv1, engClick)
assert_true(staticHandled, "Static HandleWorldClick handled click")
assert_true(SelectionModule.IsActive(), "Static IsActive is true")
local staticSel = SelectionModule.GetSelection()
assert_eq(#staticSel, 1, "Static GetSelection returned 1 ghost")
assert_true(staticSel['u_eng_1'] ~= nil, "Engineer ghost selected via static API")

-- Static HandleWorldDrag
local staticDragHandled = SelectionModule.HandleWorldDrag(wv1, 280, 380, 370, 470)
assert_true(staticDragHandled, "Static HandleWorldDrag handled drag")
assert_eq(#SelectionModule.GetSelection(), 2, "Two ghosts selected via static drag")

-- Static ClearSelection
SelectionModule.ClearSelection()
assert_false(SelectionModule.IsActive(), "Static IsActive false after static ClearSelection")

-- ========================================================================
-- Test 8: Closest ghost selection when two ghosts are within hit radius
-- ========================================================================
local buf2 = BufferModule.Create()
local mgr2 = MockManager.New(buf2)
local sel2 = SelectionModule.Create(mgr2, buf2)

local uCloseA = CreateMockUnit('u_close_a', 1)
local uCloseB = CreateMockUnit('u_close_b', 1)

mgr2._ghosts['u_close_a'] = {
    id = 'u_close_a',
    ghostId = 'u_close_a',
    realUnit = uCloseA,
    position = { x = 10, y = 0, z = 10, [1] = 10, [2] = 0, [3] = 10 }
}
mgr2._ghosts['u_close_b'] = {
    id = 'u_close_b',
    ghostId = 'u_close_b',
    realUnit = uCloseB,
    position = { x = 12, y = 0, z = 12, [1] = 12, [2] = 0, [3] = 12 }
}

-- Projected: A is at (100, 100), B is at (115, 100)
local wv2 = MockWorldView.New({
    ['10.0,0.0,10.0'] = { x = 100, y = 100, [1] = 100, [2] = 100 },
    ['12.0,0.0,12.0'] = { x = 115, y = 100, [1] = 115, [2] = 100 }
})

-- Click at (105, 100): distance to A is 5 px, distance to B is 10 px (both <= 25 px)
local closeClick = {
    Type = 'ButtonPress',
    MouseX = 105,
    MouseY = 100,
    Modifiers = { Left = true, Right = false, Shift = false }
}
sel2:HandleWorldClick(wv2, closeClick)
local selClose = sel2:GetSelection()
assert_eq(#selClose, 1, "Only 1 ghost selected when two are in range")
assert_true(selClose['u_close_a'] ~= nil, "Closest ghost A was selected")
assert_true(selClose['u_close_b'] == nil, "Farther ghost B was not selected")

-- ========================================================================
-- Test 9: Pruning destroyed ghosts from selection
-- ========================================================================
-- When manager removes a ghost (e.g. transport unloaded unit), GetSelection prunes it
mgr2._ghosts['u_close_a'] = nil -- destroyed/unloaded
local prunedSel = sel2:GetSelection()
assert_eq(#prunedSel, 0, "Pruned selection is now empty")
assert_false(sel2:IsActive(), "Selection automatically became inactive after pruning")

-- ========================================================================
-- Test 10: Box drag with Shift modifier appends to existing selection
-- ========================================================================
mgr2._ghosts['u_close_a'] = {
    id = 'u_close_a',
    ghostId = 'u_close_a',
    realUnit = uCloseA,
    position = { x = 10, y = 0, z = 10, [1] = 10, [2] = 0, [3] = 10 }
}
-- Single click to select A
sel2:HandleWorldClick(wv2, {
    Type = 'ButtonPress',
    MouseX = 100,
    MouseY = 100,
    Modifiers = { Left = true, Right = false, Shift = false }
})
assert_eq(#sel2:GetSelection(), 1, "Initially A selected")

-- Drag box over B with Shift = true
sel2:HandleWorldDrag(wv2, 110, 90, 120, 110, true)
local dragShiftSel = sel2:GetSelection()
assert_eq(#dragShiftSel, 2, "Both A and B selected after Shift-drag")
assert_true(dragShiftSel['u_close_a'] ~= nil, "A still selected after Shift-drag")
assert_true(dragShiftSel['u_close_b'] ~= nil, "B added via Shift-drag")

print("test_drop_ghosts_selection: ALL PASSED")
