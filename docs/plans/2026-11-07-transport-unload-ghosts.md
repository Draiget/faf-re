# Transport Unload Ghost Units & Queued Orders Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide virtual 3D hologram "ghost" units at planned transport unload waypoints, allow players to select ghosts individually or en masse and queue tactical/engineering orders before landing, and automatically dispatch buffered orders to real units the moment they touch ground.

**Architecture:** Entirely implemented in client-side FAF UI Lua to guarantee zero desync risk and full retail engine (`ForgedAlliance.exe`) compatibility. Composed of an isolated pure-Lua command buffer, a 3D `WorldMesh` visual manager, a `WorldView:Project` selection proxy interfacing with `orders.lua` and `construction.lua`, and an unload event dispatcher.

**Tech Stack:** FAF UI Lua, `WorldMesh` (`/lua/ui/controls/worldmesh.lua`), `WorldView:Project`, `IssueUnitCommand`.

**Spec:** [docs/specs/2026-11-07-transport-unload-ghosts-design.md](file:///i:/ProjectsFaf/faf-re/docs/specs/2026-11-07-transport-unload-ghosts-design.md)

## Global Constraints

- 100% Retail Engine Compatible (`ForgedAlliance.exe` and `faf-re`).
- Zero Sim state mutations before physical landing — zero desync risk.
- Strictly client-side UI Lua execution (`/lua/ui/game/`).
- Standard unit selection behavior (click and drag box select ghosts without artificial filters).
- Triggered strictly for the local player's own transports (`focusArmy == transport:GetArmy()`).

## Review Focus

1. **Transport shot down while in transit:** Ghosts and buffered orders must be instantly garbage-collected with no dangling `WorldMesh` or memory leaks.
2. **Player cancels or re-routes unload waypoint:** Repositioning an unload waypoint shifts all ghost formation positions and path origins; clearing `Unload` wipes ghosts and queues.
3. **Queueing orders without Shift vs with Shift:** Non-shift order clears existing pre-orders for that ghost; Shift-order appends to the queue.
4. **Engineer construction commands:** Construction blueprints selected while an engineer ghost is active must record blueprint ID and build position correctly for dispatch.
5. **Simultaneous group unload:** When multiple units disembark across consecutive ticks, each unit receives its specific queue without order mixing.

---

### Task 1: Pure Lua Pending Orders Buffer & Unit Test Suite

**Files:**
- Create: `data/fafengine/lua/ui/game/drop_ghosts_buffer.lua`
- Create: `tests/lua/test_drop_ghosts_buffer.lua`
- Create: `tests/run_lua_tests.ps1`

**Interfaces:**
- Produces:
  - `DropGhostsBuffer.Create()`: creates a new buffer instance.
  - `buffer:AddOrder(unitEntityId, commandType, targetData, appendQueue)`: appends or replaces an order for a unit.
  - `buffer:GetOrders(unitEntityId)`: returns array of `{commandType, targetData}`.
  - `buffer:ClearUnitOrders(unitEntityId)`: clears orders for a unit.
  - `buffer:ClearAll()`: wipes all pending orders.
  - `buffer:ShiftPositions(offsetVector)`: adjusts target coordinates of position-based orders when a drop point is relocated.

- [ ] **Step 1: Write the failing Lua unit test**

```lua
-- tests/lua/test_drop_ghosts_buffer.lua
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

-- Test 5: Clear unit orders
buf:ClearUnitOrders('u100')
assert_eq(table.getn(buf:GetOrders('u100')), 0, "Cleared orders count")

print("test_drop_ghosts_buffer: ALL PASSED")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -ExecutionPolicy Bypass -File tests/run_lua_tests.ps1`
Expected: FAIL (module `drop_ghosts_buffer` not found).

- [ ] **Step 3: Implement `drop_ghosts_buffer.lua`**

```lua
-- data/fafengine/lua/ui/game/drop_ghosts_buffer.lua
local DropGhostsBuffer = {}
DropGhostsBuffer.__index = DropGhostsBuffer

function Create()
    local instance = {
        _ordersByUnit = {}
    }
    return setmetatable(instance, DropGhostsBuffer)
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

-- Export for both FAF environment and standard Lua
if _G.import then
    -- FAF Lua environment
else
    return { Create = Create }
end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `powershell -ExecutionPolicy Bypass -File tests/run_lua_tests.ps1`
Expected: PASS (`test_drop_ghosts_buffer: ALL PASSED`).

- [ ] **Step 5: Commit**

```bash
git add data/fafengine/lua/ui/game/drop_ghosts_buffer.lua tests/lua/test_drop_ghosts_buffer.lua tests/run_lua_tests.ps1
git commit -m "feat(ui): add pure Lua pending drop orders buffer with unit tests"
```

---

### Task 2: 3D Ghost Visual Manager (`drop_ghosts_manager.lua`)

**Files:**
- Create: `data/fafengine/lua/ui/game/drop_ghosts_manager.lua`

**Interfaces:**
- Consumes:
  - `/lua/ui/controls/worldmesh.lua`: `WorldMesh()` for 3D visual proxies.
  - `data/fafengine/lua/ui/game/drop_ghosts_buffer.lua`: order storage.
- Produces:
  - `DropGhostsManager.Update(focusArmy)`: ticks active player transports, scans for `Unload` waypoints, generates/updates/destroys `WorldMesh` holograms.
  - `DropGhostsManager.GetActiveGhosts()`: returns table of active `{ ghostId, realUnit, position, mesh }`.
  - `DropGhostsManager.DestroyGhost(ghostId)`: safely frees a single hologram mesh and its buffer.
  - `DropGhostsManager.ClearAll()`: cleanly deletes all meshes and resets state.

- [ ] **Step 1: Implement `drop_ghosts_manager.lua`**

```lua
-- data/fafengine/lua/ui/game/drop_ghosts_manager.lua
local WorldMesh = import('/lua/ui/controls/worldmesh.lua').WorldMesh
local Buffer = import('/lua/ui/game/drop_ghosts_buffer.lua')

local DropGhostsManager = {
    _buffer = Buffer.Create(),
    _activeGhosts = {}, -- [ghostId] = { id, realUnit, transport, position, mesh }
    _lastWaypointPositions = {} -- [transportEntityId] = Vector(x, y, z)
}

-- Calculate radial formation offset for N units around drop center
local function GetFormationOffset(index, totalCount, radius)
    if totalCount <= 1 then
        return 0, 0
    end
    local angle = (index - 1) * (2 * math.pi / totalCount)
    return math.cos(angle) * radius, math.sin(angle) * radius
end

function DropGhostsManager:Update(focusArmy)
    if not focusArmy or focusArmy < 1 then return end

    -- Map current valid transports
    local seenTransports = {}
    local activeUnits = GetSelectedUnits() or {} -- or focusArmy unit scanner

    -- Process registered transports...
    -- Spawn WorldMesh with blueprint model and hologram/fake ring shader
    -- Position with GetFormationOffset around unload waypoint
end

function DropGhostsManager:GetActiveGhosts()
    return self._activeGhosts
end

function DropGhostsManager:DestroyGhost(ghostId)
    local ghost = self._activeGhosts[ghostId]
    if ghost then
        if ghost.mesh and ghost.mesh.Destroy then
            ghost.mesh:Destroy()
        end
        self._buffer:ClearUnitOrders(ghost.realUnit:GetEntityId())
        self._activeGhosts[ghostId] = nil
    end
end

function DropGhostsManager:ClearAll()
    for id, _ in pairs(self._activeGhosts) do
        self:DestroyGhost(id)
    end
    self._activeGhosts = {}
    self._lastWaypointPositions = {}
end
```

- [ ] **Step 2: Commit**

```bash
git add data/fafengine/lua/ui/game/drop_ghosts_manager.lua
git commit -m "feat(ui): add drop ghosts 3D visual manager"
```

---

### Task 3: Selection Proxy & Input Hook (`drop_ghosts_selection.lua`)

**Files:**
- Create: `data/fafengine/lua/ui/game/drop_ghosts_selection.lua`
- Modify: `data/fafengine/lua/ui/game/gamemain.lua` (hook mouse input / selection events)

**Interfaces:**
- Consumes:
  - `DropGhostsManager.GetActiveGhosts()`: list of world positions and units.
  - `WorldView:Project()`: screen coordinate conversions.
- Produces:
  - `DropGhostsSelection.HandleWorldClick(mouseEvent)`: detects click on ghosts and sets active ghost selection.
  - `DropGhostsSelection.HandleWorldDrag(rect)`: detects drag-box containment for multi-selection.
  - `DropGhostsSelection.GetSelection()`: returns currently selected ghost records.

- [ ] **Step 1: Implement screen hit-testing in `drop_ghosts_selection.lua`**
- [ ] **Step 2: Connect selection to `orders.lua` and `construction.lua`**
- [ ] **Step 3: Commit**

```bash
git add data/fafengine/lua/ui/game/drop_ghosts_selection.lua
git commit -m "feat(ui): add ghost selection proxy and UI input hooks"
```

---

### Task 4: Waypoint Path Rendering & Order Dispatcher (`drop_ghosts_dispatcher.lua`)

**Files:**
- Create: `data/fafengine/lua/ui/game/drop_ghosts_dispatcher.lua`

**Interfaces:**
- Consumes:
  - `DropGhostsBuffer.GetOrders(unitEntityId)`: retrieves planned queue.
  - `IssueUnitCommand`: FAF engine Lua command dispatch.
- Produces:
  - `DropGhostsDispatcher.OnUnitUnloaded(realUnit)`: iterates buffered orders and dispatches via `IssueUnitCommand({realUnit}, cmd, data, clear)`.
  - `DropGhostsDispatcher.DrawWaypoints()`: renders colored path lines from drop position to destination waypoints.

- [ ] **Step 1: Implement dispatch logic on disembark**
- [ ] **Step 2: Implement line rendering for queued orders**
- [ ] **Step 3: Commit**

```bash
git add data/fafengine/lua/ui/game/drop_ghosts_dispatcher.lua
git commit -m "feat(ui): add queued order waypoint renderer and disembark dispatcher"
```

---

### Task 5: Integration Hook & Scenario Smoke Test

**Files:**
- Modify: `data/fafengine/lua/ui/game/gamemain.lua`
- Create: `tools/scenarios/drop-ghosts-smoke.yaml`

- [ ] **Step 1: Hook lifecycle in `gamemain.lua`**
- [ ] **Step 2: Author scenario smoke test in `tools/scenarios/drop-ghosts-smoke.yaml`**
- [ ] **Step 3: Run scenario / test suite to verify full integration**
- [ ] **Step 4: Commit**

```bash
git add data/fafengine/lua/ui/game/gamemain.lua tools/scenarios/drop-ghosts-smoke.yaml
git commit -m "feat(ui): integrate drop ghosts subsystem and add scenario smoke test"
```