# Transport Drop Ghosts & Pre-orders (UI Mod) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide virtual 3D hologram "ghost" units at planned transport unload waypoints, allow players to select ghosts individually or en masse and queue tactical/engineering orders before landing, and automatically dispatch buffered orders to real units the moment they touch ground. Packaged as a client-side FAF UI Mod in `I:\FaforeverFiles\mods\TransportDropGhosts`.

**Architecture:** 100% pure client-side FAF UI Mod (`ui_only = true`) compatible with both `ForgedAlliance.exe` and `faf-re`. Follows FAF UI mod conventions (`mod_info.lua`, `hook/lua/ui/game/gamemain.lua`, `modules/`). Uses `GetAttachedUnitsList({ transport })` to query cargo, `WorldMesh` for 3D visualization, `WorldView:Project` for selection hit-testing, and `IssueUnitCommandToUnit` / `IssueBlueprintCommandToUnits` for order dispatch.

**Tech Stack:** FAF UI Mod Lua, `GetAttachedUnitsList`, `WorldMesh` (`/lua/ui/controls/worldmesh.lua`), `WorldView:Project`, `IssueUnitCommandToUnit` (`/lua/userInit.lua`).

**Target Path:** `I:\FaforeverFiles\mods\TransportDropGhosts`

**Spec:** [docs/specs/2026-11-07-transport-unload-ghosts-design.md](file:///i:/ProjectsFaf/faf-re/docs/specs/2026-11-07-transport-unload-ghosts-design.md)

## Global Constraints

- Client-side FAF UI Mod (`ui_only = true`) — usable in ranked ladder games and custom games.
- 100% Retail Engine Compatible (`ForgedAlliance.exe` and `faf-re`).
- Zero Sim state mutations before physical landing — zero desync risk.
- Strictly client-side UI Lua execution (`/lua/ui/game/`).
- Standard unit selection behavior (click and drag box select ghosts without artificial filters).
- Triggered strictly for the local player's own transports (`focusArmy == transport:GetArmy()`).

## Review Focus

1. **Cargo querying via `GetAttachedUnitsList`:** UI uses `GetAttachedUnitsList({ transport })` (as in `construction.lua:2444`), never non-existent UI methods.
2. **Transport shot down while in transit:** Ghosts and buffered orders must be instantly garbage-collected with no dangling `WorldMesh` or memory leaks.
3. **Player cancels or re-routes unload waypoint:** Repositioning an unload waypoint shifts all ghost formation positions and path origins; clearing `TransportUnloadUnits` wipes ghosts and queues.
4. **Queueing orders without Shift vs with Shift:** Non-shift order clears existing pre-orders for that ghost; Shift-order appends to the queue.
5. **Engineer construction commands:** When placing buildings for an engineer ghost, records blueprint ID and position, and dispatches via `IssueBlueprintCommandToUnits` / `IssueUnitCommand` upon disembarkation.

---

### Task 1: UI Mod Metadata & Pure Lua Pending Orders Buffer with Unit Tests

**Files:**
- Create: `I:\FaforeverFiles\mods\TransportDropGhosts\mod_info.lua`
- Create: `I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_buffer.lua`
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

- [ ] **Step 1: Write `mod_info.lua`**

```lua
-- I:\FaforeverFiles\mods\TransportDropGhosts\mod_info.lua
name = "Transport Drop Ghosts"
version = 1
copyright = "FAF Community"
description = "Shows 3D hologram ghost units at transport unload waypoints to queue orders before landing."
author = "FAF Community"
url = ""
uid = "c4d710b1-9b7e-49f2-8c11-9a35db9d0efa"
exclusive = false
ui_only = true
selectable = true
enabled = true
```

- [ ] **Step 2: Write failing unit test `tests/lua/test_drop_ghosts_buffer.lua`**

```lua
-- tests/lua/test_drop_ghosts_buffer.lua
package.path = package.path .. ";I:/FaforeverFiles/mods/TransportDropGhosts/modules/?.lua"
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

- [ ] **Step 3: Run test to verify it fails**

Run: `powershell -ExecutionPolicy Bypass -File tests/run_lua_tests.ps1`
Expected: FAIL (`module 'drop_ghosts_buffer' not found`).

- [ ] **Step 4: Implement `I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_buffer.lua`**

```lua
-- I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_buffer.lua
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

if _G.import then
    -- FAF Lua import compatibility
else
    return { Create = Create }
end
```

- [ ] **Step 5: Run test to verify it passes**

Run: `powershell -ExecutionPolicy Bypass -File tests/run_lua_tests.ps1`
Expected: PASS (`test_drop_ghosts_buffer: ALL PASSED`).

- [ ] **Step 6: Commit test harness and mod files**

```bash
git add tests/lua/test_drop_ghosts_buffer.lua tests/run_lua_tests.ps1
git commit -m "feat(mod): create UI mod scaffold and pending drop orders buffer with unit tests"
```

---

### Task 2: 3D Ghost Visual Manager (`modules/drop_ghosts_manager.lua`)

**Files:**
- Create: `I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_manager.lua`

**Interfaces:**
- Consumes:
  - `GetAttachedUnitsList({ transport })` (`construction.lua:2444`) to enumerate cargo units.
  - `/lua/ui/controls/worldmesh.lua`: `WorldMesh()` with shader `'FakeRings'` / `'RallyPoint'`.
  - `transport:GetCommandQueue()` to find `TransportUnloadUnits` waypoint positions.
- Produces:
  - `DropGhostsManager.Update(focusArmy)`: ticks active player transports, scans for `TransportUnloadUnits` waypoints, generates/updates/destroys `WorldMesh` holograms.
  - `DropGhostsManager.GetActiveGhosts()`: returns table of active `{ ghostId, realUnit, position, mesh }`.
  - `DropGhostsManager.DestroyGhost(ghostId)`: safely frees a single hologram mesh and its buffer.
  - `DropGhostsManager.ClearAll()`: cleanly deletes all meshes and resets state.

- [ ] **Step 1: Implement `modules/drop_ghosts_manager.lua`**
- [ ] **Step 2: Commit**

---

### Task 3: Selection Proxy & Input Interception (`modules/drop_ghosts_selection.lua`)

**Files:**
- Create: `I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_selection.lua`

**Interfaces:**
- Consumes:
  - `DropGhostsManager:GetActiveGhosts()`: list of world positions and units.
  - `WorldView:Project()`: screen coordinate conversions.
  - `import("/lua/ui/game/orders.lua").SetAvailableOrders`: to populate abilities.
  - `import("/lua/ui/game/construction.lua").OnSelection`: to show engineer palettes.
- Produces:
  - `DropGhostsSelection.HandleWorldClick(worldView, event)`: detects click on ghosts and sets active ghost selection.
  - `DropGhostsSelection.HandleWorldDrag(worldView, minX, minY, maxX, maxY)`: detects drag-box containment for multi-selection.
  - `DropGhostsSelection.GetSelection()`: returns currently selected ghost records.

- [ ] **Step 1: Implement screen hit-testing with `WorldView:Project` in `drop_ghosts_selection.lua`**
- [ ] **Step 2: Connect selection updates to `orders.SetAvailableOrders` and `construction.OnSelection`**
- [ ] **Step 3: Commit**

---

### Task 4: Waypoint Path Rendering & Order Dispatcher (`modules/drop_ghosts_dispatcher.lua`)

**Files:**
- Create: `I:\FaforeverFiles\mods\TransportDropGhosts\modules\drop_ghosts_dispatcher.lua`

**Interfaces:**
- Consumes:
  - `DropGhostsBuffer:GetOrders(unitEntityId)`: retrieves planned queue.
  - `IssueUnitCommandToUnit` (`/lua/userInit.lua`) / `IssueBlueprintCommandToUnits` for orders.
  - `commandMeshResources` (`/lua/ui/game/commandmeshes.lua`) for waypoint icons.
- Produces:
  - `DropGhostsDispatcher.OnBeat()`: polls `GetAttachedUnitsList({ transport })`; when a unit is no longer attached (unloaded), dispatches buffered orders to the `realUnit`.
  - `DropGhostsDispatcher.DrawWaypoints()`: renders colored path lines from drop position to destination waypoints.

- [ ] **Step 1: Implement dispatch logic on disembark**
- [ ] **Step 2: Implement line rendering for queued orders using standard waypoint meshes**
- [ ] **Step 3: Commit**

---

### Task 5: Integration Hook in `hook/lua/ui/game/gamemain.lua` & Scenario Verification

**Files:**
- Create: `I:\FaforeverFiles\mods\TransportDropGhosts\hook\lua\ui\game\gamemain.lua`
- Create: `tools/scenarios/drop-ghosts-smoke.yaml`

- [ ] **Step 1: Wire `AddBeatFunction` and world input hook in `hook/lua/ui/game/gamemain.lua`**
- [ ] **Step 2: Author scenario smoke test in `tools/scenarios/drop-ghosts-smoke.yaml`**
- [ ] **Step 3: Run scenario / test suite to verify full integration**
- [ ] **Step 4: Commit**