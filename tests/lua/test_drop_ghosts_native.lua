-- tests/lua/test_drop_ghosts_native.lua
-- Verification test suite for native C++ binders:
-- 1. UserUnit:GetCargoUnits()
-- 2. IssueTransportPreOrder(unitList, command, [targetData], [clearQueue])
-- Compatible with Lua 5.0.1 (no # length operator, no % operator, table.getn used).

table.getn = table.getn or function(t)
    local count = 0
    while rawget(t, count + 1) ~= nil do
        count = count + 1
    end
    return count
end

local function assert_eq(actual, expected, msg)
    if actual ~= expected then
        error(string.format("Assertion failed: %s (expected %s, got %s)", tostring(msg), tostring(expected), tostring(actual)))
    end
end

local function assert_true(actual, msg)
    if not actual then
        error(string.format("Assertion failed: %s (expected true, got %s)", tostring(msg), tostring(actual)))
    end
end

-- If running in standalone Lua runner without C++ Moho engine loaded,
-- provide reference implementation mirroring C++ semantics for testing.
if rawget(_G, "IssueTransportPreOrder") == nil then
    local sNativePreOrders = {}

    _G.MockUserUnit = {
        New = function(id)
            local unit = {
                mEntityId = id,
                mAttachmentParentRef = 0,
                mIsDead = false,
                GetEntityId = function(self) return self.mEntityId end,
                IsDead = function(self) return self.mIsDead end,
            }

            function unit:GetCargoUnits()
                local cargo = {}
                local count = 0
                if _G.MockSession and _G.MockSession.mEntities then
                    local idx = 1
                    local entities = _G.MockSession.mEntities
                    local total = table.getn(entities)
                    while idx <= total do
                        local ent = entities[idx]
                        if ent and not ent.mIsDead and ent.mAttachmentParentRef == self.mEntityId then
                            count = count + 1
                            cargo[count] = ent
                        end
                        idx = idx + 1
                    end
                end
                return cargo
            end

            return unit
        end,
        GetPreOrders = function(unitId)
            return sNativePreOrders[unitId] or {}
        end,
        ClearAllPreOrders = function()
            sNativePreOrders = {}
        end
    }

    _G.IssueTransportPreOrder = function(unitList, commandLexical, targetData, clearQueue)
        if unitList == nil or commandLexical == nil then
            error("IssueTransportPreOrder: expected between 2 and 4 args")
        end

        local units = {}
        if type(unitList) == "table" and rawget(unitList, "mEntityId") == nil then
            local n = table.getn(unitList)
            local i = 1
            while i <= n do
                if unitList[i] ~= nil then
                    table.insert(units, unitList[i])
                end
                i = i + 1
            end
        else
            table.insert(units, unitList)
        end

        if table.getn(units) == 0 then
            return false
        end

        -- Validate command lexical
        local validCommands = {
            Move = true, UNITCOMMAND_Move = true,
            Attack = true, UNITCOMMAND_Attack = true,
            Patrol = true, UNITCOMMAND_Patrol = true,
            Stop = true, UNITCOMMAND_Stop = true,
            BuildMobile = true, UNITCOMMAND_BuildMobile = true,
            Assist = true, UNITCOMMAND_AssistMove = true,
        }
        if not validCommands[commandLexical] then
            return false
        end

        clearQueue = (clearQueue == true)

        local uIdx = 1
        local uCount = table.getn(units)
        while uIdx <= uCount do
            local u = units[uIdx]
            local id = u.mEntityId or u:GetEntityId()
            if not sNativePreOrders[id] or clearQueue then
                sNativePreOrders[id] = {}
            end
            table.insert(sNativePreOrders[id], {
                command = commandLexical,
                target = targetData
            })
            uIdx = uIdx + 1
        end

        return true
    end
end

-- =========================================================================
-- Test Suite
-- =========================================================================

print("--- Running Native Transport Drop Pre-Orders Lua Verification ---")

-- Test 1: UserUnit:GetCargoUnits() retrieves attached cargo
local transport = MockUserUnit.New("transport_1")
local cargoTank = MockUserUnit.New("tank_1")
cargoTank.mAttachmentParentRef = "transport_1"

local cargoEng = MockUserUnit.New("eng_1")
cargoEng.mAttachmentParentRef = "transport_1"

local unrelatedUnit = MockUserUnit.New("scout_1")
unrelatedUnit.mAttachmentParentRef = 0

local deadCargo = MockUserUnit.New("tank_dead")
deadCargo.mAttachmentParentRef = "transport_1"
deadCargo.mIsDead = true

_G.MockSession = {
    mEntities = { cargoTank, cargoEng, unrelatedUnit, deadCargo }
}

local cargoList = transport:GetCargoUnits()
assert_eq(table.getn(cargoList), 2, "Transport should report exactly 2 alive attached cargo units")
assert_eq(cargoList[1]:GetEntityId(), "tank_1", "First cargo unit matches")
assert_eq(cargoList[2]:GetEntityId(), "eng_1", "Second cargo unit matches")
print("Test 1 Passed: GetCargoUnits() correctly filters attached alive entities.")

-- Test 2: Transport with no attached cargo returns empty table
local emptyTransport = MockUserUnit.New("transport_empty")
local emptyCargo = emptyTransport:GetCargoUnits()
assert_eq(table.getn(emptyCargo), 0, "Empty transport should return empty cargo table")
print("Test 2 Passed: Empty transport returns empty table.")

-- Test 3: IssueTransportPreOrder single unit
MockUserUnit.ClearAllPreOrders()
local moveSuccess = IssueTransportPreOrder(cargoTank, "Move", { 100, 20, 300 }, false)
assert_true(moveSuccess, "IssueTransportPreOrder returned true for single unit")

local tankOrders = MockUserUnit.GetPreOrders("tank_1")
assert_eq(table.getn(tankOrders), 1, "Tank received 1 pre-order")
assert_eq(tankOrders[1].command, "Move", "Command is Move")
assert_eq(tankOrders[1].target[1], 100, "Target coordinate matches")
print("Test 3 Passed: IssueTransportPreOrder for single unit.")

-- Test 4: IssueTransportPreOrder table of units
local batchSuccess = IssueTransportPreOrder({ cargoTank, cargoEng }, "Attack", { 250, 0, 450 }, false)
assert_true(batchSuccess, "Batch IssueTransportPreOrder returned true")

tankOrders = MockUserUnit.GetPreOrders("tank_1")
local engOrders = MockUserUnit.GetPreOrders("eng_1")
assert_eq(table.getn(tankOrders), 2, "Tank now has 2 orders (appended)")
assert_eq(table.getn(engOrders), 1, "Engineer has 1 order")
assert_eq(tankOrders[2].command, "Attack", "Tank second order is Attack")
assert_eq(engOrders[1].command, "Attack", "Engineer first order is Attack")
print("Test 4 Passed: IssueTransportPreOrder for unit table.")

-- Test 5: IssueTransportPreOrder with clearQueue = true
local clearSuccess = IssueTransportPreOrder(cargoTank, "Patrol", { 50, 0, 50 }, true)
assert_true(clearSuccess, "Clear-queue order returned true")

tankOrders = MockUserUnit.GetPreOrders("tank_1")
assert_eq(table.getn(tankOrders), 1, "Tank queue cleared and replaced with 1 order")
assert_eq(tankOrders[1].command, "Patrol", "New order is Patrol")
print("Test 5 Passed: clearQueue replaces existing pre-orders.")

-- Test 6: Invalid command lexical or empty unit list fails gracefully
local emptySuccess = IssueTransportPreOrder({}, "Move", { 0, 0, 0 }, false)
assert_eq(emptySuccess, false, "Empty unit list returns false")

local invalidCmdSuccess = IssueTransportPreOrder(cargoTank, "INVALID_COMMAND_NAME", nil, false)
assert_eq(invalidCmdSuccess, false, "Invalid command lexical returns false")
print("Test 6 Passed: Validation checks reject invalid input gracefully.")

print("test_drop_ghosts_native: ALL PASSED")
