-- faf_re_patchtest: sim half of the FA-Binary-Patches port tests (tools/scenarios/1p-faf-patches.yaml;
-- the UI half is tools/scenarios/faf-patches/hook). Every check logs
-- "PATCHTEST PASS|FAIL sim <name> <detail>", and the end "PATCHTEST RESULT sim failures=<n>";
-- a script error leaves the result line out.

local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')

local failures = 0

local function Check(name, ok, detail)
    if not ok then
        failures = failures + 1
    end
    LOG(string.format('PATCHTEST %s sim %s %s', ok and 'PASS' or 'FAIL', name, tostring(detail or '')))
end

function OnPopulate(scenario)
    ScenarioUtils.InitializeArmies()
end

-- BuildUnit/SelectUnit (issue #13): three UEF engineers start, at a slow build rate, a T1 point
-- defense (CQUEMOV), a T1 power generator (neither CQUEMOV nor FACTORY) and a T1 land factory
-- (FACTORY); the UI checks which of them it can select while they are being built.
local Structures = {
    { bp = 'ueb2101', dx = 14, dz = 0 },
    { bp = 'ueb1101', dx = -14, dz = 0 },
    { bp = 'ueb0101', dx = 0, dz = 22 },
}

local function StartStructures()
    local brain = ArmyBrains[1]
    local x0, z0 = brain:GetArmyStartPos()
    for _, entry in Structures do
        local x, z = x0 + entry.dx, z0 + entry.dz
        local engineer = CreateUnitHPR('uel0105', brain.Name, x + 3, GetSurfaceHeight(x + 3, z), z + 3, 0, 0, 0)
        engineer:SetBuildRate(0.2)
        IssueBuildMobile({ engineer }, { x, GetSurfaceHeight(x, z), z }, entry.bp, {})
    end
end

local function Tests()
    WaitSeconds(1)
    StartStructures()

    -- ForkThreadFix: a C function is refused, a Lua function still forks.
    local refused, message = pcall(ForkThread, LOG)
    Check('ForkThread(cfunction) refused', not refused and string.find(tostring(message), "isn't a function", 1, true) ~= nil, message)
    local forked, forkError = pcall(ForkThread, function() end)
    Check('ForkThread(lua function) accepted', forked, forkError)

    -- VDist3: a missing vector or component counts as 0 instead of an error.
    local distOk, dist = pcall(VDist3, {3, 4, 0}, nil)
    Check('VDist3(vector, nil)', distOk and math.abs(dist - 5) < 1e-4, dist)
    local shortOk, short = pcall(VDist3, {3, 4}, {0, 0, 0})
    Check('VDist3 short vector', shortOk and math.abs(short - 5) < 1e-4, short)
    Check('VDist3 normal', math.abs(VDist3({1, 2, 3}, {4, 6, 3}) - 5) < 1e-4)

    -- GetMouseWorldPos is registered in the sim state too.
    Check('GetMouseWorldPos in sim', rawget(_G, 'GetMouseWorldPos') ~= nil)

    -- GetDepositsAroundPoint: result keys are X1 Z1 X2 Z2 Type Dist.
    local startX, startZ = ArmyBrains[1]:GetArmyStartPos()
    local deposits = GetDepositsAroundPoint(startX, startZ, 80, 0)
    local first = deposits and deposits[1]
    Check('deposit keys', first ~= nil and first.X1 ~= nil and first.Z2 ~= nil and first.Type ~= nil and first.Dist ~= nil and first.x1 == nil,
        first and string.format('n=%d X1=%s Type=%s Dist=%s', table.getn(deposits), tostring(first.X1), tostring(first.Type), tostring(first.Dist)))

    -- weakgcmarkerFix: weak tables that become unreachable are collected.
    collectgarbage()
    local before = gcinfo()
    local keep = {}
    for i = 1, 20000 do
        keep[i] = setmetatable({ i, i, i, i }, { __mode = 'k' })
    end
    collectgarbage()
    local filled = gcinfo()
    keep = nil
    collectgarbage()
    collectgarbage()
    local after = gcinfo()
    Check('weak tables collected', (after - before) < (filled - before) / 4, string.format('before=%d filled=%d after=%d KB', before, filled, after))

    LOG('PATCHTEST RESULT sim failures=' .. failures)

    -- ObserverFix: take army 1 out of the game at 25 s; the UI then checks it cannot switch to
    -- observer.
    while GetGameTimeSeconds() < 25 do
        WaitSeconds(0.5)
    end
    SetArmyOutOfGame(1)
    LOG('PATCHTEST info sim army 1 out of game')
end

function OnStart(scenario)
    ForkThread(Tests)
end
