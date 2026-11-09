-- faf-re test: the unit zoo (tests/replay/README.md). The zoo init file mounts this folder at /zoo and names /zoo
-- a hook folder, so the engine appends this file to FAF's /lua/simInit.lua. On top of a recorded game it spawns
-- every unit blueprint for the first two armies, wave by wave, lets them fight, then kills or destroys what is left,
-- and after that drives the commands, economy and AI calls the waves don't reach. Everything is deterministic:
-- blueprint ids are sorted, tables are walked as arrays, and nothing reads the clock, so the sim's checksums are
-- the same on every run and on the original game (the golden file next to the test).
do
    local TableGetn = table.getn
    local TableInsert = table.insert

    local function Log(text)
        LOG('ZOO: ' .. text)
    end

    -- A blueprint's categories as a set, from its category list (the same list on every engine).
    local function Categories(bp)
        local set = {}
        local list = bp and bp.Categories
        if list then
            for i = 1, TableGetn(list) do
                set[list[i]] = true
            end
        end
        return set
    end

    local function Alive(unit)
        return unit and not IsDestroyed(unit) and not unit.Dead
    end

    -- Calls fn(...) and logs a failure instead of stopping the zoo; returns fn's first result. Only the arguments
    -- given are passed on: the engine's functions reject trailing nils as extra arguments.
    local function Try(what, fn, ...)
        local ok, result = pcall(fn, unpack(arg))
        if not ok then
            Log(what .. ' failed: ' .. tostring(result))
            return nil
        end
        return result
    end

    local Zoo = { trace = false } -- trace: a log line before every sweep call, to find a crashing one

    function Zoo.Setup()
        local armies = ListArmies()
        Zoo.a = armies[1]
        Zoo.b = armies[2]
        local size = ScenarioInfo.size
        Zoo.w = size[1]
        Zoo.h = size[2]
        Zoo.cx = Zoo.w / 2
        Zoo.cz = Zoo.h / 2
        -- The first spot (in a fixed scan order) with water deep enough for ships.
        for gx = 16, Zoo.w - 16, 16 do
            for gz = 16, Zoo.h - 16, 16 do
                if not Zoo.wx and GetSurfaceHeight(gx, gz) > GetTerrainHeight(gx, gz) + 3 then
                    Zoo.wx = gx
                    Zoo.wz = gz
                end
            end
        end
        -- FAF's preset placeholders (spawn_dummy_*) are left out: the original game hangs creating
        -- spawn_dummy_1214_-3-6_22 (its sim stops at that CreateUnitHPR and never comes back).
        Zoo.ids = {}
        local all = EntityCategoryGetUnitList(categories.ALLUNITS)
        for i = 1, TableGetn(all) do
            if string.sub(all[i], 1, 12) ~= 'spawn_dummy_' then
                TableInsert(Zoo.ids, all[i])
            end
        end
        table.sort(Zoo.ids)
        Log(TableGetn(Zoo.ids) .. ' unit blueprints, armies ' .. tostring(Zoo.a) .. ' ' .. tostring(Zoo.b)
            .. ', water ' .. tostring(Zoo.wx) .. ',' .. tostring(Zoo.wz))
    end

    local function Clamp(v, low, high)
        if v < low then return low end
        if v > high then return high end
        return v
    end

    function Zoo.Spawn(id, army, x, z, heading)
        x = Clamp(x, 8, Zoo.w - 8)
        z = Clamp(z, 8, Zoo.h - 8)
        return Try('create ' .. id, CreateUnitHPR, id, army, x, GetSurfaceHeight(x, z), z, 0, heading, 0)
    end

    -- One wave: each blueprint once per army, facing each other, then an attack-move across.
    function Zoo.Wave(first, count)
        local spawned = {}
        local last = math.min(first + count - 1, TableGetn(Zoo.ids))
        for i = first, last do
            local id = Zoo.ids[i]
            local cats = Categories(__blueprints[id])
            local x, z = Zoo.cx, Zoo.cz
            local naval = cats.NAVAL and not cats.HOVER and not cats.AMPHIBIOUS
            if naval and Zoo.wx then
                x, z = Zoo.wx, Zoo.wz
            end
            do -- ships on a map without deep water stand on land: their creation, weapons and death still run
                if Zoo.trace then Log('spawn ' .. id .. ' tick ' .. GetGameTick()) end
                local offset = (i - first) * 5 - count * 2.5
                local ua = Zoo.Spawn(id, Zoo.a, x - 30, z + offset, 1.57)
                local ub = Zoo.Spawn(id, Zoo.b, x + 30, z + offset, -1.57)
                if ua then TableInsert(spawned, { unit = ua, side = 1, cats = cats }) end
                if ub then TableInsert(spawned, { unit = ub, side = 2, cats = cats }) end
            end
        end
        for k = 1, TableGetn(spawned) do
            local s = spawned[k]
            if Alive(s.unit) and s.cats.MOBILE then
                local tx = s.side == 1 and Zoo.cx + 40 or Zoo.cx - 40
                Try('attack-move', IssueAggressiveMove, { s.unit }, { tx, 0, Zoo.cz })
            end
        end
        WaitTicks(130)
        for k = 1, TableGetn(spawned) do
            local s = spawned[k]
            if Alive(s.unit) then
                if Zoo.trace then Log('end ' .. s.unit:GetUnitId() .. ' ' .. k .. ' tick ' .. GetGameTick()) end
                if math.mod(k, 2) == 0 then
                    Try('kill', s.unit.Kill, s.unit)
                else
                    Try('destroy', s.unit.Destroy, s.unit)
                end
            end
        end
        WaitTicks(20)
        return TableGetn(spawned)
    end

    -- A method table's function names, sorted: the engines may lay a table out differently, so its walk order is
    -- never used. The engine's own functions are of type 'cfunction' in this Lua.
    local function SortedFunctionNames(methods)
        local names = {}
        for name, value in methods do
            if type(name) == 'string' and (type(value) == 'cfunction' or type(value) == 'function') then
                TableInsert(names, name)
            end
        end
        table.sort(names)
        return names
    end

    local GetterPrefixes = { 'Get', 'Is', 'Can', 'Has', 'Should', 'Calc', 'Find', 'Test', 'Count', 'Check' }

    local function IsGetter(name)
        for i = 1, TableGetn(GetterPrefixes) do
            local prefix = GetterPrefixes[i]
            if string.sub(name, 1, string.len(prefix)) == prefix then
                return true
            end
        end
        return false
    end

    -- Getters that crash the original game too, so the sweep leaves them out:
    -- weapon:GetProjectileBlueprint() on a beam weapon (no projectile blueprint): 0x006D8C90 hands the weapon's
    -- blueprint pointer (+0x4C) to 0x0050DF90, which reads [blueprint+0x5C] unchecked.
    -- platoon:IsCommandsActive(1): 0x00731F80 counts its second argument with lua_getn (0x0090AD30), which reads any
    -- value as a table.
    -- unit:GetAttacker() never returns in the original game (its sim stops there; ours returns).
    local SkipGetters = {
        ['weapon_methods.GetProjectileBlueprint'] = true,
        ['unit_methods.GetAttacker'] = true,
        ['platoon_methods.IsCommandsActive'] = true,
    }

    -- Every getter of moho[tableName] on `object`, once without an argument and once with 1 (an index, an army).
    -- Errors are expected (a getter that needs another argument) and still run the engine's argument checks.
    function Zoo.SweepGetters(tableName, object)
        local methods = rawget(moho, tableName)
        if not methods or not object then
            Log('sweep ' .. tableName .. ': nothing to sweep')
            return
        end
        local names = SortedFunctionNames(methods)
        if TableGetn(names) == 0 then
            local keys = 0
            local sample = ''
            for k, v in methods do
                keys = keys + 1
                if keys <= 4 then sample = sample .. ' ' .. tostring(k) .. '=' .. type(v) end
            end
            local mt = getmetatable(methods)
            Log('sweep ' .. tableName .. ': ' .. type(methods) .. ', ' .. keys .. ' keys:' .. sample .. ', metatable '
                .. tostring(mt) .. ', object ' .. type(object))
        end
        local called = 0
        local failed = 0
        for i = 1, TableGetn(names) do
            local name = names[i]
            if IsGetter(name) and not SkipGetters[tableName .. '.' .. name] then
                local fn = methods[name]
                if Zoo.trace then Log('call ' .. tableName .. '.' .. name) end
                if not pcall(fn, object) then failed = failed + 1 end
                if not pcall(fn, object, 1) then failed = failed + 1 end
                called = called + 2
            end
        end
        Log('sweep ' .. tableName .. ': ' .. called .. ' calls, ' .. failed .. ' errors')
    end

    -- Every global getter the engine registers in the sim's Lua (a C function whose name says it reads), without an
    -- argument and with 1.
    function Zoo.SweepGlobals()
        local globals = getfenv(0)
        local names = {}
        for name, value in globals do
            if type(name) == 'string' and type(value) == 'cfunction' and IsGetter(name) and not SkipGetters['_G.' .. name] then
                TableInsert(names, name)
            end
        end
        table.sort(names)
        local failed = 0
        for i = 1, TableGetn(names) do
            if Zoo.trace then Log('call _G.' .. names[i]) end
            local fn = globals[names[i]]
            if not pcall(fn) then failed = failed + 1 end
            if not pcall(fn, 1) then failed = failed + 1 end
        end
        Log('sweep globals: ' .. TableGetn(names) .. ' getters, ' .. failed .. ' errors')
    end

    function Zoo.SweepUnit(unit)
        if not Alive(unit) then
            return
        end
        Zoo.SweepGetters('entity_methods', unit)
        Zoo.SweepGetters('unit_methods', unit)
        local weapon = Try('GetWeapon', unit.GetWeapon, unit, 1)
        if weapon then
            Zoo.SweepGetters('weapon_methods', weapon)
        end
        local navigator = Try('GetNavigator', unit.GetNavigator, unit)
        if navigator then
            Zoo.SweepGetters('navigator_methods', navigator)
        end
        local blip = Try('GetBlip', unit.GetBlip, unit, 2)
        if blip then
            Zoo.SweepGetters('blip_methods', blip)
        end
        if unit.MyShield then
            Zoo.SweepGetters('shield_methods', unit.MyShield)
        end
    end

    -- One unit of every kind, for the platoon scenario and the getter sweep.
    local SampleKinds = { 'uel0001', 'uel0105', 'ueb0101', 'ueb1103', 'ueb4202', 'uea0107', 'uel0201', 'ueb2305',
                          'ueb2108', 'uea0303', 'ues0201', 'url0402', 'xsl0401', 'ual0401' }

    function Zoo.SpawnSample(army, z)
        local sample = {}
        for i = 1, TableGetn(SampleKinds) do
            local unit = Zoo.Spawn(SampleKinds[i], army, Zoo.cx - 20 + i * 3, z, 0)
            if unit then
                TableInsert(sample, unit)
            end
        end
        return sample
    end

    function Zoo.DestroyAll(units)
        for i = 1, TableGetn(units) do
            if Alive(units[i]) then
                Try('destroy', units[i].Destroy, units[i])
            end
        end
    end

    -- Every getter of the sim's Lua objects: a unit of every kind (its entity, unit, weapon, navigator, blip and
    -- shield methods), an army brain and a platoon. Last in the zoo: the original game stops for good on some of these
    -- calls (GetProjectileBlueprint and IsCommandsActive above crash it, GetAttacker and a shield's GetBlueprint
    -- never return), so the checksums compared with it end where it stops, after the waves and the scenarios.
    function Zoo.Sweeps()
        local brainA = GetArmyBrain(Zoo.a)
        local sample = Zoo.SpawnSample(Zoo.a, Zoo.cz - 40)
        WaitTicks(10)
        for i = 1, TableGetn(sample) do
            Zoo.SweepUnit(sample[i])
        end
        Zoo.SweepGetters('aibrain_methods', brainA)
        local platoon = Try('MakePlatoon', brainA.MakePlatoon, brainA, 'ZooSweep', '')
        if platoon then
            Try('AssignUnitsToPlatoon', brainA.AssignUnitsToPlatoon, brainA, platoon, sample, 'Attack', 'GrowthFormation')
            Zoo.SweepGetters('platoon_methods', platoon)
            Try('DisbandPlatoon', brainA.DisbandPlatoon, brainA, platoon)
        end
        Zoo.DestroyAll(sample)
        Zoo.SweepGlobals()
        Log('sweeps done')
    end

    -- Methods the fuzz leaves out: they end the object, or wait (a yield inside pcall only errors).
    local FuzzSkip = {
        Destroy = true, Kill = true, KillSelf = true, DestroyIntel = true, PlayCommanderWarpInEffect = true,
    }
    -- Calls that crash the original game the same way, left out of the fuzz:
    -- unit:CanPathTo on a unit with no navigator (a structure): 0x006CB960 calls through [unit+0x54C] unchecked;
    -- a number where a table goes: lua_getn (0x0090AD30) reads any value as a table, and these count such an argument
    -- with no type check first: platoon:FormPlatoon (0x0072D8F0), brain:FindUpgradeBP (0x00588C90),
    -- brain:BuildStructure (0x0058B690).
    local FuzzCrashes = {
        ['unit_methods.CanPathTo'] = true,
        ['platoon_methods.FormPlatoon'] = true,
        ['aibrain_methods.FindUpgradeBP'] = true,
        ['aibrain_methods.BuildStructure'] = true,
    }

    -- Every method of moho[tableName] on `object` with each argument pattern: nothing, an enemy unit, a position, a
    -- unit blueprint id, 1, true, two numbers, a position and a number, a unit and a number. The wrong patterns stop
    -- at the engine's argument checks; the right ones run the method. Errors are expected and counted.
    function Zoo.Fuzz(tableName, object, ctx, label)
        local key = label or tableName
        local methods = rawget(moho, tableName)
        if not methods or not object then
            return
        end
        local patterns = {
            {},
            { ctx.enemy },
            { ctx.pos },
            { 'uel0201' },
            { 1 },
            { true },
            { 1, 1 },
            { ctx.pos, 1 },
            { ctx.enemy, 1 },
        }
        local names = SortedFunctionNames(methods)
        local calls = 0
        local failed = 0
        for i = 1, TableGetn(names) do
            local name = names[i]
            if not FuzzSkip[name] and not SkipGetters[key .. '.' .. name] and not FuzzCrashes[key .. '.' .. name] then
                local fn = methods[name]
                for p = 1, TableGetn(patterns) do
                    if Zoo.trace then Log('fuzz ' .. key .. '.' .. name .. ' #' .. p) end
                    local args = patterns[p]
                    local ok
                    if TableGetn(args) == 0 then
                        ok = pcall(fn, object)
                    elseif TableGetn(args) == 1 then
                        ok = pcall(fn, object, args[1])
                    else
                        ok = pcall(fn, object, args[1], args[2])
                    end
                    calls = calls + 1
                    if not ok then failed = failed + 1 end
                end
            end
        end
        Log('fuzz ' .. key .. ': ' .. calls .. ' calls, ' .. failed .. ' errors')
    end

    -- The same calls on any object, through its metatable's methods (the engine's classes whose method table has no
    -- moho.<name>_methods entry: manipulators, effects, economy events, decals, projectiles, props).
    function Zoo.FuzzObject(label, object, ctx)
        if not object then
            Log('fuzz ' .. label .. ': no object')
            return
        end
        local methods = getmetatable(object)
        if type(methods) == 'table' and type(rawget(methods, '__index')) == 'table' then
            methods = rawget(methods, '__index')
        end
        if type(methods) ~= 'table' then
            Log('fuzz ' .. label .. ': no methods')
            return
        end
        local saved = moho['zoo_fuzz']
        moho['zoo_fuzz'] = methods
        Zoo.Fuzz('zoo_fuzz', object, ctx, label)
        moho['zoo_fuzz'] = saved
    end

    -- Projectiles, props, a shield, every kind of manipulator, effects, an economy event, a decal and a blip, each
    -- made here and given the same calls.
    function Zoo.FuzzMore(ctx)
        -- A global the engine may not register: FAF's Lua errors on reading a missing global, rawget doesn't.
        local function G(name)
            return rawget(getfenv(0), name) or function() error(name .. ' is not registered') end
        end
        local a = Zoo.a
        local x = Zoo.cx
        local z = Zoo.cz - 70
        local tank = Zoo.Spawn('uel0201', a, x, z, 0)
        local shieldGen = Zoo.Spawn('ueb4202', a, x + 10, z, 0)
        local engineer = Zoo.Spawn('uel0105', a, x - 10, z, 0)
        WaitTicks(5)
        if not Alive(tank) then
            Log('fuzz more: no tank')
            return
        end
        local weapon = Try('GetWeapon', tank.GetWeapon, tank, 1)
        local made = {
            { 'projectile', Try('CreateProjectile', tank.CreateProjectile, tank,
                '/projectiles/TDFGauss01/TDFGauss01_proj.bp', 0, 1, 0, 0, 0, 1) },
            { 'rotator', Try('CreateRotator', G('CreateRotator'), tank, 0, 'y') },
            { 'animator', Try('CreateAnimator', G('CreateAnimator'), tank) },
            { 'slider', Try('CreateSlider', G('CreateSlider'), tank, 0, 0, 1, 0, 1) },
            { 'aim', weapon and Try('CreateAimController', G('CreateAimController'), weapon, 'Zoo', 0, 0, 0) },
            { 'footplant', Try('CreateFootPlantController', G('CreateFootPlantController'), tank, 0, 0, 0, true, 1) },
            { 'collision', Try('CreateCollisionDetector', G('CreateCollisionDetector'), tank) },
            { 'storage', Try('CreateStorageManip', G('CreateStorageManip'), tank, 0, 'MASS', 0, 0, 0, 0, 1, 0) },
            { 'thrust', Try('CreateThrustController', G('CreateThrustController'), tank, 'Zoo', 0) },
            { 'builderarm', engineer and Try('CreateBuilderArmController', G('CreateBuilderArmController'), engineer, 0, 0, 0) },
            { 'slave', Try('CreateSlaveManipulator', G('CreateSlaveManipulator'), tank, 0, 0) },
            { 'emitter', Try('CreateEmitterAtEntity', G('CreateEmitterAtEntity'), tank, a,
                '/effects/emitters/destruction_explosion_fire_01_emit.bp') },
            { 'attached emitter', Try('CreateAttachedEmitter', G('CreateAttachedEmitter'), tank, 0, a,
                '/effects/emitters/destruction_explosion_fire_01_emit.bp') },
            { 'economy event', engineer and Try('CreateEconomyEvent', G('CreateEconomyEvent'), engineer, 10, 10, 1) },
            { 'decal', Try('CreateDecal', G('CreateDecal'), { x, 0, z }, 0, 'scorch_001_albedo', '', 'Albedo', 4, 4, 100, 10, a) },
            { 'blip', Try('GetBlip', tank.GetBlip, tank, 2) },
            { 'shield', shieldGen and shieldGen.MyShield },
        }
        local wrecks = Try('GetReclaimablesInRect', G('GetReclaimablesInRect'), Rect(Zoo.cx - 60, Zoo.cz - 60, Zoo.cx + 60, Zoo.cz + 60))
        if wrecks and wrecks[1] then
            TableInsert(made, { 'prop', wrecks[1] })
        end
        for i = 1, TableGetn(made) do
            Zoo.FuzzObject(made[i][1], made[i][2], ctx)
        end
        WaitTicks(10)
        Zoo.DestroyAll({ tank, shieldGen, engineer })
        Log('fuzz more done')
    end

    -- The fuzz on a unit of every kind, its weapon and navigator, an army brain and a platoon. Last of all: setters
    -- change the game in ways no checksum was checked for.
    function Zoo.FuzzAll()
        local brainA = GetArmyBrain(Zoo.a)
        local enemy = Zoo.Spawn('uel0201', Zoo.b, Zoo.cx + 10, Zoo.cz - 50, 0)
        local ctx = { enemy = enemy, pos = { Zoo.cx, GetSurfaceHeight(Zoo.cx, Zoo.cz), Zoo.cz } }
        local sample = Zoo.SpawnSample(Zoo.a, Zoo.cz - 60)
        WaitTicks(10)
        for i = 1, TableGetn(sample) do
            local unit = sample[i]
            if Alive(unit) then
                local weapon = Try('GetWeapon', unit.GetWeapon, unit, 1)
                local navigator = Try('GetNavigator', unit.GetNavigator, unit)
                Zoo.Fuzz('unit_methods', unit, ctx)
                if Alive(unit) then Zoo.Fuzz('entity_methods', unit, ctx) end
                if weapon and Alive(unit) then Zoo.Fuzz('weapon_methods', weapon, ctx) end
                if navigator and Alive(unit) then Zoo.Fuzz('navigator_methods', navigator, ctx) end
            end
            WaitTicks(1)
        end
        local platoon = Try('MakePlatoon', brainA.MakePlatoon, brainA, 'ZooFuzz', '')
        if platoon then
            Try('AssignUnitsToPlatoon', brainA.AssignUnitsToPlatoon, brainA, platoon, sample, 'Attack', 'GrowthFormation')
            Zoo.Fuzz('platoon_methods', platoon, ctx)
        end
        Zoo.Fuzz('aibrain_methods', brainA, ctx)
        WaitTicks(10)
        Zoo.DestroyAll(sample)
        Zoo.FuzzMore(ctx)
        Log('fuzz done')
    end

    -- The calls ordinary games make rarely: an AI platoon, building, factories, upgrades, transports, missiles,
    -- reclaim, repair, capture and squad orders. Units are UEF's unless a faction's own kind is the point.
    function Zoo.Scenarios()
        local x = Zoo.cx
        local z = Zoo.cz
        local a = Zoo.a
        local b = Zoo.b
        local brainA = GetArmyBrain(a)

        -- An AI platoon moves, attack-moves and stops.
        local sample = Zoo.SpawnSample(a, z - 40)
        WaitTicks(10)
        local platoon = Try('MakePlatoon', brainA.MakePlatoon, brainA, 'ZooPlatoon', '')
        if platoon then
            Try('AssignUnitsToPlatoon', brainA.AssignUnitsToPlatoon, brainA, platoon, sample, 'Attack', 'GrowthFormation')
            Try('platoon move', platoon.MoveToLocation, platoon, { x, 0, z + 20 }, false)
            WaitTicks(30)
            Try('platoon aggressive', platoon.AggressiveMoveToLocation, platoon, { x + 20, 0, z })
            WaitTicks(30)
            Try('platoon stop', platoon.Stop, platoon)
            Try('DisbandPlatoon', brainA.DisbandPlatoon, brainA, platoon)
        end
        Zoo.DestroyAll(sample)
        WaitTicks(10)

        -- Engineers build, a factory produces, an extractor upgrades.
        local engineer = Zoo.Spawn('uel0105', a, x - 10, z + 30, 0)
        local engineer2 = Zoo.Spawn('uel0105', a, x - 14, z + 30, 0)
        local factory = Zoo.Spawn('ueb0101', a, x + 10, z + 30, 0)
        local extractor = Zoo.Spawn('ueb1103', a, x + 24, z + 30, 0)
        if engineer then
            Try('IssueBuildMobile', IssueBuildMobile, { engineer }, { x - 10, 0, z + 40 }, 'ueb1101', {})
        end
        if engineer2 and engineer then
            Try('IssueGuard', IssueGuard, { engineer2 }, engineer)
        end
        if factory then
            Try('IssueBuildFactory', IssueBuildFactory, { factory }, 'uel0105', 2)
            Try('IssueFactoryRallyPoint', IssueFactoryRallyPoint, { factory }, { x + 10, 0, z + 45 })
        end
        if extractor then
            Try('IssueUpgrade', IssueUpgrade, { extractor }, 'ueb1202')
        end
        WaitTicks(150)

        -- A transport carries two tanks and drops them.
        local transport = Zoo.Spawn('uea0107', a, x - 30, z + 10, 0)
        local tanks = {}
        for i = 1, 2 do
            local tank = Zoo.Spawn('uel0201', a, x - 30 + i * 3, z + 14, 0)
            if tank then TableInsert(tanks, tank) end
        end
        if transport and TableGetn(tanks) > 0 then
            Try('IssueTransportLoad', IssueTransportLoad, tanks, transport)
            WaitTicks(100)
            Try('IssueTransportUnload', IssueTransportUnload, { transport }, { x - 50, 0, z + 10 })
            WaitTicks(100)
        end

        -- Missiles: a strategic launcher against an anti-nuke, a tactical launcher against tactical defence.
        local launcher = Zoo.Spawn('ueb2305', a, x - 40, z - 20, 0)
        local antiNuke = Zoo.Spawn('ueb4302', b, x + 40, z - 20, 0)
        local tactical = Zoo.Spawn('ueb2108', a, x - 40, z - 30, 0)
        local target = Zoo.Spawn('ueb1101', b, x + 40, z - 30, 0)
        if antiNuke then Try('GiveNukeSiloAmmo', antiNuke.GiveNukeSiloAmmo, antiNuke, 1) end
        if launcher then
            Try('GiveNukeSiloAmmo', launcher.GiveNukeSiloAmmo, launcher, 2)
            Try('IssueNuke', IssueNuke, { launcher }, { x + 40, 0, z - 20 })
        end
        if tactical then
            Try('GiveTacticalSiloAmmo', tactical.GiveTacticalSiloAmmo, tactical, 2)
            if target then
                Try('IssueTactical', IssueTactical, { tactical }, target)
            end
        end
        WaitTicks(300)

        -- Reclaim the wrecks, repair a damaged unit, capture an enemy one.
        local reclaimer = Zoo.Spawn('uel0105', a, x, z, 0)
        local wrecks = Try('GetReclaimablesInRect', GetReclaimablesInRect, Rect(x - 40, z - 40, x + 40, z + 40))
        if reclaimer and wrecks then
            local count = 0
            for i = 1, TableGetn(wrecks) do
                if count < 5 and wrecks[i] then
                    Try('IssueReclaim', IssueReclaim, { reclaimer }, wrecks[i])
                    count = count + 1
                end
            end
        end
        local damaged = Zoo.Spawn('ueb1101', a, x + 5, z + 5, 0)
        if damaged then
            Try('SetHealth', damaged.SetHealth, damaged, damaged, 100)
        end
        local repairer = Zoo.Spawn('uel0105', a, x + 8, z + 8, 0)
        if repairer and damaged then
            Try('IssueRepair', IssueRepair, { repairer }, damaged)
        end
        local captured = Zoo.Spawn('ueb1101', b, x + 20, z + 5, 0)
        local capturer = Zoo.Spawn('uel0105', a, x + 22, z + 8, 0)
        if capturer and captured then
            Try('IssueCapture', IssueCapture, { capturer }, captured)
        end
        WaitTicks(200)

        -- Movement orders on a squad: formation move, patrol, stop.
        local squad = {}
        for i = 1, 6 do
            local unit = Zoo.Spawn('uel0201', a, x - 6 + i * 2, z - 10, 0)
            if unit then TableInsert(squad, unit) end
        end
        if TableGetn(squad) > 0 then
            Try('IssueFormMove', IssueFormMove, squad, { x, 0, z + 30 }, 'AttackFormation', 0)
            WaitTicks(50)
            Try('IssuePatrol', IssuePatrol, squad, { x + 30, 0, z })
            Try('IssuePatrol', IssuePatrol, squad, { x - 30, 0, z })
            WaitTicks(50)
            Try('IssueStop', IssueStop, squad)
            Try('IssueClearCommands', IssueClearCommands, squad)
        end
        Log('scenarios done')
    end

    function Zoo.Run()
        WaitTicks(50)
        Zoo.Setup()
        if not Zoo.a or not Zoo.b then
            Log('needs two armies')
            return
        end
        local total = 0
        local groupSize = 24
        for first = 1, TableGetn(Zoo.ids), groupSize do
            total = total + Zoo.Wave(first, groupSize)
        end
        Log('waves done, ' .. total .. ' units spawned')
        Zoo.Scenarios()
        Zoo.Sweeps()
        Zoo.FuzzAll()
    end

    local ZooBeginSession = BeginSession
    BeginSession = function()
        ZooBeginSession()
        ForkThread(Zoo.Run)
    end
end
