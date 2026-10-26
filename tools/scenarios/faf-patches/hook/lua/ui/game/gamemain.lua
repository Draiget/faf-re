-- UI half of the FA-Binary-Patches port tests (tools/scenarios/1p-faf-patches.yaml; the map
-- faf_re_patchtest has the sim half). Every check logs "PATCHTEST PASS|FAIL ui <name> <detail>",
-- and the end "PATCHTEST RESULT ui failures=<n>"; a script error leaves the result line out.
local PatchTestOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    PatchTestOnFirstUpdate()

    local failures = 0
    local function Check(name, ok, detail)
        if not ok then
            failures = failures + 1
        end
        LOG(string.format('PATCHTEST %s ui %s %s', ok and 'PASS' or 'FAIL', name, tostring(detail or '')))
    end

    ForkThread(function()
        WaitSeconds(2)
        if GetFocusArmy() < 1 then
            SetFocusArmy(1)
        end

        -- ObserverFix, part 1: a player in the game cannot switch to observer (stock rule too).
        SetFocusArmy(-1)
        WaitSeconds(0.5)
        Check('cannot observe while in the game', GetFocusArmy() == 1, GetFocusArmy())

        -- BuildUnit/SelectUnit (issue #13): of the structures the sim starts, the CQUEMOV point
        -- defense and the FACTORY can be selected while being built, the power generator cannot.
        local selectable = {}
        for second = 1, 20 do
            UISelectionByCategory('STRUCTURE', false, false, false, false)
            selectable = {}
            for _, unit in GetSelectedUnits() or {} do
                if unit:GetHealth() < unit:GetMaxHealth() then
                    selectable[unit:GetBlueprint().BlueprintId] = true
                end
            end
            if selectable.ueb2101 and selectable.ueb0101 then
                break
            end
            WaitSeconds(1)
        end
        Check('CQUEMOV structure selectable while built', selectable.ueb2101 == true)
        Check('FACTORY selectable while built', selectable.ueb0101 == true)
        Check('other structure not selectable while built', selectable.ueb1101 == nil)
        SelectUnits({})

        -- ForkThreadFix (both Lua states).
        local refused, message = pcall(ForkThread, LOG)
        Check('ForkThread(cfunction) refused', not refused and string.find(tostring(message), "isn't a function", 1, true) ~= nil, message)
        local forked, forkError = pcall(ForkThread, function() end)
        Check('ForkThread(lua function) accepted', forked, forkError)

        -- GetTimeForProfile is registered in the UI state too.
        -- (`rawget`: the UI state errors on reading an undefined global; `type` of a C function is "cfunction".)
        local profile = rawget(_G, 'GetTimeForProfile')
        Check('GetTimeForProfile in UI', profile ~= nil and type(profile(0)) == 'number', type(profile))

        -- LuaMessages: a binding's type error reads "<type> expected but got <type>"
        -- (EjectSessionClient: FAF's Lua does not wrap it, and the type check comes first).
        local typeOk, typeError = pcall(EjectSessionClient, 'x')
        Check('type error text', not typeOk and string.find(tostring(typeError), 'integer expected but got string', 1, true) ~= nil, typeError)

        -- WorldView:SetCustomRender: any value, no return values, world views only.
        local view = import('/lua/ui/game/worldview.lua').viewLeft
        local results = nil
        local customOk, customError = pcall(function() results = { view:SetCustomRender(1) } end)
        Check('SetCustomRender(1) accepted', customOk, customError)
        Check('SetCustomRender returns nothing', results ~= nil and table.getn(results) == 0, results and table.getn(results))
        view:SetCustomRender(true)
        Check('no GetCustomRender', view.GetCustomRender == nil)
        local Group = import('/lua/maui/group.lua').Group
        local group = Group(GetFrame(0))
        Check('SetCustomRender only on world views', group.SetCustomRender == nil)
        group:Destroy()

        -- Bitmap:SetColorMask.
        local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
        local bitmap = Bitmap(GetFrame(0))
        bitmap:SetAlpha(0.5)
        Check('SetColorMask exists', rawget(getmetatable(bitmap) or {}, 'SetColorMask') ~= nil or bitmap.SetColorMask ~= nil)
        if bitmap.SetColorMask then
            local maskOk, maskError = pcall(bitmap.SetColorMask, bitmap, 'ff0000')
            Check('SetColorMask accepts a colour', maskOk, maskError)
            local badOk, badError = pcall(bitmap.SetColorMask, bitmap, 'nocolour')
            Check('SetColorMask unknown colour', not badOk and string.find(tostring(badError), 'Unknown color: nocolour', 1, true) ~= nil, badError)
            Check('SetColorMask keeps alpha', math.abs(bitmap:GetAlpha() - 0.5) < 0.01, bitmap:GetAlpha())
        end
        bitmap:Destroy()

        -- FixGetInterpolatedAlignedBox: xMax, yMax and zMax are three keys.
        local WorldMesh = import('/lua/ui/controls/worldmesh.lua').WorldMesh
        local mesh = WorldMesh()
        mesh:SetMesh({ MeshName = '/env/Common/Props/sphere_lod0.scm', TextureName = '/meshes/game/Assist_albedo.dds', ShaderName = 'FakeRings', UniformScale = 1 })
        mesh:SetStance(Vector(100, 20, 300))
        WaitSeconds(0.5)
        local boxOk, box = pcall(mesh.GetInterpolatedAlignedBox, mesh, 0)
        if not boxOk then
            Check('aligned box call', false, box)
            box = nil
        end
        local boxText = box and string.format('x %s..%s y %s..%s z %s..%s', tostring(box.xMin), tostring(box.xMax), tostring(box.yMin), tostring(box.yMax), tostring(box.zMin), tostring(box.zMax))
        Check('aligned box has yMax and zMax', box ~= nil and box.yMax ~= nil and box.zMax ~= nil and box.xMax ~= nil and box.yMax > box.yMin and box.zMax > box.zMin, boxText)
        mesh:Destroy()

        -- SetAlpha(a, false) does not recurse; SetAlpha(a, true) does.
        local parent = Group(GetFrame(0))
        local child = Bitmap(parent)
        parent:SetAlpha(0.3, false)
        Check('SetAlpha(a, false) not recursive', math.abs(parent:GetAlpha() - 0.3) < 0.01 and math.abs(child:GetAlpha() - 1) < 0.01, child:GetAlpha())
        parent:SetAlpha(0.6, true)
        Check('SetAlpha(a, true) recursive', math.abs(child:GetAlpha() - 0.6) < 0.01, child:GetAlpha())
        parent:Destroy()

        -- TeamColorMode accepts a palette string as well as a bool.
        local paletteOk, paletteError = pcall(TeamColorMode, 'ffff0000,ff00ff00,ff0000ff')
        Check('TeamColorMode(palette string)', paletteOk, paletteError)
        local boolOk, boolError = pcall(TeamColorMode, false)
        Check('TeamColorMode(bool)', boolOk, boolError)

        -- GetDepositsAroundPoint is registered in the UI state too.
        local deposits = rawget(_G, 'GetDepositsAroundPoint')
        local depositList = deposits and deposits(250, 250, 4000, 0)
        Check('GetDepositsAroundPoint in UI', depositList ~= nil and table.getn(depositList) > 0 and depositList[1].X1 ~= nil, depositList and table.getn(depositList))

        -- VDist3 in the UI state.
        local distOk, dist = pcall(VDist3, {3, 4, 0}, nil)
        Check('VDist3(vector, nil) in UI', distOk and math.abs(dist - 5) < 1e-4, dist)

        -- WorldView:ProjectMultiple keeps the keys and returns {x, y}.
        local projectOk, projected = pcall(view.ProjectMultiple, view, { a = { 100, 20, 300 }, [2] = { 50, 20, 50 } })
        Check('ProjectMultiple', projectOk and type(projected) == 'table' and projected.a ~= nil and projected[2] ~= nil and type(projected.a[1]) == 'number' and type(projected.a[2]) == 'number',
            projectOk and projected and projected.a and string.format('%s %s', tostring(projected.a[1]), tostring(projected.a[2])) or projected)

        -- UserUnit:GetFractionComplete / GetInterpolatedPosition, and SelectUnits returns nothing.
        local commander = nil
        local seen = ''
        for attempt = 1, 20 do
            UISelectionByCategory('ALLUNITS', false, false, false, false)
            seen = ''
            for _, unit in GetSelectedUnits() or {} do
                seen = seen .. ' ' .. unit:GetBlueprint().BlueprintId
                if unit:IsInCategory('COMMAND') then
                    commander = unit
                end
            end
            if commander then
                break
            end
            WaitSeconds(0.5)
        end
        Check('have a commander to test', commander ~= nil, 'selected:' .. seen)
        if commander then
            local fracOk, fraction = pcall(function() return commander:GetFractionComplete() end)
            Check('UserUnit:GetFractionComplete', fracOk and fraction == 1, fraction)
            local posOk, pos = pcall(function() return commander:GetInterpolatedPosition() end)
            Check('UserUnit:GetInterpolatedPosition', posOk and type(pos) == 'table' and type(pos[1]) == 'number' and type(pos[3]) == 'number',
                posOk and pos and string.format('%s %s %s', tostring(pos[1]), tostring(pos[2]), tostring(pos[3])) or pos)
        end
        local selectResults = { SelectUnits({}) }
        Check('SelectUnits returns nothing', table.getn(selectResults) == 0, table.getn(selectResults))

        -- weakgcmarkerFix in the UI state.
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
        Check('weak tables collected (UI)', (after - before) < (filled - before) / 4, string.format('before=%d filled=%d after=%d KB', before, filled, after))

        -- ObserverFix, part 2: the sim takes army 1 out of the game at about 25 s of game time; a
        -- player who commands an army still may not switch to observer (the stock binary let a
        -- defeated one).
        while GameTime() < 30 do
            WaitSeconds(0.5)
        end
        SetFocusArmy(-1)
        WaitSeconds(0.5)
        Check('cannot observe after being defeated', GetFocusArmy() == 1, GetFocusArmy())

        LOG('PATCHTEST RESULT ui failures=' .. failures)
    end)
end
