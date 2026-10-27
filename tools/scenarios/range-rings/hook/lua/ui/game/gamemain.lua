-- UI half of the range-ring stencil overflow test (tools/scenarios/1p-rangerings-main.yaml).
-- Turns the Build Range overlay on (as the overlay menu does), points the world camera at each
-- engineer cluster and logs "RINGTEST SHOT <name>" when a screenshot should be taken (capture.ps1
-- takes them): first with range_StencilFlush 1, then with 0 (the original batches). range_Fill is
-- turned on so holes in the merged fill show as well.
local RingTestOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    RingTestOnFirstUpdate()

    ForkThread(function()
        -- The spawned T1 engineers only: the ACU is an ENGINEER too, with a build ring of its own.
        local engineers = {}
        for _ = 1, 90 do
            WaitSeconds(1)
            UISelectionByCategory('ENGINEER', false, false, false, false)
            engineers = {}
            for _, unit in GetSelectedUnits() or {} do
                if unit:GetUnitId() == 'uel0105' then
                    table.insert(engineers, unit)
                end
            end
            if table.getn(engineers) >= 328 then
                break
            end
        end
        SelectUnits(nil)
        LOG('RINGTEST engineers ' .. table.getn(engineers))
        if table.getn(engineers) < 328 then
            LOG('RINGTEST DONE (clusters missing)')
            return
        end

        -- Cluster A is the one with the smaller x (the sim script orders them).
        local minX
        for _, unit in engineers do
            local x = unit:GetPosition()[1]
            if minX == nil or x < minX then
                minX = x
            end
        end
        local idsA, idsB = {}, {}
        for _, unit in engineers do
            if unit:GetPosition()[1] < minX + 20 then
                table.insert(idsA, unit:GetEntityId())
            else
                table.insert(idsB, unit:GetEntityId())
            end
        end
        LOG(string.format('RINGTEST cluster A %d, cluster B %d', table.getn(idsA), table.getn(idsB)))

        local params = import('/lua/ui/game/rangeoverlayparams.lua').RangeOverlayParams.Miscellaneous
        SetOverlayFilter('Miscellaneous', params.Categories, params.NormalColor, params.SelectColor,
            params.RolloverColor, params.Inner[1], params.Inner[2], params.Outer[1], params.Outer[2])
        SetOverlayFilters({'Miscellaneous'})

        local camera = GetCamera('WorldCamera')
        local function Shot(ids, zoom, name)
            camera:TrackEntities(ids, zoom, 0)
            WaitSeconds(4)
            LOG('RINGTEST SHOT ' .. name)
            WaitSeconds(3)
        end

        -- The fill pass too, so holes in the merged fill show, not only stray outlines.
        ConExecute('range_Fill 1')
        ConExecute('range_StencilFlush 1')
        Shot(idsA, 30, 'A128-flush1')
        Shot(idsB, 40, 'B200-flush1')
        ConExecute('range_StencilFlush 0')
        Shot(idsA, 30, 'A128-flush0')
        Shot(idsB, 40, 'B200-flush0')
        -- Back to the default, so the game shows the fixed rings until mpemu closes it.
        ConExecute('range_StencilFlush 1')

        -- Selection test on row C (200 interceptors) with the Anti-Air overlay: the middle
        -- third selected, with the selected-unit rings on, and the fill back off (the game's
        -- default).
        ConExecute('range_Fill 0')
        local antiAir = import('/lua/ui/game/rangeoverlayparams.lua').RangeOverlayParams.AntiAir
        SetOverlayFilter('AntiAir', antiAir.Categories, antiAir.NormalColor, antiAir.SelectColor,
            antiAir.RolloverColor, antiAir.Inner[1], antiAir.Inner[2], antiAir.Outer[1], antiAir.Outer[2])
        SetOverlayFilters({'AntiAir'})
        UISelectionByCategory('AIR', false, false, false, false)
        local row = {}
        for _, unit in GetSelectedUnits() or {} do
            if unit:GetUnitId() == 'uea0102' then
                table.insert(row, unit)
            end
        end
        SelectUnits(nil)
        table.sort(row, function(a, b) return a:GetPosition()[1] < b:GetPosition()[1] end)
        local count = table.getn(row)
        LOG('RINGTEST row C ' .. count)
        if count > 0 then
            local idsC, middle = {}, {}
            for i, unit in row do
                table.insert(idsC, unit:GetEntityId())
                if i > count / 3 and i <= 2 * count / 3 then
                    table.insert(middle, unit)
                end
            end
            -- Aim at the row's centre directly: tracking left it in a corner of the view.
            local cx, cy, cz = 0, 0, 0
            for _, unit in row do
                local p = unit:GetPosition()
                cx, cy, cz = cx + p[1], cy + p[2], cz + p[3]
            end
            local settings = camera:SaveSettings()
            local focus = Vector(cx / count, cy / count, cz / count)
            local function Frame(name)
                camera:SnapTo(focus, { settings.Heading, settings.Pitch, 0 }, 230)
                WaitSeconds(3)
                LOG('RINGTEST SHOT ' .. name)
                WaitSeconds(3)
            end

            ConExecute('range_RenderSelected 1')
            SelectUnits(middle)
            Frame('C-middle-selected')
            SelectUnits(nil)
            Frame('C-none-selected')
        end
        LOG('RINGTEST DONE (range_StencilFlush back to 1)')
    end)
end
