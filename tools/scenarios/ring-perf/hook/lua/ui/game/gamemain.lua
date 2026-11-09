-- UI half of the range-ring render cost test (tools/scenarios/1p-ringperf-main.yaml). Run with
-- FAF_GPU_PROFILE=<frames> in the environment, so the log carries each render pass's CPU and GPU
-- time. Turns the Build Range overlay on, points the camera at the 2000 engineers and holds six
-- phases, each logged as "RINGPERF phase <name>": no, half and all of them selected (with the
-- selected-unit rings on), each with range_StencilFlush 1 and 0.
local RingPerfOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    RingPerfOnFirstUpdate()

    ForkThread(function()
        local engineers = {}
        for _ = 1, 120 do
            WaitSeconds(1)
            UISelectionByCategory('ENGINEER', false, false, false, false)
            engineers = {}
            for _, unit in GetSelectedUnits() or {} do
                if unit:GetUnitId() == 'uel0105' then
                    table.insert(engineers, unit)
                end
            end
            if table.getn(engineers) >= 2000 then
                break
            end
        end
        SelectUnits(nil)
        local count = table.getn(engineers)
        LOG('RINGPERF engineers ' .. count)
        if count < 2000 then
            LOG('RINGPERF DONE (engineers missing)')
            return
        end

        local ids, half = {}, {}
        for i, unit in engineers do
            table.insert(ids, unit:GetEntityId())
            if i <= count / 2 then
                table.insert(half, unit)
            end
        end

        local params = import('/lua/ui/game/rangeoverlayparams.lua').RangeOverlayParams.Miscellaneous
        SetOverlayFilter('Miscellaneous', params.Categories, params.NormalColor, params.SelectColor,
            params.RolloverColor, params.Inner[1], params.Inner[2], params.Outer[1], params.Outer[2])
        SetOverlayFilters({'Miscellaneous'})
        ConExecute('range_Fill 0')
        ConExecute('range_RenderSelected 1')

        GetCamera('WorldCamera'):TrackEntities(ids, 90, 0)
        WaitSeconds(6)

        local phases = {
            { 'none-flush1', nil, 1 }, { 'none-flush0', nil, 0 },
            { 'half-flush1', half, 1 }, { 'half-flush0', half, 0 },
            { 'all-flush1', engineers, 1 }, { 'all-flush0', engineers, 0 },
        }
        for _, phase in phases do
            SelectUnits(phase[2])
            ConExecute('range_StencilFlush ' .. phase[3])
            LOG('RINGPERF phase ' .. phase[1])
            WaitSeconds(12)
        end
        SelectUnits(nil)
        ConExecute('range_StencilFlush 1')
        LOG('RINGPERF DONE')
    end)
end
