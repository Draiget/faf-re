-- UI half of the ship-wake comparison (tools/scenarios/1p-shipwake-*.yaml). Follows the ships
-- with the world camera and logs "WAKETEST SHOT <name>" when a screenshot should be taken:
-- first with the engine's own particle settings, then with efx_ParticleWaterSurface and
-- efx_WaterOffset at 0 (the values the recovered engine had before it was fixed).
local WakeTestOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    WakeTestOnFirstUpdate()

    ForkThread(function()
        local ships = {}
        for _ = 1, 60 do
            WaitSeconds(1)
            UISelectionByCategory('NAVAL', false, false, false, false)
            ships = GetSelectedUnits() or {}
            if table.getn(ships) >= 3 then
                break
            end
        end
        SelectUnits(nil)
        if table.getn(ships) == 0 then
            LOG('WAKETEST no ships')
            return
        end

        local ids = {}
        for _, unit in ships do
            table.insert(ids, unit:GetEntityId())
        end
        local camera = GetCamera('WorldCamera')
        camera:TrackEntities(ids, 55, 0)

        WaitSeconds(20)
        LOG('WAKETEST SHOT default')
        WaitSeconds(3)

        ConExecute('efx_ParticleWaterSurface 0')
        ConExecute('efx_WaterOffset 0')
        WaitSeconds(15)
        LOG('WAKETEST SHOT zeroed')
        WaitSeconds(3)
        LOG('WAKETEST DONE')
    end)
end
