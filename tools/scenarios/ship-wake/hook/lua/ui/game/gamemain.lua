-- UI half of the ship-wake comparison (tools/scenarios/1p-shipwake-*.yaml). Follows the ships
-- with the world camera and logs "WAKETEST SHOT <name>" when a screenshot should be taken:
-- "default" with the engine's own particle settings, "wide" from further out, then "zeroed"
-- with efx_ParticleWaterSurface and efx_WaterOffset at 0 (the values the recovered engine had
-- before it was fixed). It first logs every console variable's value (convarnames.lua), so two
-- exes' logs can be diffed; the retail exe does not write console output to its log.
-- The retail exe has stopped logging after the first PrintWindow capture in every run so far,
-- so expect only "default" from it.
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

        -- Log every console variable's runtime value ("float X == v", "bool X is on", ...),
        -- so the logs of two exes can be diffed.
        local loaded, err = pcall(doscript, '/shipwake/lua/ui/game/convarnames.lua')
        if loaded and ConVarNames then
            LOG('WAKETEST CONVARS BEGIN')
            for _, entry in ConVarNames do
                ConExecute(entry[2] and (entry[1] .. ' show') or entry[1])
            end
            LOG('WAKETEST CONVARS END')
        else
            LOG('WAKETEST convar list not loaded: ' .. tostring(err))
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

        -- A wider view of the same water and the shore around it.
        camera:TrackEntities(ids, 160, 0)
        WaitSeconds(3)
        LOG('WAKETEST SHOT wide')
        WaitSeconds(3)
        camera:TrackEntities(ids, 55, 0)

        ConExecute('efx_ParticleWaterSurface 0')
        ConExecute('efx_WaterOffset 0')
        WaitSeconds(15)
        LOG('WAKETEST SHOT zeroed')
        WaitSeconds(3)
        LOG('WAKETEST DONE')
    end)
end
