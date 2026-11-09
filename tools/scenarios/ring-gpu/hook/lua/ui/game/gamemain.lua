-- UI half of the range-ring A/B test (tools/scenarios/1p-ringgpu-*.yaml). Run with
-- FAF_GPU_PROFILE=<frames> in the environment, so the log carries each render pass's CPU and GPU
-- time, and ring-gpu\capture.ps1 alongside for the screenshots.
--
-- Pauses the game once both packs are up, then for every scene (camera, overlay, selection) runs
-- every switch setting: ren_GpuRanges 0/1 x range_ViewCull 0/1. For each it logs
-- "RINGGPU SHOT <scene>-<setting>" (capture.ps1 saves the window there) and then holds
-- "RINGGPU perf <scene>-<setting>" for six seconds of "pass Ranges" lines. On an exe without
-- those switches the console just rejects them, so every setting draws the same way.
local RingGpuOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    RingGpuOnFirstUpdate()

    ForkThread(function()
        -- Set by hook-reference; rawget, since reading a global nobody set is an error.
        local referenceOnly = rawget(getfenv(1), 'RingGpuReferenceOnly') == true
        local engineers, artillery = {}, {}
        for _ = 1, 120 do
            WaitSeconds(1)
            UISelectionByCategory('ALLUNITS', false, false, false, false)
            engineers, artillery = {}, {}
            for _, unit in GetSelectedUnits() or {} do
                local id = unit:GetUnitId()
                if id == 'uel0105' then
                    table.insert(engineers, unit)
                elseif id == 'uel0103' or id == 'uel0111' then
                    table.insert(artillery, unit)
                end
            end
            if table.getn(engineers) >= 2000 and table.getn(artillery) >= 500 then
                break
            end
        end
        SelectUnits(nil)
        LOG(string.format('RINGGPU engineers %d, artillery %d', table.getn(engineers), table.getn(artillery)))
        if table.getn(engineers) < 2000 or table.getn(artillery) < 500 then
            LOG('RINGGPU DONE (units missing)')
            return
        end
        -- The UI stays up: hiding it races the pause and changes the world view's size, so
        -- screenshots from different runs would not line up. analyze.ps1 masks what animates.
        SessionRequestPause()

        local function Ids(units)
            local ids = {}
            for _, unit in units do
                table.insert(ids, unit:GetEntityId())
            end
            return ids
        end
        local function Bounds(units)
            local minX, maxX, minZ, maxZ, y = nil, nil, nil, nil, 0
            for _, unit in units do
                local p = unit:GetPosition()
                minX, maxX = math.min(minX or p[1], p[1]), math.max(maxX or p[1], p[1])
                minZ, maxZ = math.min(minZ or p[3], p[3]), math.max(maxZ or p[3], p[3])
                y = y + p[2]
            end
            return minX, maxX, minZ, maxZ, y / table.getn(units)
        end
        local function Overlay(name)
            local params = import('/lua/ui/game/rangeoverlayparams.lua').RangeOverlayParams[name]
            SetOverlayFilter(name, params.Categories, params.NormalColor, params.SelectColor,
                params.RolloverColor, params.Inner[1], params.Inner[2], params.Outer[1], params.Outer[2])
            SetOverlayFilters({ name })
        end

        local camera = GetCamera('WorldCamera')
        local minX, maxX, minZ, maxZ, y = Bounds(artillery)
        local cx, cz = (minX + maxX) / 2, (minZ + maxZ) / 2
        ConExecute('range_RenderSelected 1')

        local scenes = {
            { name = 'eng-wide', overlay = 'Miscellaneous', units = engineers, fill = 0,
              aim = function() camera:TrackEntities(Ids(engineers), 90, 0) end },
            { name = 'art-wide', overlay = 'IndirectFire', units = artillery, fill = 0,
              aim = function() camera:TrackEntities(Ids(artillery), 260, 0) end },
            { name = 'art-close', overlay = 'IndirectFire', units = artillery, fill = 0,
              aim = function()
                  local s = camera:SaveSettings()
                  camera:SnapTo(Vector(cx, y, cz), { s.Heading, s.Pitch, 0 }, 25)
              end },
            { name = 'art-close-fill', overlay = 'IndirectFire', units = artillery, fill = 1,
              aim = function()
                  local s = camera:SaveSettings()
                  camera:SnapTo(Vector(cx, y, cz), { s.Heading, s.Pitch, 0 }, 25)
              end },
            -- Past the pack's edge, where the merged outline crosses the view.
            { name = 'art-edge', overlay = 'IndirectFire', units = artillery, fill = 0,
              aim = function()
                  local s = camera:SaveSettings()
                  camera:SnapTo(Vector(maxX + 40, y, cz), { s.Heading, s.Pitch, 0 }, 45)
              end },
        }
        local settings = { { 'legacy', 0, 0 }, { 'gpu', 1, 0 }, { 'cull', 0, 1 }, { 'gpucull', 1, 1 } }
        local rounds = 3
        -- Reference runs (init_ringgpu_reference.lua mounts hook-reference, which sets the flag): one
        -- screenshot per scene and no timing, for an exe without the switches (retail).
        if referenceOnly then
            settings = { { 'legacy', 0, 0 } }
            rounds = 1
        end

        for _, scene in scenes do
            Overlay(scene.overlay)
            ConExecute('range_Fill ' .. scene.fill)
            SelectUnits(scene.units)
            scene.aim()
            WaitSeconds(4)
            -- Three rounds through the settings, so load from anything else on the machine
            -- lands on every setting alike; screenshots in the first round only.
            for round = 1, rounds do
                for _, setting in settings do
                    if not referenceOnly then
                        ConExecute('ren_GpuRanges ' .. setting[2])
                        ConExecute('range_ViewCull ' .. setting[3])
                    end
                    local tag = scene.name .. '-' .. setting[1]
                    WaitSeconds(1.5)
                    if round == 1 then
                        LOG('RINGGPU SHOT ' .. tag)
                        WaitSeconds(1)
                    end
                    if not referenceOnly then
                        LOG('RINGGPU perf ' .. tag)
                        WaitSeconds(4)
                    end
                end
            end
        end
        LOG('RINGGPU perf end')
        SelectUnits(nil)
        ConExecute('range_Fill 0')
        if not referenceOnly then
            ConExecute('ren_GpuRanges -1')
            ConExecute('range_ViewCull 1')
        end
        LOG('RINGGPU DONE')
    end)
end
