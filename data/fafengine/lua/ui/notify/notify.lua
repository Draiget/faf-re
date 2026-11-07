-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/notify/notify.lua, in the same chunk, so it sees that file's locals (ACUs, messages).

--- The replay viewer's new sim: the units these threads watch are gone, and each looked its unit up once. The ACUs
--- that are upgrading at the new time are watched again.
--- FAF's notify.lua may define it already (issue #327, FAForever/fa#7373). rawget on the module: FAF's Lua errors on
--- reading a global that doesn't exist.
if not rawget(getfenv(1), 'KillAllWatchers') then
    local baseOnStartEnhancement = onStartEnhancement

    --- As FAF's, keeping when each enhancement started, so a move can start the watcher again from the one under
    --- way at the new time. A start seen again after a move replaces the one at the same tick.
    function onStartEnhancement(id, army, category, source)
        baseOnStartEnhancement(id, army, category, source)
        local data = id and ACUs[id]
        if data then
            local tick = GameTick()
            data.starts = data.starts or {}
            for index, start in data.starts do
                if start.tick == tick then
                    table.remove(data.starts, index)
                    break
                end
            end
            table.insert(data.starts, {tick = tick, category = category, source = source})
        end
    end

    local rewatchThread = false

    --- Gives each ACU its watcher back once the replaced sim's units are there, when it is working on an enhancement
    --- at the new time: work under way with no unit as its focus (building, repairing and reclaiming have one; the
    --- order queue is no help, as the new sim's orders reach the UI later), and an enhancement that started at or
    --- before that time. A 'started' message from the new sim starts one by itself.
    local function RewatchAfterSimReplaced(pending)
        -- A large keyframe can take a while to load; a minute at most.
        for _ = 1, 600 do
            WaitSeconds(0.1)
            local left = {}
            local tick = GameTick()
            for _, data in pending do
                local unit = GetUnitById(data.id)
                if data.watcher then
                    -- started by the new sim's own message
                elseif unit then
                    local latest = false
                    for _, start in data.starts do
                        if start.tick <= tick and (not latest or start.tick > latest.tick) then
                            latest = start
                        end
                    end
                    local text = latest and messages and messages()[latest.category][latest.source]
                    if text and unit:GetWorkProgress() > 0 and not unit:GetFocus() then
                        data.startTime = latest.tick / 10
                        data.watcher = ForkThread(watchEnhancement, data.id, text, latest.category, latest.source)
                    end
                else
                    table.insert(left, data)
                end
            end
            pending = left
            if table.empty(pending) then
                break
            end
        end
        rewatchThread = false
    end

    function KillAllWatchers()
        if rewatchThread then
            KillThread(rewatchThread)
            rewatchThread = false
        end
        local pending = {}
        for _, data in ACUs do
            killWatcher(data)
            if data.starts then
                table.insert(pending, data)
            end
        end
        if not table.empty(pending) then
            rewatchThread = ForkThread(RewatchAfterSimReplaced, pending)
        end
    end
end
