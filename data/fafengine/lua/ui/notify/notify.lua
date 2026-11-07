-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/notify/notify.lua, in the same chunk, so it sees that file's locals (ACUs, NotifyOverlay).

--- The replay viewer's new sim: the units these threads watch are gone, and each looked its unit up once. With the
--- new sim's first beat the engine sends the 'started' message again for each ACU upgrading in it
--- (SIM_AddRestoredUiData), which starts its watcher anew.
--- FAF's notify.lua may define both already (issue #327, FAForever/fa#7373). rawget on the module: FAF's Lua errors on
--- reading a global that doesn't exist.
if not rawget(getfenv(1), 'KillAllWatchers') then
    function KillAllWatchers()
        for _, data in ACUs do
            killWatcher(data)
        end
    end

    --- As FAF's, but it stops when its unit is gone: a replay move can remove the units while it loads, before
    --- KillAllWatchers runs.
    function watchEnhancement(id, text, category, source)
        local overlayData = {}
        overlayData.unit = GetUnitById(id)
        overlayData.pos = overlayData.unit:GetPosition()
        overlayData.msg = {to = 'allies', NotifyOverlay = true, data = {id = id, text = text, category = category, source = source}}
        overlayData.eta = -1

        while true do
            if IsDestroyed(overlayData.unit) then
                local data = ACUs[id]
                if data and data.watcher == CurrentThread() then
                    data.watcher = false
                    NotifyOverlay.sendDestroyOverlayMessage(id)
                end
                return
            end
            NotifyOverlay.generateEnhancementMessage(overlayData)
            WaitSeconds(0.1)
        end
    end
end
