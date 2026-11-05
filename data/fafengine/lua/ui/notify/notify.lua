-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/notify/notify.lua.

--- The replay viewer's new sim: the units these threads watch are gone, and each looked its unit up once.
function KillAllWatchers()
    for _, data in ACUs do
        killWatcher(data)
    end
end
