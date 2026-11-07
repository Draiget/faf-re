-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/notify/notify.lua.

--- The replay viewer's new sim: the units these threads watch are gone, and each looked its unit up once.
--- FAF's notify.lua may define it already (issue #327). rawget on the module: FAF's Lua errors on reading a global
--- that doesn't exist.
if not rawget(getfenv(1), 'KillAllWatchers') then
    function KillAllWatchers()
        for _, data in ACUs do
            killWatcher(data)
        end
    end
end
