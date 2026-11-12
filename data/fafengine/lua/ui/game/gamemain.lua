-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered
-- as a hook directory): appended to /lua/ui/game/gamemain.lua.
--
-- A replay gets the timeline bar. The engine's own modules lie under /fafengine/modules, a
-- path no FAF file has, so they are never taken as hooks of FAF's files. FAF's Lua may
-- carry the timeline itself (issue #327, /lua/ui/game/replay_timeline.lua); its own
-- CreateUI then makes the bar, so this doesn't.

local diskGetFileInfo = rawget(_G, 'DiskGetFileInfo')
if diskGetFileInfo and not diskGetFileInfo('/lua/ui/game/replay_timeline.lua') then
    local OldCreateUI = CreateUI
    function CreateUI(isReplay)
        OldCreateUI(isReplay)
        if isReplay then
            import('/fafengine/modules/lua/ui/game/replay_timeline.lua').Create()
        end
    end
end

-- ============================================================================
-- Transport Cargo Holograms Hook
-- ============================================================================

local Holograms = nil
local function GetHolograms()
    if not Holograms then
        local ok, mod = pcall(import, '/fafengine/modules/lua/ui/game/transport_holograms.lua')
        if ok and type(mod) == 'table' then
            Holograms = mod
        end
    end
    return Holograms
end

local function OnHologramBeat()
    local holo = GetHolograms()
    if holo then
        local updateFn = rawget(holo, 'Update')
        if updateFn then
            pcall(updateFn)
        end
    end
end

local oldCreateUI = CreateUI
function CreateUI(isReplay)
    if oldCreateUI then oldCreateUI(isReplay) end
    if AddBeatFunction then
        AddBeatFunction(OnHologramBeat)
    elseif rawget(_G, 'AddBeatFunction') then
        rawget(_G, 'AddBeatFunction')(OnHologramBeat)
    end
end

local oldOnSelectionChanged = OnSelectionChanged
function OnSelectionChanged(oldSelection, newSelection, added, removed)
    if oldOnSelectionChanged then
        oldOnSelectionChanged(oldSelection, newSelection, added, removed)
    end
    if newSelection and table.getn(newSelection) > 0 then
        local holo = GetHolograms()
        local regFn = holo and rawget(holo, 'RegisterTransport')
        if regFn then
            for _, u in ipairs(newSelection) do
                if u and u.IsInCategory and u:IsInCategory('TRANSPORTATION') then
                    pcall(regFn, u)
                end
            end
        end
    end
end
