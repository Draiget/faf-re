local previousCreateUI = CreateUI
function CreateUI(isReplay)
    local result = previousCreateUI(isReplay)
    local settings = import('/mods/Microchip-Icon-Mod/modules/scales.lua')
    local ok, message = settings.Apply(settings.Load(), false)
    if not ok then WARN('Microchip Icon Mod: ' .. message) end
    return result
end
