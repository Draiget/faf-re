-- Overlay the requested key while this mod is loaded; never write keymap preferences.
local originalMicrochipKeyMap = GetCurrentKeyMap
function GetCurrentKeyMap()
    local result=table.copy(originalMicrochipKeyMap())
    for key in pairs(result) do
        if NormalizeKeyBinding(key)=='Ctrl-Shift-L' then result[key]=nil end
    end
    result['Ctrl-Shift-L']='microchip_evil_stamp'
    return result
end
