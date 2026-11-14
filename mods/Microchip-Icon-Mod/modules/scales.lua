local Catalog = import('/mods/Microchip-Icon-Mod/modules/catalog.lua').Icons
local Prefs = import('/lua/user/prefs.lua')
local prefix = '/mods/Microchip-Icon-Mod/custom-strategic-icons/'
local preference = 'microchip_icon_scales'

function Validate(draft)
    local result = {}
    for _, icon in ipairs(Catalog) do
        local value = draft[icon.key]
        if value == nil then value = 100 end
        local n = tonumber(value)
        if not n or n ~= n or n < 25 or n > 400 or n ~= math.floor(n) then
            return nil, icon.name .. ': enter a whole percentage from 25 to 400.'
        end
        result[icon.key] = n
    end
    return result
end

function Load()
    local saved = Prefs.GetFromCurrentProfile(preference)
    if type(saved) ~= 'table' then saved = {} end
    local clean = {}
    for _, icon in ipairs(Catalog) do
        local value = tonumber(saved[icon.key])
        clean[icon.key] = value and value >= 25 and value <= 400 and value == math.floor(value) and value or 100
    end
    return clean
end

function Apply(draft, save)
    local clean, problem = Validate(draft)
    if not clean then return false, problem end
    local bindingType = type(SetStrategicIconScales)
    if bindingType ~= 'function' and bindingType ~= 'cfunction' then
        return false, 'Live scaling requires the updated Microchip game engine.'
    end
    local payload = {}
    for _, icon in ipairs(Catalog) do
        if clean[icon.key] ~= 100 then payload[prefix .. icon.key] = clean[icon.key] end
    end
    local ok, applied = pcall(SetStrategicIconScales, payload)
    if not ok or not applied then return false, 'Could not apply icon sizes. Settings have not been saved.' end
    if save then Prefs.SetToCurrentProfile(preference, clean) end
    return true, 'Applied live. Sizes saved for future games.'
end
