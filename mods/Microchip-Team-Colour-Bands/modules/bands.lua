-- Local display only: shades are applied on this PC and never sent to other players.
local Prefs = import('/lua/user/prefs.lua')

Allies = {'ffccffb3', 'ff99f07a', 'ff66d94a', 'ff3fbf2f', 'ff2ea02a', 'ff1f8020', 'ff3dd9a0', 'ff145c14'}
Enemies = {'ffffb3a8', 'ffff7a6b', 'ffff3d3d', 'ffe01010', 'ffb00c0c', 'ff800808', 'ffff4fa0', 'ff5a0505'}
Player = 'ff436eee'
Neutral = 'ffdeb887'

local active = false
local colours = {}
local listeners = {}

function Settings()
    local s = Prefs.GetFromCurrentProfile('microchip_team_colour_bands') or {}
    if s.autoEnable == nil then s.autoEnable = true end
    if s.keepBlue == nil then s.keepBlue = true end
    if s.order ~= 'name' then s.order = 'slot' end
    return s
end

function SaveSettings(s)
    Prefs.SetToCurrentProfile('microchip_team_colour_bands', s)
end

-- Beyond 8 per side the list repeats, darkened slightly so neighbours still differ.
local function Pick(list, n)
    local base = list[math.mod(n - 1, table.getn(list)) + 1]
    local cycle = math.floor((n - 1) / table.getn(list))
    if cycle == 0 then return base end
    local factor = math.max(0.4, 1 - 0.18 * cycle)
    local out = 'ff'
    for i = 3, 7, 2 do
        out = out .. string.format('%02x', math.floor(tonumber(string.sub(base, i, i + 1), 16) * factor))
    end
    return out
end

-- Returns armyIndex -> 'aarrggbb' for every army.
function Calculate()
    local s = Settings()
    local armies = GetArmiesTable().armiesTable or {}
    local focus = GetFocusArmy()
    local allies, enemies, result = {}, {}, {}
    for index, army in armies do
        if index == focus then
            result[index] = s.keepBlue and Player or Allies[1]
        elseif army.civilian or (focus > 0 and IsNeutral(focus, index)) then
            result[index] = Neutral
        elseif focus > 0 and IsAlly(focus, index) then
            table.insert(allies, index)
        else
            table.insert(enemies, index)
        end
    end
    local function Sort(list)
        if s.order == 'name' then
            table.sort(list, function(a, b)
                return string.lower(tostring(armies[a].nickname or '')) < string.lower(tostring(armies[b].nickname or ''))
            end)
        else table.sort(list) end
    end
    Sort(allies); Sort(enemies)
    for n, index in allies do result[index] = Pick(Allies, n) end
    for n, index in enemies do result[index] = Pick(Enemies, n) end
    return result
end

-- TeamColorMode wants one colour per army index, comma separated, starting at army 1.
function ModeString(map)
    local count = 0
    for index in map do if index > count then count = index end end
    local parts = {}
    for i = 1, count do table.insert(parts, string.lower(map[i] or Neutral)) end
    return table.concat(parts, ',')
end

function SetActive(on, map)
    active = on and true or false
    colours = active and (map or Calculate()) or {}
    for _, fn in listeners do pcall(fn, active) end
end

function IsActive() return active end

function ColourForArmy(index)
    return active and index and colours[index] or nil
end

function ColourForName(name)
    if not active or not name then return nil end
    for index, army in GetArmiesTable().armiesTable or {} do
        if army.nickname == name then return colours[index] end
    end
    return nil
end

function OnChange(fn) table.insert(listeners, fn) end
