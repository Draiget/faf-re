-- Private AO test scene: structures of four factions in a grid plus clusters of land units, in front of the first army's start position.
local function Say(text) LOG(string.format('AO-TEST: [%.1f s] %s', GetGameTimeSeconds(), text)) end
local function WaitUntil(seconds) while GetGameTimeSeconds() < seconds do WaitTicks(5) end end

local FACTIONS = { 'ue', 'ua', 'ur', 'xs' }
local STRUCTURES = { '0101', '0102', '1101', '1102', '1103', '1104', '1201', '1301', '3101', '3201', '4202', '4301', '2101', '2104', '2301' }
local UNITS = { 'uel0201', 'ual0201', 'url0107', 'xsl0201', 'uel0106', 'ual0106' }

ForkThread(function()
    local brain = ArmyBrains[1]
    local x0, z0 = brain:GetArmyStartPos()
    WaitUntil(4)
    local created = 0
    for fi, prefix in FACTIONS do
        for si, number in STRUCTURES do
            local id = prefix .. 'b' .. number
            local ux = x0 - 36 + (si - 1) * 5
            local uz = z0 - 24 + (fi - 1) * 11
            if __blueprints[id] then
                if CreateUnitHPR(id, brain.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0) then created = created + 1 end
            end
        end
    end
    -- tight clusters of units behind the grid (units touching units)
    for ci = 1, 4 do
        for k = 1, 12 do
            local id = UNITS[math.mod(k, 6) + 1]
            local ux = x0 - 30 + (ci - 1) * 18 + math.mod(k, 4) * 1.6
            local uz = z0 + 24 + math.floor(k / 4) * 1.6
            if __blueprints[id] then
                if CreateUnitHPR(id, brain.Name, ux, GetTerrainHeight(ux, uz), uz, 0, 0, 0) then created = created + 1 end
            end
        end
    end
    Say(string.format('%d units created around (%.1f, %.1f)', created, x0, z0))
end)
