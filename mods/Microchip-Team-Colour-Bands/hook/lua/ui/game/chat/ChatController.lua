-- Microchip Team Colour Bands: new chat lines use the band shade while the mode is on.
local Bands = import('/mods/Microchip-Team-Colour-Bands/modules/bands.lua')
local bandsOriginalAppendEntry = AppendEntry
function AppendEntry(entry)
    if type(entry) == 'table' and entry.ArmyID and not entry.Camera and not entry.Location then
        local colour = Bands.ColourForArmy(entry.ArmyID)
        if colour then
            entry = table.copy(entry)
            entry.Color = colour
        end
    end
    return bandsOriginalAppendEntry(entry)
end
