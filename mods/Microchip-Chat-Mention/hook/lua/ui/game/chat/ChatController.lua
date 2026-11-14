local Mention = import('/mods/Microchip-Chat-Mention/modules/mentions.lua')
local oldReceive, oldAppend = OnReceive, AppendEntry
local incoming

function OnReceive(sender, message)
    local previous = incoming
    incoming = {sender = sender, message = message}
    oldReceive(sender, message)
    incoming = previous
end

function AppendEntry(entry)
    oldAppend(entry)
    -- Both received chat and locally echoed outgoing messages arrive here.
    -- Preserve FAF's routing/mute filters before looking for mentions.
    if entry and IsValidEntry(entry) then
        if incoming then
            Mention.Receive(incoming.sender, incoming.message, entry)
        elseif entry.ArmyID and entry.ArmyID > 0 then
            local armies = GetArmiesTable().armiesTable
            local army = armies and armies[entry.ArmyID]
            if army and army.nickname then
                Mention.Receive(army.nickname, {text = entry.Text, to = entry.Recipient, Id = entry.Id}, entry)
            end
        end
    end
end
