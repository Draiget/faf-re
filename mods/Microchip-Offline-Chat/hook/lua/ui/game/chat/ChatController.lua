-- Classic engines can keep this UI mod enabled; the offline bridge is x64-only.
if rawget(_G, 'MicrochipQueueTranslation') then
local Translator = import('/fafengine/lua/ui/translation.lua')
Translator.Reset()
local originalAppendEntry = AppendEntry
local originalOnReceive = OnReceive
local receiving, ownMessage = false, false

-- Live chat arrives via engine and sim paths; drop the second copy even if its Id did not survive.
local recent = {}
function OnReceive(sender, message)
    if type(message) == 'table' and type(message.text) == 'string' then
        local now = GetSystemTimeSeconds()
        local key = tostring(sender) .. '\0' .. tostring(message.to) .. '\0' .. message.text
        for k, seen in recent do if now - seen > 2 then recent[k] = nil end end
        if recent[key] then return end
        recent[key] = now
    end
    local wasReceiving, wasOwn = receiving, ownMessage
    receiving, ownMessage = true, false
    for _, client in pairs(GetSessionClients() or {}) do
        if client['local'] and client.name == sender then ownMessage = true; break end
    end
    originalOnReceive(sender, message)
    receiving, ownMessage = wasReceiving, wasOwn
end

function AppendEntry(entry)
    originalAppendEntry(entry)
    if ownMessage or (not receiving and entry.ArmyID == GetFocusArmy()) then return end
    -- Only translate visible, already-filtered player chat. Never camera links or system lines.
    if not entry.ArmyID or entry.ArmyID == 0 or entry.Camera or entry.Location then return end
    local original = table.copy(entry)
    Translator.Translate(entry.Text, function(english)
        local translated = table.copy(original)
        translated.Text = english
        translated.Id = nil
        originalAppendEntry(translated)
    end)
end
end
