local Prefs = import('/lua/user/prefs.lua')
local Matching = import('/mods/Microchip-Chat-Mention/modules/matching.lua')
local settings
local recent = {}
local simulationTimer, nextSimulation

function Settings()
    if not settings then settings = Matching.Normalize(Prefs.GetFromCurrentProfile('microchip_chat_mention')) end
    return settings
end

function Save(value)
    settings = Matching.Normalize(value)
    Prefs.SetToCurrentProfile('microchip_chat_mention', settings)
    nextSimulation = nil
    if not settings.enabled then import('/mods/Microchip-Chat-Mention/modules/popup.lua').Clear() end
end

function PlayerName()
    for _, client in pairs(GetSessionClients() or {}) do
        if client['local'] and type(client.name) == 'string' then return client.name end
    end
    -- Never use the focus army: an observer may be watching another player.
    return ''
end

function Receive(sender, message, entry)
    local config = Settings()
    if not config.enabled or type(sender) ~= 'string' or type(message) ~= 'table' then return end
    if type(message.text) ~= 'string' or message.to == 'notify' then return end
    if entry.Camera or entry.Location or (entry.Type and entry.Type ~= 'Chat') then return end
    local player = PlayerName()
    local matched = Matching.Match(message.text, player, config.nicknames)
    if not matched then return end
    local now = GetSystemTimeSeconds()
    for key, seen in pairs(recent) do if now - seen > 2 then recent[key] = nil end end
    local key = sender .. '\0' .. tostring(message.Id or message.text) .. '\0' .. tostring(message.to)
    if recent[key] then return end
    recent[key] = now
    import('/mods/Microchip-Chat-Mention/modules/popup.lua').Push({
        sender = sender, text = message.text, matched = matched,
        channel = message.to == 'allies' and 'ALLIES' or (type(message.to) == 'number' and 'PRIVATE' or 'ALL'),
        seconds = config.seconds,
        sound = config.sound,
        fontSize = config.fontSize,
    })
end

function Start()
    if simulationTimer and not IsDestroyed(simulationTimer) then return end
    nextSimulation = nil
    local frame = GetFrame(0)
    simulationTimer = import('/lua/maui/group.lua').Group(frame)
    -- Maui groups have circular default layout variables until both axes are
    -- anchored. Even a non-drawing timer must have a valid layout in the tree.
    simulationTimer.Width:Set(1); simulationTimer.Height:Set(1)
    simulationTimer.Left:Set(frame.Left); simulationTimer.Top:Set(frame.Top)
    simulationTimer:DisableHitTest()
    simulationTimer:SetNeedsFrameUpdate(true)
    simulationTimer.OnFrame = function()
        local config = Settings()
        if not config.enabled or not config.simulation then nextSimulation = nil; return end
        local now = GetSystemTimeSeconds()
        if not nextSimulation then nextSimulation = now + 10 end
        if now < nextSimulation then return end
        nextSimulation = now + 10
        local player = PlayerName()
        if player == '' then player = 'Microchip' end
        -- Local UI only: never send test messages to the session or simulation.
        import('/mods/Microchip-Chat-Mention/modules/popup.lua').Push({
            sender = 'Mention Test', channel = 'LOCAL TEST', seconds = config.seconds,
            text = player .. ', this is your 10-second mention test.',
            sound = config.sound, fontSize = config.fontSize,
        })
    end
end
