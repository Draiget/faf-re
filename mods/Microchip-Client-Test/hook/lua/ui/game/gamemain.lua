-- Opt-in diagnostics only; this hook does not change simulation or networking settings.
local originalCreateUI = CreateUI
local recordingThread
function CreateUI(isReplay)
    local result = originalCreateUI(isReplay)
    if recordingThread then KillThread(recordingThread); recordingThread = nil end
    if isReplay or not SessionIsMultiplayer() or not GetPreference('microchip_client_test_recording', false) then
        return result
    end
    recordingThread = ForkThread(function()
        local recorder = import('/mods/Microchip-Client-Test/modules/networkrecorder.lua').New()
        local seenClients, startupWaits = false, 0
        LOG('MicrochipNetDiag START interval_seconds=2; passive local recording, not a lag diagnosis')
        while true do
            local ok, clients = pcall(GetSessionClients)
            if ok and type(clients) == 'table' and next(clients) ~= nil then
                seenClients = true
                local captured, lines = pcall(function()
                    return recorder:Capture(clients, GetSystemTimeSeconds(), GameTick())
                end)
                if not captured then WARN('MicrochipNetDiag STOP: sample could not be recorded'); break end
                for _, line in ipairs(lines) do LOG(line) end
            else
                if seenClients or startupWaits >= 30 then break end
                startupWaits = startupWaits + 1
            end
            WaitSeconds(2)
        end
        LOG('MicrochipNetDiag STOP')
    end)
    return result
end

local ecoSkinTestCreateUI = CreateUI
function CreateUI(isReplay)
    ecoSkinTestCreateUI(isReplay)
    if not GetPreference('microchip_eco_test',false) or not rawget(_G,'MicrochipQueueTranslation') then return end
    ForkThread(function()
        WaitSeconds(4)
        local info=SessionGetScenarioInfo()
        info.Options.Ratings={AllyHigh=2100,AllyLow=1200}
        local sharing=import('/mods/Microchip-Eco-Sharing/modules/sharing.lua')
        local settings=sharing.Settings()
        settings.mode='Rank'; settings.targets={AllyHigh={ENERGY=true,MASS=true},AllyLow={ENERGY=true}}
        import('/mods/Microchip-Eco-Sharing/modules/panel.lua').Toggle()
        LOG('MicrochipEcoSkinTest panel opened')
    end)
end