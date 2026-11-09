-- mpemu rejoin runs only: every client sends one test command through the game every
-- 10 s, marked "back" in a client started with /rejoin and "first" in the others.
do
    local baseCreateUI = CreateUI
    function CreateUI(isReplay)
        baseCreateUI(isReplay)
        if isReplay then
            return
        end
        -- A client started with /testejectvote votes to eject whoever is returning, once it sees them.
        -- Quickly, as the first vote ends the rejoin and the next client has little time to see it.
        if HasCommandLineArg('/testejectvote') then
            ForkThread(function()
                while true do
                    WaitSeconds(0.1)
                    for index, client in GetSessionClients() or {} do
                        if client.rejoinStage == 'transfer' and not client['local'] then
                            LOG('rejoin-test: voting to eject client ' .. tostring(index))
                            EjectSessionClient(index)
                            return
                        end
                    end
                end
            end)
        end
        -- /testquit: quits normally at 3:00 of game time.
        if HasCommandLineArg('/testquit') then
            ForkThread(function()
                while GetGameTimeSeconds() < 180 do
                    WaitSeconds(1)
                end
                LOG('rejoin-test: quitting')
                ExitApplication()
            end)
        end
        -- /testpausebefore: pauses at 3:00 of game time, so before the kill, until the player is back.
        -- /testpauseduring: pauses for 20 s once the player is on the way back.
        local function FindStage(stage)
            for index, client in GetSessionClients() or {} do
                if client.rejoinStage == stage and not client['local'] then
                    return true
                end
            end
            return false
        end
        if HasCommandLineArg('/testpausebefore') then
            ForkThread(function()
                while GetGameTimeSeconds() < 180 do
                    WaitSeconds(1)
                end
                LOG('rejoin-test: pausing before the kill, game time ' .. tostring(GetGameTimeSeconds()))
                SessionRequestPause()
                while not FindStage('back') do
                    WaitSeconds(1)
                end
                LOG('rejoin-test: resuming, the player is back, game time ' .. tostring(GetGameTimeSeconds()))
                SessionResume()
            end)
        end
        if HasCommandLineArg('/testpauseduring') then
            ForkThread(function()
                while not FindStage('transfer') do
                    WaitSeconds(1)
                end
                LOG('rejoin-test: pausing during the transfer')
                SessionRequestPause()
                WaitSeconds(20)
                LOG('rejoin-test: resuming')
                SessionResume()
            end)
        end
        local sender = HasCommandLineArg('/rejoin') and 'back' or 'first'
        -- A client started with /testunitorders gives its factories a real order, which
        -- takes its command id from the engine's pool, as a player's click does.
        if HasCommandLineArg('/testunitorders') then
            ForkThread(function()
                local count = 0
                while true do
                    WaitSeconds(15)
                    UISelectionByCategory('FACTORY', false, false, false, false)
                    local factories = GetSelectedUnits() or {}
                    if factories[1] then
                        count = count + 1
                        IssueBlueprintCommand('UNITCOMMAND_BuildFactory', string.sub(factories[1]:GetUnitId(), 1, 2) .. 'l0105', 1)
                        local queue = SetCurrentFactoryForQueueDisplay(factories[1]) or {}
                        LOG('rejoin-test: factory order ' .. sender .. ' ' .. tostring(count)
                            .. ': ' .. tostring(table.getn(factories)) .. ' factories, queue ' .. tostring(table.getn(queue)))
                    end
                end
            end)
        end
        ForkThread(function()
            local count = 0
            -- /testordersfast: four a second, so some fall in every gap of a handover.
            local interval = HasCommandLineArg('/testordersfast') and 0.25 or 10
            while true do
                WaitSeconds(interval)
                count = count + 1
                SimCallback({ Func = 'RejoinTestOrder', Args = { Sender = sender, Count = count } }, false)
            end
        end)
    end
end
