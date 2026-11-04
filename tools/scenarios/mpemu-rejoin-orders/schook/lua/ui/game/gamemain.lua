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
        if HasCommandLineArg('/testejectvote') then
            ForkThread(function()
                while true do
                    WaitSeconds(1)
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
        local sender = HasCommandLineArg('/rejoin') and 'back' or 'first'
        ForkThread(function()
            local count = 0
            while true do
                WaitSeconds(10)
                count = count + 1
                SimCallback({ Func = 'RejoinTestOrder', Args = { Sender = sender, Count = count } }, false)
            end
        end)
    end
end
