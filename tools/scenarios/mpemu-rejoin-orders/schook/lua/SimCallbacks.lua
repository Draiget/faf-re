-- mpemu rejoin runs only: init_mpemu_rejoin_orders.lua mounts this folder. Each client
-- logs every test command with the source and army the engine says sent it, so the logs
-- show whether a rejoined player's commands still count as that seat's. It also runs in
-- a replay of the game, which holds the same commands.
do
    local baseDoCallback = DoCallback
    function DoCallback(name, data, units)
        if name == 'RejoinTestOrder' then
            local army = import('/lua/SimUtils.lua').GetCurrentCommandSourceArmy()
            LOG('rejoin-test: order ' .. tostring(data.Sender) .. ' ' .. tostring(data.Count)
                .. ' from source ' .. tostring(GetCurrentCommandSource())
                .. ' army ' .. tostring(army)
                .. ' at tick ' .. tostring(GetGameTick()))
            -- Changes what the checksums cover, so a command that runs twice, or at another beat, shows as a desync.
            for _, brain in ArmyBrains do
                brain:GiveResource('MASS', 0.5)
            end
            return
        end
        return baseDoCallback(name, data, units)
    end
end
