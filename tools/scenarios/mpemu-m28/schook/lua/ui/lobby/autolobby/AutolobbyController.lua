-- mpemu M28AI runs only: init_mpemu_m28.lua mounts this folder, so this hook
-- runs after FAF's AutolobbyController.lua. The autolobby never enables sim
-- mods; every client launches with the M28AI mod from the vault instead.
do
    local baseLaunchGame = AutolobbyCommunications.LaunchGame
    AutolobbyCommunications.LaunchGame = function(self, gameConfig)
        local Mods = import('/lua/mods.lua')
        local wanted = {}
        for uid, mod in Mods.AllMods() do
            if mod.name == 'M28AI' then
                wanted[uid] = true
            end
        end
        gameConfig.GameMods = Mods.GetGameMods(wanted)
        for _, mod in gameConfig.GameMods do
            LOG('mpemu-m28: launching with sim mod ' .. tostring(mod.name) .. ' v' .. tostring(mod.version) .. ' ' .. tostring(mod.uid))
        end
        if table.getn(gameConfig.GameMods) == 0 then
            WARN('mpemu-m28: M28AI is not in the vault; launching without it')
        end
        return baseLaunchGame(self, gameConfig)
    end
end
