local function AllHumansReady(players)
    local hasHuman = false
    for _, player in players:pairs() do
        if player.Human then
            if not player.Ready then
                return false
            end
            hasHuman = true
        end
    end
    return hasHuman
end

function WatchLobby(getPlayers)
    local wasReady = false
    local players = getPlayers()
    while players do
        -- FAF temporarily flattens PlayerOptions during launch.
        if players.pairs then
            local ready = AllHumansReady(players)
            if ready and not wasReady then
                ConExecute('SC_FlashGameWindow')
                PlaySound(Sound({Bank = 'Interface', Cue = 'UI_Comm_UEF_In'}))
            end
            wasReady = ready
        end
        WaitSeconds(0.25)
        players = getPlayers()
    end
end
