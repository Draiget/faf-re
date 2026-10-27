-- Replay parity runner (tools/replay-parity): appended to the stock gamemain.lua through the
-- /parityhook hook folder. User side only, so it cannot change what the sim computes.
--   * runs the sim flat out (WLD_GameSpeed 50 is 10^5 times normal speed, i.e. uncapped)
--   * parks the camera at the map centre, zoomed fully in, so little is drawn
--   * logs a heartbeat the runner reads to see the replay advancing:
--       PARITY heartbeat tick=<beat> time=<game seconds> over=<game over>
local ParityOnFirstUpdate = OnFirstUpdate
function OnFirstUpdate()
    ParityOnFirstUpdate()

    local GameTickFn = rawget(_G, 'GameTick')
    local GameOverFn = rawget(_G, 'SessionIsGameOver')

    ForkThread(function()
        WaitSeconds(0.5)
        local cam = GetCamera('WorldCamera')
        if cam then
            -- Reset frames the whole map around its centre; zooming in keeps that focus.
            cam:Reset()
            cam:SetZoom(cam:GetMinZoom(), 0)
        end
        LOG('PARITY camera parked')
        while true do
            ConExecute('WLD_GameSpeed 50')
            LOG(string.format('PARITY heartbeat tick=%d time=%.1f over=%s',
                GameTickFn and GameTickFn() or -1, GameTime(), tostring(GameOverFn and GameOverFn() or false)))
            WaitSeconds(2)
        end
    end)
end
