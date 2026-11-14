local originalCreateUI = CreateUI
local worker, toast, generation = nil, nil, 0
function CreateUI(isReplay)
    local result = originalCreateUI(isReplay)
    generation = generation + 1
    local session = generation
    if worker then KillThread(worker); worker = nil end
    if toast then toast:Destroy(); toast = nil end
    if isReplay or GetFocusArmy() < 1 then return result end
    worker = ForkThread(function()
        WaitSeconds(2)
        if MicrochipGetVisibleEnemies == nil then
            WARN('Microchip Threat Alerts: updated engine helper is required; alerts disabled.')
            return
        end
        LOG('Microchip Threat Alerts: helper type=' .. type(MicrochipGetVisibleEnemies))
        local Detector = import('/mods/Microchip-Threat-Alerts/modules/detection.lua')
        local Ping = import('/lua/ui/game/ping.lua')
        local UIUtil = import('/lua/ui/uiutil.lua')
        local Layout = import('/lua/maui/layouthelpers.lua')
        local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
        local focus = GetFocusArmy()
        local detector = Detector.New()
        toast = Bitmap(GetFrame(0))
        toast:SetSolidColor('dd142730'); toast.Width:Set(600); toast.Height:Set(58)
        toast.Depth:Set(GetFrame(0):GetTopmostDepth() + 5)
        Layout.AtTopIn(toast, GetFrame(0), 100); Layout.AtHorizontalCenterIn(toast, GetFrame(0))
        toast:DisableHitTest()
        local label = UIUtil.CreateText(toast, '', 18, UIUtil.bodyFont)
        Layout.AtLeftTopIn(label, toast, 12, 6); label:DisableHitTest()
        local detail = UIUtil.CreateText(toast, 'Local alert - newly spotted in direct vision', 13, UIUtil.bodyFont)
        Layout.AtLeftTopIn(detail, toast, 12, 32); detail:DisableHitTest()
        toast:Hide()
        local hideAt = -1
        while generation == session and GetFocusArmy() == focus do
            local now = GetSystemTimeSeconds()
            local visible = {}
            for _, unit in ipairs(MicrochipGetVisibleEnemies() or {}) do
                -- Copy only this visible snapshot; never retain or track a hidden unit object.
                local bp = unit:GetBlueprint()
                if Detector.Threat(bp) then
                    table.insert(visible, {id = unit:GetEntityId(), blueprint = bp, position = unit:GetPosition()})
                end
            end
            local threat = detector:Update(visible, now)
            if threat then
                local ping = {}
                for key, value in pairs(Ping.PingTypes.alert) do ping[key] = value end
                ping.Owner = focus - 1; ping.Location = threat.position
                -- DisplayPing renders locally. Never call DoPing, SimCallback, or SessionSendChatMessage.
                Ping.DisplayPing({ping})
                label:SetText(string.sub(threat.kind .. ' spotted: ' .. LOC(threat.name), 1, 70))
                toast:Show(); hideAt = now + 6
                LOG('Microchip Threat Alerts: local ' .. threat.kind .. ' alert')
            elseif now >= hideAt then toast:Hide() end
            WaitSeconds(1)
        end
        if toast then toast:Destroy(); toast = nil end
    end)
    return result
end
