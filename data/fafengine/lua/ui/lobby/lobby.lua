-- Engine hook (data/fafengine, mounted by the engine at /fafengine and
-- registered as a hook directory): appended to /lua/ui/lobby/lobby.lua.
--
-- A player with a style the engine has proven (docs/PEER_FEATURES.md) shows it
-- as the colour of their name, over the host, player and local colours.

do
    -- nil from an exe older than this hook, which shares the folder.
    local function PeerStyle(ownerID)
        if lobbyComm and lobbyComm.GetPeerStyle and ownerID then
            return lobbyComm:GetPeerStyle(ownerID)
        end
    end

    local baseSetSlotInfo = SetSlotInfo
    function SetSlotInfo(slotNum, playerInfo)
        baseSetSlotInfo(slotNum, playerInfo)
        if playerInfo.Human then
            local style = PeerStyle(playerInfo.OwnerID)
            if style then
                GUI.slots[slotNum].name:SetTitleTextColor(style)
            end
        end
    end

    local baseInitLobbyComm = InitLobbyComm
    function InitLobbyComm(protocol, localPort, desiredPlayerName, localPlayerUID, natTraversalProvider)
        baseInitLobbyComm(protocol, localPort, desiredPlayerName, localPlayerUID, natTraversalProvider)

        -- The proof can arrive after the slot was drawn.
        lobbyComm.PeerStyleChanged = function(self, uid)
            local slot = FindSlotForID(uid)
            local style = PeerStyle(uid)
            if style and slot and GUI.slots and GUI.slots[slot] then
                GUI.slots[slot].name:SetTitleTextColor(style)
            end
        end
    end
end
