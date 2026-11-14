local originalEcoCreateUI = CreateUI
function CreateUI(isReplay)
    local result=originalEcoCreateUI(isReplay)
    local sharing=import('/mods/Microchip-Eco-Sharing/modules/sharing.lua')
    sharing.Stop()
    sharing.Initialize()
    return result
end
