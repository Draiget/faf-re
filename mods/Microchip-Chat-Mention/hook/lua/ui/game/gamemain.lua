local oldCreateUI = CreateUI
function CreateUI(isReplay)
    oldCreateUI(isReplay)
    import('/mods/Microchip-Chat-Mention/modules/popup.lua').Clear()
    import('/mods/Microchip-Chat-Mention/modules/mentions.lua').Start()
    IN_AddKeyMapTable({
        ['Ctrl-Shift-M'] = {
            action = 'UI_Lua import("/mods/Microchip-Chat-Mention/modules/options.lua").Open()',
            category = 'ui',
        },
    })
end
