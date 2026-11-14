local originalMicrochipCreateUI = CreateUI
function CreateUI(isReplay)
    originalMicrochipCreateUI(isReplay)
    -- keymapper may already be cached before UI mod hooks are available.
    IN_AddKeyMapTable({
        ['Ctrl-Shift-L'] = {
            action = 'UI_Lua import("/mods/Microchip-Evil-Stamp/modules/picker.lua").Toggle()',
            category = 'ui',
        },
    })
end
