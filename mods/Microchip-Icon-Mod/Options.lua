function Main()
    UMT.Options.AddOptions('Microchip-Icon-Mod', 'Microchip Icon Mod', function(parent)
        return import('/mods/Microchip-Icon-Mod/modules/panel.lua').Open(parent)
    end)
end
