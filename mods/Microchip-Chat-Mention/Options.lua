function Main()
    UMT.Options.AddOptions('Microchip-Chat-Mention', 'Microchip Chat Mention', function(parent)
        return import('/mods/Microchip-Chat-Mention/modules/options.lua').Open(parent)
    end)
end
