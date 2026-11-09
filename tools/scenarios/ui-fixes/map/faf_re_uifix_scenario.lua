version = 3
-- faf_re_uifix: UI fix check map (tools/scenarios/1p-uifix-main.yaml).
-- Seton's Clutch terrain: the scmap and save of faf_re_lockstep, copied or hard-linked in as
-- faf_re_uifix.scmap / faf_re_uifix_save.lua.
ScenarioInfo = {
    name = "FAF RE UI fixes",
    description = "A factory building a tank and a tank group, for the UI fix checks.",
    type = 'skirmish',
    starts = true,
    preview = '',
    size = {1024, 1024},
    map = '/maps/faf_re_uifix/faf_re_uifix.scmap',
    save = '/maps/faf_re_uifix/faf_re_uifix_save.lua',
    script = '/maps/faf_re_uifix/faf_re_uifix_script.lua',
    norushradius = 0.000000,
    Configurations = {
        ['standard'] = {
            teams = {
                { name = 'FFA', armies = {'ARMY_1','ARMY_2','ARMY_3','ARMY_4','ARMY_5','ARMY_6','ARMY_7','ARMY_8',} },
            },
            customprops = {
                ['ExtraArmies'] = STRING( 'ARMY_9 NEUTRAL_CIVILIAN' ),
            },
        },
    }}
