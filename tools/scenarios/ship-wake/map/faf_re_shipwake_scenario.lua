version = 3
-- faf_re_shipwake: ship-wake visual comparison map (tools/scenarios/1p-shipwake-*.yaml).
-- Seton's Clutch terrain: the scmap and save of faf_re_lockstep, copied or hard-linked in as
-- faf_re_shipwake.scmap / faf_re_shipwake_save.lua.
ScenarioInfo = {
    name = "FAF RE ship wake",
    description = "Three ships sail through open water while the camera follows them.",
    type = 'skirmish',
    starts = true,
    preview = '',
    size = {1024, 1024},
    map = '/maps/faf_re_shipwake/faf_re_shipwake.scmap',
    save = '/maps/faf_re_shipwake/faf_re_shipwake_save.lua',
    script = '/maps/faf_re_shipwake/faf_re_shipwake_script.lua',
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
