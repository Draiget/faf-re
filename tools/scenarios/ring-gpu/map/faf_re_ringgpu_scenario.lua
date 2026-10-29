version = 3
-- faf_re_ringgpu: range-ring A/B test map (tools/scenarios/1p-ringgpu-*.yaml).
-- Seton's Clutch terrain: the scmap and save of faf_re_lockstep, copied or hard-linked in as
-- faf_re_ringgpu.scmap / faf_re_ringgpu_save.lua.
ScenarioInfo = {
    name = "FAF RE ring gpu",
    description = "An engineer pack and an artillery pack for the range-ring A/B test.",
    type = 'skirmish',
    starts = true,
    preview = '',
    size = {1024, 1024},
    map = '/maps/faf_re_ringgpu/faf_re_ringgpu.scmap',
    save = '/maps/faf_re_ringgpu/faf_re_ringgpu_save.lua',
    script = '/maps/faf_re_ringgpu/faf_re_ringgpu_script.lua',
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
