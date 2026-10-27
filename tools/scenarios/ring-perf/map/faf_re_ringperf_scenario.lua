version = 3
-- faf_re_ringperf: range-ring render cost test map (tools/scenarios/1p-ringperf-main.yaml).
-- Seton's Clutch terrain: the scmap and save of faf_re_lockstep, copied or hard-linked in as
-- faf_re_ringperf.scmap / faf_re_ringperf_save.lua.
ScenarioInfo = {
    name = "FAF RE ring perf",
    description = "2000 engineers packed in a grid for the range-ring render cost test.",
    type = 'skirmish',
    starts = true,
    preview = '',
    size = {1024, 1024},
    map = '/maps/faf_re_ringperf/faf_re_ringperf.scmap',
    save = '/maps/faf_re_ringperf/faf_re_ringperf_save.lua',
    script = '/maps/faf_re_ringperf/faf_re_ringperf_script.lua',
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
