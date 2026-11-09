-- Engine hook (data/fafengine, mounted by the engine at /fafengine and registered as a hook directory): appended to
-- /lua/ui/help/tooltips.lua.
--
-- The options screen shows Tooltips['options_<key>'] when the mouse is over an option; the hook of
-- /lua/options/options.lua adds five options, so their texts go here. FAF's Lua may carry them already (issue #327,
-- FAForever/fa#7372); an entry that is there is left as FAF wrote it.

do
    local entries = {
        options_graphics_api = {
            title = "<LOC OPTIONS_GRAPHICS_API_TITLE>Graphics API",
            description = "<LOC OPTIONS_GRAPHICS_API_DESCRIPTION>The renderer the game draws with. Automatic uses the newest one this PC can start. Takes effect after a restart; if the chosen renderer cannot start, the game uses Direct3D 9.",
        },
        options_replay_keyframe_budget = {
            title = "<LOC OPTIONS_REPLAY_KEYFRAME_BUDGET_TITLE>Replay keyframe cache (MB)",
            description = "<LOC OPTIONS_REPLAY_KEYFRAME_BUDGET_DESCRIPTION>Disk space a replay may use for its saved positions, in the replay_keyframes folder next to the game, or in faf_replay_keyframes in the system's temporary folder when the game's folder can't be written. Over this, the oldest are thinned out, and moving far back takes longer. Cleared when the next replay starts.",
        },
        options_replay_keyframe_spacing = {
            title = "<LOC OPTIONS_REPLAY_KEYFRAME_SPACING_TITLE>Replay keyframe spacing (seconds)",
            description = "<LOC OPTIONS_REPLAY_KEYFRAME_SPACING_DESCRIPTION>Game time between a replay's saved positions. Closer ones make moves shorter and use more of the cache. The background preparation takes a new value from the next replay.",
        },
        options_replay_keyframe_prepare = {
            title = "<LOC OPTIONS_REPLAY_KEYFRAME_PREPARE_TITLE>Replay background preparation",
            description = "<LOC OPTIONS_REPLAY_KEYFRAME_PREPARE_DESCRIPTION>A hidden low-priority copy of the game saves positions ahead of a replay you watch, so a first jump forward can load one. Off saves CPU, and jumps forward play through the game instead.",
        },
        options_splat_budget_tier = {
            title = 'Ground splat limit',
            description = 'Maximum ground splats drawn in each view, including tread marks. '
                .. 'At Medium/High fidelity: Original 2,499; Enhanced 10,000; Very high 25,000; Extreme 50,000. '
                .. 'At Low fidelity: 249; 1,000; 2,500; 5,000. '
                .. 'Applies after pressing Apply or OK, without restarting. '
                .. 'Higher limits use more memory and rendering time. Marks can still disappear when the selected limit '
                .. 'or available memory is exceeded. This does not change splat lifetime or every type of decal.',
        },
    }
    for key, entry in entries do
        if not Tooltips[key] then
            Tooltips[key] = entry
        end
    end
end
