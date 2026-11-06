-- Engine hook (data/fafengine, mounted by the engine at /fafengine and
-- registered as a hook directory): appended to /lua/options/options.lua.
--
-- Adds the renderer choice to the Video tab. The engine reads the option
-- `graphics_api` once, when it creates the device (CScApp::CreateDevice), so a
-- change needs a restart; `restart = true` makes the options screen say so and
-- offer it. `auto` takes the newest renderer that starts (Direct3D 12, Vulkan,
-- Direct3D 11, Direct3D 9). A command-line switch (/d3d9, /d3d11, /d3d12,
-- /vulkan, /D3D10) overrides the option, and a chosen renderer that cannot
-- start falls back to Direct3D 9.
--
-- FAF's own options.lua may carry these entries (issue #327); an entry whose key
-- is already in the tab is left out here, so it shows once, with FAF's text.

local function HasOptionKey(items, key)
    for _, item in items do
        if item.key == key then
            return true
        end
    end
    return false
end

do
    local graphicsApi = {
        title = "Graphics API",
        key = 'graphics_api',
        type = 'toggle',
        default = 'auto',
        restart = true,
        tip = "The renderer the game draws with. Automatic uses the newest one this PC can start. "
            .. "Takes effect after a restart; if the chosen renderer cannot start, the game uses Direct3D 9.",
        custom = {
            states = {
                { text = "Automatic (newest available)", key = 'auto' },
                { text = "Direct3D 9", key = 'd3d9' },
                { text = "Direct3D 11", key = 'd3d11' },
                { text = "Direct3D 12", key = 'd3d12' },
                { text = "Vulkan", key = 'vulkan' },
            },
        },
    }

    local video = options and options.video
    if video and video.items and not HasOptionKey(video.items, graphicsApi.key) then
        -- After Vertical Sync, with the other display settings; at the end of
        -- the tab when that entry is missing.
        local position = table.getn(video.items) + 1
        for index, item in video.items do
            if item.key == 'vsync' then
                position = index + 1
                break
            end
        end
        table.insert(video.items, position, graphicsApi)
    end
end

-- The replay viewer's keyframes: saved game states it moves back to. Compressed, in replay_keyframes next to the exe.
do
    local gameplay = options and options.gameplay
    if gameplay and gameplay.items then
        local function Add(item)
            if not HasOptionKey(gameplay.items, item.key) then
                table.insert(gameplay.items, item)
            end
        end
        Add({
            title = "Replay keyframe cache (MB)",
            key = 'replay_keyframe_budget',
            type = 'slider',
            default = 2048,
            tip = "Disk space a replay may use for its saved positions, in the replay_keyframes folder next to the game. "
                .. "Over this, the oldest are thinned out, and moving far back takes longer. Cleared when the next replay starts.",
            set = function(key, value, startup)
                ConExecute("replay_KeyframeMaxMB " .. tostring(value))
            end,
            custom = {
                min = 256,
                max = 16384,
                inc = 256,
            },
        })
        Add({
            title = "Replay keyframe spacing (seconds)",
            key = 'replay_keyframe_spacing',
            type = 'slider',
            default = 30,
            tip = "Game time between a replay's saved positions. Closer ones make moves shorter and use more of the cache. "
                .. "The background preparation takes a new value from the next replay.",
            set = function(key, value, startup)
                ConExecute("replay_KeyframeEvery " .. tostring(math.floor(value) * 10))
            end,
            custom = {
                min = 10,
                max = 300,
                inc = 10,
            },
        })
        Add({
            title = "Replay background preparation",
            key = 'replay_keyframe_prepare',
            type = 'toggle',
            default = 1,
            tip = "A hidden low-priority copy of the game saves positions ahead of a replay you watch, so a first jump forward "
                .. "can load one. Off saves CPU, and jumps forward play through the game instead.",
            set = function(key, value, startup)
                ConExecute("replay_PrepareKeyframes " .. tostring(value))
            end,
            custom = {
                states = {
                    {text = "<LOC _On>", key = 1},
                    {text = "<LOC _Off>", key = 0},
                },
            },
        })
    end
end
