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
    if video and video.items then
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


do
    local replayKeyframeOption = {
        title = "Replay Keyframe Interval",
        key = 'replay_keyframe_interval',
        type = 'toggle',
        default = '-1',
        tip = "Interval between keyframes saved during replay playback for fast backward scrubbing. When Disabled, keyframes are not saved and backward rewinding is unavailable.",
        custom = {
            states = {
                { text = "Disabled", key = '-1' },
                { text = "Start only", key = '0' },
                { text = "Every 30 seconds", key = '30' },
                { text = "Every 1 minute", key = '60' },
                { text = "Every 2 minutes", key = '120' },
                { text = "Every 5 minutes", key = '300' },
            },
        },
        set = function(key, value)
            ConExecute("sim_ReplayKeyframeInterval " .. tostring(value))
        end,
    }

    local replayKeyframeStorageOption = {
        title = "Replay Keyframe Storage",
        key = 'replay_keyframe_storage',
        type = 'toggle',
        default = '2',
        tip = "Select where replay keyframes are stored: in RAM (Memory) for fastest snapshots and zero disk files, on Disk (Cache) to minimize RAM usage, or both (RAM + Disk Cache).",
        custom = {
            states = {
                { text = "RAM (Memory only)", key = '1' },
                { text = "Disk Cache (Files only)", key = '0' },
                { text = "RAM + Disk Cache (Both)", key = '2' },
            },
        },
        set = function(key, value)
            ConExecute("sim_ReplayKeyframeStorage " .. tostring(value))
        end,
    }

    local targetTab = options and (options.gameplay or options.interface or options.video)
    if targetTab and targetTab.items then
        table.insert(targetTab.items, replayKeyframeOption)
        table.insert(targetTab.items, replayKeyframeStorageOption)
    end
end
