-- Engine hook (data/fafengine, mounted by the engine at /fafengine and
-- registered as a hook directory): appended to /lua/options/options.lua.
--
-- Adds the renderer choice to the Video tab. The engine reads the option
-- `graphics_api` once, when it creates the device (CScApp::CreateDevice), so a
-- change needs a restart; `restart = true` makes the options screen say so and
-- offer it. `auto` takes the first renderer that starts (Direct3D 11,
-- Direct3D 12, Vulkan, Direct3D 9). A command-line switch (/d3d9, /d3d11, /d3d12,
-- /vulkan, /D3D10) overrides the option, and a chosen renderer that cannot
-- start falls back to Direct3D 9.

do
    local graphicsApi = {
        title = "Graphics API",
        key = 'graphics_api',
        type = 'toggle',
        default = 'auto',
        restart = true,
        tip = "The renderer the game draws with. Automatic uses the first one this PC can start (Direct3D 11, 12, Vulkan, then 9). "
            .. "Takes effect after a restart; if the chosen renderer cannot start, the game uses Direct3D 9.",
        custom = {
            states = {
                { text = "Automatic", key = 'auto' },
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
