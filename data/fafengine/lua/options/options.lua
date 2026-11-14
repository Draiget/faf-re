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
                { text = "<LOC OPTIONS_GRAPHICS_API_AUTO>Automatic (newest available)", key = 'auto' },
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

-- The replay viewer's keyframes: saved game states it moves back to. Compressed, in replay_keyframes next to the exe
-- (faf_replay_keyframes in the temporary folder when the exe's folder can't be written).
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
            tip = "Disk space a replay may use for its saved positions, in the replay_keyframes folder next to the game, or in "
                .. "faf_replay_keyframes in the system's temporary folder when the game's folder can't be written. "
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


-- Local rendering only. Older executables must neither show this option nor
-- receive an unknown command when preferences are applied at startup.
do
    local command = 'ren_SplatBudgetTier'
    local extendedCommand = 'ren_SplatBudgetTierExtended'
    local function Supported(name)
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, name)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, match in ipairs(matches) do
            if match == name then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported(command) then
        local position = table.getn(video.items) + 1
        local present = false
        for index, item in ipairs(video.items) do
            if item.key == 'splat_budget_tier' then
                present = true
            elseif item.key == 'fidelity' then
                position = index + 1
            end
        end
        if not present then
            local states = {
                { text = 'Original', key = 0 },
                { text = 'Enhanced (about 4x)', key = 1 },
                { text = 'Very high (about 10x)', key = 2 },
                { text = 'Extreme (about 20x)', key = 3 },
            }
            if Supported(extendedCommand) then
                table.insert(states, { text = 'Experimental (about 40x)', key = 4 })
                table.insert(states, { text = 'Experimental (about 100x)', key = 5 })
                table.insert(states, { text = 'Experimental (about 200x)', key = 6 })
            end
            table.insert(video.items, position, {
                title = 'Ground splat limit',
                key = 'splat_budget_tier',
                type = 'toggle',
                default = 0,
                set = function(key, value, startup)
                    if not Supported(command) then
                        return
                    end
                    -- Do not concatenate unvalidated preference text into a command.
                    if value ~= 0 and value ~= 1 and value ~= 2 and value ~= 3 and value ~= 4 and value ~= 5 and value ~= 6 then
                        value = 0
                    end
                    local destination = command
                    if Supported(extendedCommand) then
                        destination = extendedCommand
                    elseif value >= 4 then
                        -- A saved experimental tier on an older engine falls back
                        -- to its supported maximum, never an invalid console value.
                        value = 3
                    end
                    ConExecute(destination .. ' ' .. tostring(value))
                end,
                custom = {
                    states = states,
                },
            })
        end
    end
end

-- Shadow maps up to 4096, for the renderers newer than Direct3D 9. The engine holds Direct3D 9 at 2048 (Shadow::Init).
do
    local video = options and options.video
    if video and video.items then
        for _, item in video.items do
            if item.key == 'shadow_resolution' and item.custom then
                item.custom.max = 4096
                break
            end
        end
    end
end

-- Finer shadows near the camera (ren_ShadowCascades), on Direct3D 12 and Vulkan. Shown only by an engine that
-- has the command, as the ones below.
do
    local command = 'ren_ShadowCascades'
    local function Supported()
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported() then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'shadow_resolution' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Sharper near shadows',
            key = 'shadow_cascades',
            type = 'toggle',
            default = 3,
            tip = 'Extra shadow detail close to the camera when it is tilted. Direct3D 12 and Vulkan only; '
                .. 'other renderers keep the original shadows.',
            set = function(key, value, startup)
                if value ~= 0 then
                    value = 3
                end
                ConExecute(command .. ' ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = 3 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
    end
end

-- Ray-traced shadows (ren_RayTracedShadows) and ray-traced ambient occlusion (ren_RayAo), on Direct3D 12 and Vulkan
-- devices that can trace rays. Shown only by an engine that has the commands, as the others.
-- Ray-traced shadows and the explosion and weapon lights are off until the player turns them on. Their keys changed
-- when the default went from on to off: the options screen saves every value, defaults too, so the old keys hold
-- 1 for everyone who ran a build that had them on.
do
    local function Supported(command)
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported('ren_RayTracedShadows') then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'shadow_cascades' or item.key == 'shadow_resolution' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Ray-traced shadows',
            key = 'ray_traced_shadows_optin',
            type = 'toggle',
            default = 0,
            tip = 'Sun shadows of the ground, units and buildings traced by ray: exact at every distance, and hills '
                .. 'shade the ground. Needs a graphics card that can trace rays, on Direct3D 12 or Vulkan; '
                .. 'elsewhere the shadow map stays.',
            set = function(key, value, startup)
                ConExecute('ren_RayTracedShadows ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = 1 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
        if Supported('ren_RayAo') then
            table.insert(video.items, position + 1, {
                title = 'Ray-traced ambient light',
                key = 'ray_traced_ao',
                type = 'toggle',
                default = 1,
                tip = 'With ray-traced shadows on: the shading of nooks, the ground around buildings and units '
                    .. 'under each other, traced by ray instead of read from the screen.',
                set = function(key, value, startup)
                    ConExecute('ren_RayAo ' .. tostring(value))
                end,
                custom = {
                    states = {
                        { text = '<LOC _On>', key = 1 },
                        { text = '<LOC _Off>', key = 0 },
                    },
                },
            })
        end
        if Supported('ren_DynamicLights') then
            table.insert(video.items, math.min(position + 3, table.getn(video.items) + 1), {
                title = 'Explosion and weapon lights',
                key = 'dynamic_lights_optin',
                type = 'toggle',
                default = 0,
                tip = 'Direct3D 12 and Vulkan: explosions, muzzle flashes, engines, projectiles and beams light the '
                    .. 'ground and the units around them.',
                set = function(key, value, startup)
                    ConExecute('ren_DynamicLights ' .. tostring(value))
                end,
                custom = {
                    states = {
                        { text = '<LOC _On>', key = 1 },
                        { text = '<LOC _Off>', key = 0 },
                    },
                },
            })
        end
        if Supported('ren_RayBounce') then
            table.insert(video.items, math.min(position + 2, table.getn(video.items) + 1), {
                title = 'Ray-traced bounce light',
                key = 'ray_bounce_optin',
                type = 'toggle',
                default = 0,
                tip = 'With ray-traced shadows on: light bounces once off the ground, cliffs and buildings onto what '
                    .. 'stands next to them, in their own colour.',
                set = function(key, value, startup)
                    ConExecute('ren_RayBounce ' .. tostring(value))
                end,
                custom = {
                    states = {
                        { text = '<LOC _On>', key = 1 },
                        { text = '<LOC _Off>', key = 0 },
                    },
                },
            })
        end
        if Supported('ren_RayWaterReflections') then
            table.insert(video.items, math.min(position + 2, table.getn(video.items) + 1), {
                title = 'Ray-traced water reflections',
                key = 'ray_water_optin',
                type = 'toggle',
                default = 0,
                tip = 'With ray-traced shadows on: lakes and the sea reflect the hills, ground and units around them, '
                    .. 'not only the sky.',
                set = function(key, value, startup)
                    ConExecute('ren_RayWaterReflections ' .. tostring(value))
                end,
                custom = {
                    states = {
                        { text = '<LOC _On>', key = 1 },
                        { text = '<LOC _Off>', key = 0 },
                    },
                },
            })
        end
        if Supported('ren_RaySunAngle') then
            table.insert(video.items, math.min(position + 2, table.getn(video.items) + 1), {
                title = 'Soft ray-traced shadows',
                key = 'ray_soft_shadows',
                type = 'toggle',
                default = 1,
                tip = 'With ray-traced shadows on: the sun is a disc, not a point, so shadows are sharp where '
                    .. 'they start and soften further from their caster.',
                set = function(key, value, startup)
                    ConExecute('ren_RaySunAngle ' .. ((value == 1) and '3' or '0'))
                end,
                custom = {
                    states = {
                        { text = '<LOC _On>', key = 1 },
                        { text = '<LOC _Off>', key = 0 },
                    },
                },
            })
        end
    end
end

-- Temporal anti-aliasing (ren_Taa), on Direct3D 12 and Vulkan: off until the player turns it on.
do
    local kind = type(ConTextMatches)
    local supported = false
    if kind == 'function' or kind == 'cfunction' then
        local ok, matches = pcall(ConTextMatches, 'ren_Taa')
        if ok and type(matches) == 'table' then
            for _, name in ipairs(matches) do
                if name == 'ren_Taa' then
                    supported = true
                end
            end
        end
    end
    local video = options and options.video
    if supported and video and video.items then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'antialiasing' or item.key == 'fxaa_on' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Temporal anti-aliasing',
            key = 'taa',
            type = 'toggle',
            default = 0,
            tip = 'Direct3D 12 and Vulkan: smooths edges and stops thin lines and far detail from crawling, by blending '
                .. 'each frame with the last ones. Replaces FXAA while on.',
            set = function(key, value, startup)
                ConExecute('ren_Taa ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = 1 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
        -- ren_RenderScale: with temporal anti-aliasing, the world drawn smaller and rebuilt to full size.
        table.insert(video.items, position + 1, {
            title = 'Render resolution',
            key = 'render_scale',
            type = 'toggle',
            default = 100,
            tip = 'With temporal anti-aliasing on: draws the world at a lower resolution and rebuilds the full picture '
                .. 'from the last frames. Faster on a slow graphics card, a little softer. The interface stays sharp.',
            set = function(key, value, startup)
                ConExecute('ren_RenderScale ' .. tostring((tonumber(value) or 100) / 100))
            end,
            custom = {
                states = {
                    { text = '100%', key = 100 },
                    { text = '85%', key = 85 },
                    { text = '75%', key = 75 },
                    { text = '67%', key = 67 },
                    { text = '50%', key = 50 },
                },
            },
        })
    end
end

-- Sun shafts and height fog (ren_Atmosphere), on Direct3D 12 and Vulkan: off until the player turns it on.
do
    local function Supported(command)
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported('ren_Atmosphere') then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'dynamic_lights_optin' or item.key == 'ray_soft_shadows' or item.key == 'ray_traced_ao'
                or item.key == 'ray_traced_shadows_optin' or item.key == 'shadow_resolution' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Sun shafts and height fog',
            key = 'atmosphere',
            type = 'toggle',
            default = 0,
            tip = 'Direct3D 12 and Vulkan: a light haze over the low ground and water, lit by the sun, darker where '
                .. 'hills shade it. Never thick enough to hide units.',
            set = function(key, value, startup)
                ConExecute('ren_Atmosphere ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = 1 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
    end
end

-- Texture filtering (ren_TextureAnisotropy), on Direct3D 12 and Vulkan: anisotropic filtering for the tiled ground
-- and unit textures. Shown only by an engine that has the command, as the ones below.
do
    local command = 'ren_TextureAnisotropy'
    local function Supported()
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported() then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'texture_level' then
                position = index + 1
            end
        end
        -- Option values are levels, so a saved preference never reaches the command as text.
        local levels = { [0] = '0', [1] = '4', [2] = '8', [3] = '16' }
        table.insert(video.items, position, {
            title = 'Texture filtering',
            key = 'texture_anisotropy',
            type = 'toggle',
            default = 2,
            tip = 'Keeps ground and unit textures sharp when seen at a slant (anisotropic filtering). '
                .. 'Direct3D 12 and Vulkan only.',
            set = function(key, value, startup)
                ConExecute(command .. ' ' .. (levels[value] or levels[2]))
            end,
            custom = {
                states = {
                    { text = 'Trilinear', key = 0 },
                    { text = '4x', key = 1 },
                    { text = '8x', key = 2 },
                    { text = '16x', key = 3 },
                },
            },
        })
    end
end

-- Ambient occlusion (ren_Ao), on Direct3D 12 and Vulkan. Shown only by an engine that has the command,
-- as the splat limit above.
do
    local command = 'ren_Ao'
    local function Supported()
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported() then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'shadow_resolution' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Ambient occlusion',
            key = 'ambient_occlusion',
            type = 'toggle',
            default = -1,
            tip = 'Darkens creases and the ground under units. Direct3D 12 and Vulkan only; other renderers keep the original look.',
            set = function(key, value, startup)
                if value ~= 0 and value ~= -1 then
                    value = -1
                end
                ConExecute(command .. ' ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = -1 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
    end
end

-- FXAA (ren_Fxaa) on Direct3D 12 and Vulkan, which list no multisampled anti-aliasing. Shown only by an
-- engine that has the command.
do
    local command = 'ren_Fxaa'
    local function Supported()
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported() then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'antialiasing' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Anti-aliasing (FXAA)',
            -- 'fxaa' held -1 (Automatic, which followed the Anti-Aliasing setting) before FXAA was on by default.
            key = 'fxaa_on',
            type = 'toggle',
            default = 1,
            tip = 'Smooths jagged edges on Direct3D 12 and Vulkan. Other renderers ignore it.',
            set = function(key, value, startup)
                if value ~= 0 then
                    value = 1
                end
                ConExecute(command .. ' ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = 1 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
    end
end

-- Sharpening (ren_Sharpen) and colour grading (ren_Grade) on Direct3D 12 and Vulkan, after FXAA. Shown only by an
-- engine that has the commands.
do
    local function Supported(command)
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    local video = options and options.video
    if video and video.items and Supported('ren_Sharpen') and Supported('ren_Grade') then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'fxaa_on' then
                position = index + 1
            end
        end
        -- Option values are levels, not the strength itself, so a saved preference never reaches the command as text.
        local sharpness = { [0] = '0', [1] = '0.25', [2] = '0.5', [3] = '1' }
        table.insert(video.items, position, {
            title = 'Sharpening',
            key = 'sharpen_level',
            type = 'toggle',
            default = 2,
            tip = 'Brings back edge and texture detail that FXAA and scaling soften. Direct3D 12 and Vulkan only.',
            set = function(key, value, startup)
                ConExecute('ren_Sharpen ' .. (sharpness[value] or sharpness[2]))
            end,
            custom = {
                states = {
                    { text = '<LOC _Off>', key = 0 },
                    { text = '<LOC _Low>', key = 1 },
                    { text = '<LOC _Medium>', key = 2 },
                    { text = '<LOC _High>', key = 3 },
                },
            },
        })
        table.insert(video.items, position + 1, {
            title = 'Colour grading',
            key = 'grade_on',
            type = 'toggle',
            default = 1,
            tip = 'Livelier dull colours and slightly deeper contrast; team colours stay as they are. Direct3D 12 and Vulkan only.',
            set = function(key, value, startup)
                if value ~= 0 then
                    value = 1
                end
                ConExecute('ren_Grade ' .. tostring(value))
            end,
            custom = {
                states = {
                    { text = '<LOC _On>', key = 1 },
                    { text = '<LOC _Off>', key = 0 },
                },
            },
        })
    end

    -- Wide glow (ren_BloomWide), after FAF's own bloom options when they are listed (FAF ships Bloom Render off).
    if video and video.items and Supported('ren_BloomWide') then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'bloom_render' or item.key == 'bloom_intensity' or item.key == 'grade_on' then
                position = index + 1
            end
        end
        local strength = { [0] = '0', [1] = '1', [2] = '2' }
        table.insert(video.items, position, {
            title = 'Wide glow',
            key = 'bloom_wide_level',
            type = 'toggle',
            default = 0,
            tip = 'A soft, wide halo around lights, explosions and shields, added to the bloom. Needs Bloom Render. '
                .. 'Direct3D 12 and Vulkan only.',
            set = function(key, value, startup)
                ConExecute('ren_BloomWide ' .. (strength[value] or strength[0]))
            end,
            custom = {
                states = {
                    { text = '<LOC _Off>', key = 0 },
                    { text = 'Normal', key = 1 },
                    { text = 'Strong', key = 2 },
                },
            },
        })
    end
end

-- Interface text (ren_MsdfText, ren_MsdfTextMinSize), on every renderer: smooth text from MSDF atlases, smooth text
-- with the small sizes on the original Windows (GDI) glyphs, or the original glyphs everywhere. A mod's own font has
-- no GDI version and keeps its atlas either way. Shown only by an engine that has the commands.
do
    local function Supported(command)
        -- The engine's Lua reports C functions as 'cfunction'.
        local kind = type(ConTextMatches)
        if kind ~= 'function' and kind ~= 'cfunction' then
            return false
        end
        local ok, matches = pcall(ConTextMatches, command)
        if not ok or type(matches) ~= 'table' then
            return false
        end
        for _, name in ipairs(matches) do
            if name == command then
                return true
            end
        end
        return false
    end

    -- FAF's options.lua may carry this entry too (FAForever/fa#7372); then it shows once, with FAF's text.
    local video = options and options.video
    if video and video.items and not HasOptionKey(video.items, 'interface_text')
        and Supported('ren_MsdfText') and Supported('ren_MsdfTextMinSize') then
        -- Option values are levels, so a saved preference never reaches the commands as text.
        -- 13: the GDI glyphs' hinting matters most below about 13 px, where MSDF text is softer and dimmer.
        local modes = {
            [0] = { on = '0', minSize = '1' },
            [1] = { on = '1', minSize = '13' },
            [2] = { on = '1', minSize = '1' },
        }
        table.insert(video.items, {
            title = 'Interface text',
            key = 'interface_text',
            type = 'toggle',
            default = 2,
            tip = 'Smooth draws interface text from distance-field atlases, sharp at any size. Original draws it with '
                .. 'the Windows glyphs, as the original game does. Small text original keeps text with a font size under 13 '
                .. 'on the Windows glyphs.',
            set = function(key, value, startup)
                local mode = modes[value] or modes[2]
                ConExecute('ren_MsdfTextMinSize ' .. mode.minSize)
                ConExecute('ren_MsdfText ' .. mode.on)
            end,
            custom = {
                states = {
                    { text = '<LOC OPTIONS_INTERFACE_TEXT_SMOOTH>Smooth', key = 2 },
                    { text = '<LOC OPTIONS_INTERFACE_TEXT_SMALL_ORIGINAL>Small text original', key = 1 },
                    { text = '<LOC OPTIONS_INTERFACE_TEXT_ORIGINAL>Original', key = 0 },
                },
            },
        })
    end
end
