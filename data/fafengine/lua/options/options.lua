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
        local present = false
        for index, item in ipairs(video.items) do
            if item.key == 'splat_budget_tier' then
                present = true
            elseif item.key == 'fidelity' then
                position = index + 1
            end
        end
        if not present then
            table.insert(video.items, position, {
                title = 'Ground splat limit',
                key = 'splat_budget_tier',
                type = 'toggle',
                default = 0,
                set = function(key, value, startup)
                    if not Supported() then
                        return
                    end
                    -- Do not concatenate unvalidated preference text into a command.
                    if value ~= 0 and value ~= 1 and value ~= 2 and value ~= 3 then
                        value = 0
                    end
                    ConExecute(command .. ' ' .. tostring(value))
                end,
                custom = {
                    states = {
                        { text = 'Original', key = 0 },
                        { text = 'Enhanced (about 4x)', key = 1 },
                        { text = 'Very high (about 10x)', key = 2 },
                        { text = 'Extreme (about 20x)', key = 3 },
                    },
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
-- Ray-traced shadows, the ray-traced ambient light and the explosion and weapon lights are off until the player turns
-- them on. Their keys changed when the default went from on to off: the options screen saves every value, defaults
-- too, so the old keys hold 1 for everyone who ran a build that had them on.
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
            requiresRayTracing = true,
            type = 'toggle',
            default = 0,
            tip = 'Experimental. Sun shadows of the ground, units and buildings traced by ray instead of read from the shadow map: '
                .. 'no map resolution, and hills shade the ground, within the range the shadow map covers. Needs a graphics card '
                .. 'that can trace rays, on Direct3D 12 or Vulkan; elsewhere the shadow map stays. It replaces Shadow Filtering and '
                .. 'the contact shadows while it is on, and can show dark patches on slopes at low sun.',
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
                key = 'ray_traced_ao_optin',
                requiresRayTracing = true,
                type = 'toggle',
                default = 0,
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
                    .. 'ground and the units around them (a simple screen-space version). It does nothing while the '
                    .. '"Dynamic Lights" option is not Off: those lights, with shadows, replace it and the two never run together.',
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
        if Supported('ren_RaySunAngle') then
            table.insert(video.items, math.min(position + 2, table.getn(video.items) + 1), {
                title = 'Soft ray-traced shadows',
                key = 'ray_soft_shadows_optin',
                requiresRayTracing = true,
                type = 'toggle',
                default = 0,
                tip = 'With ray-traced shadows on: the sun is a disc, not a point, so shadows are sharp where '
                    .. 'they start and soften further from their caster. Costs several times the hard shadows '
                    .. '(about 10 ms a frame on a Radeon RX 7900 XTX with a few hundred units on screen) and the '
                    .. 'soft edge is grainy.',
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

-- Detailed water (ren_WaterDetail), on Direct3D 12 and Vulkan at high fidelity: on by default.
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
    if video and video.items and Supported('ren_WaterDetail') then
        local position = table.getn(video.items) + 1
        for index, item in ipairs(video.items) do
            if item.key == 'atmosphere' then
                position = index + 1
            end
        end
        table.insert(video.items, position, {
            title = 'Detailed water',
            key = 'water_detail',
            type = 'toggle',
            default = 1,
            tip = 'Direct3D 12 and Vulkan, high fidelity: rolling waves, a sun path and sparkles on the water, clear '
                .. 'shallows and foam at the shore.',
            set = function(key, value, startup)
                ConExecute('ren_WaterDetail ' .. tostring(value))
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

-- Texture filtering (texture_anisotropy), anti-aliasing (fxaa_on), temporal anti-aliasing (taa), sharpening
-- (sharpen_level), colour grading (grade_on), the wide glow (bloom_wide_level), the render scale (render_scale), sun
-- shafts and height fog (atmosphere) and the ray-traced bounce light and water reflections (ray_bounce_optin,
-- ray_water_optin) are Options > Video entries of the render feature registry (src/moho/render/ImageQualityFeatures.cpp, optionslogic.lua), which lists each for the graphics
-- API that is running. The ones that were Lua blocks here keep their option keys and number keys, so saved profiles keep working.

-- Ambient occlusion: the entry (key 'ambient_occlusion') is built from the engine's render feature registry
-- (src/moho/render/AmbientOcclusion.cpp, optionslogic.lua) for the graphics API that runs, one option for every
-- occlusion kernel: Off, Standard (ren_Ao's own, the old On), and the GTAO levels Low, Medium and High. The keys of
-- Off ("0") and Standard ("-1") are the values the old On / Off toggle stored.

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

-- The interface scale without a restart, and following the display (/fafengine/modules/lua/ui/uiscale.lua). FAF's UI
-- Scale entry asked for a restart; here it applies at once. "Match display scale" after it sets UI Scale from the scale
-- of the display the game window is on. Only on an engine that reports that scale (GetDisplayScale).
do
    if rawget(_G, 'GetDisplayScale') then
        local UiScale = import('/fafengine/modules/lua/ui/uiscale.lua')
        for _, tab in options do
            local items = type(tab) == 'table' and tab.items
            if items then
                for index, item in items do
                    if item.key == 'ui_scale' then
                        item.restart = nil
                        item.set = function(key, value, startup)
                            if not startup and type(value) == 'number' then
                                UiScale.OnChosen(value)
                            end
                        end
                        if not HasOptionKey(items, 'ui_scale_auto') then
                            table.insert(items, index + 1, {
                                title = "Match display scale",
                                key = 'ui_scale_auto',
                                type = 'toggle',
                                -- Reset to defaults follows the display; a profile without the setting yet gets
                                -- it from uiscale.lua's StartupScale (on for UI Scale unset or 100 %).
                                default = true,
                                set = function(key, value, startup)
                                    if not startup then
                                        UiScale.OnFollowChosen(value == true)
                                    end
                                end,
                                custom = {
                                    states = {
                                        { text = "<LOC _On>", key = true },
                                        { text = "<LOC _Off>", key = false },
                                    },
                                },
                            })
                        end
                        break
                    end
                end
            end
        end
    end
end

-- Water quality (ren_WaterQuality): the size of the reflection target and the filtered reflection and refraction lookups of the water.
-- It takes effect at once: the water shader patch is always in the effect on the renderers that can run it, the tap counts are shader
-- constants set every frame and the reflection target is made again when its size changes, so changing it needs no restart. Shown only
-- by an engine that has the command, as the ones above.
do
    local command = 'ren_WaterQuality'
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
            if item.key == 'texture_anisotropy' then
                position = index + 1
            end
        end
        -- Option values are levels, so a saved preference never reaches the command as text.
        local levels = { [0] = '0', [1] = '1', [2] = '2', [3] = '3' }
        table.insert(video.items, position, {
            title = 'Water Quality',
            key = 'water_quality',
            type = 'toggle',
            default = 1,
            tip = 'Reflection and refraction of the water. Low draws the mirrored units at half the screen size and filters '
                .. 'their lookup, Medium also filters the refraction and softens the shoreline, High draws the reflection at '
                .. '1.5 times the screen size. Changes apply at once. Off is the shipped look.',
            set = function(key, value, startup)
                ConExecute(command .. ' ' .. (levels[value] or levels[1]))
            end,
            custom = {
                states = {
                    { text = 'Off (shipped)', key = 0 },
                    { text = 'Low (half size)', key = 1 },
                    { text = 'Medium', key = 2 },
                    { text = 'High (1.5x)', key = 3 },
                },
            },
        })
    end
end

-- What the water shows of the scene around it (docs/WATER_REFLECTIONS.md): screen-space reflections and caustics on the sea bed. The water shader
-- patch is always in the effect on the renderers that can run it and both are shader constants set every frame, so they change at once. Shown only
-- by an engine that has the command, as the ones above.
do
    local function Supported(command)
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
    if video and video.items then
        local function Insert(item, afterKey)
            local position = table.getn(video.items) + 1
            for index, other in ipairs(video.items) do
                if other.key == afterKey then
                    position = index + 1
                end
            end
            table.insert(video.items, position, item)
        end

        if Supported('ren_WaterSSR') then
            local values = { [0] = '0', [1] = '1' }
            Insert({
                title = 'Water Reflections',
                key = 'water_reflections',
                type = 'toggle',
                default = 1,
                tip = 'The water reflects the terrain, buildings and units around it (screen-space reflections), not only the sky '
                    .. 'and the mirrored units. Changes apply at once. Off is the shipped look.',
                set = function(key, value, startup)
                    ConExecute('ren_WaterSSR ' .. (values[value] or values[1]))
                end,
                custom = {
                    states = {
                        { text = '<LOC _Off>', key = 0 },
                        { text = '<LOC _On>', key = 1 },
                    },
                },
            }, 'water_quality')
        end

        if Supported('ren_WaterCaustics') then
            local values = { [0] = '0', [1] = '25', [2] = '50', [3] = '100' }
            Insert({
                title = 'Water Caustics',
                key = 'water_caustics',
                type = 'toggle',
                default = 2,
                tip = 'Moving light patterns on the sea bed seen through shallow water. They follow the wave simulation. '
                    .. 'Changes apply at once.',
                set = function(key, value, startup)
                    ConExecute('ren_WaterCaustics ' .. (values[value] or values[2]))
                end,
                custom = {
                    states = {
                        { text = '<LOC _Off>', key = 0 },
                        { text = 'Low', key = 1 },
                        { text = 'Medium', key = 2 },
                        { text = 'High', key = 3 },
                    },
                },
            }, 'water_reflections')
        end
    end
end
