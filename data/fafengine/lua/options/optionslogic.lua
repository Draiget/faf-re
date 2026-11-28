-- Engine hook (data/fafengine, registered as a hook directory): appended to /lua/options/optionslogic.lua.
--
-- The renderer features the engine registers (src/moho/render/RenderFeatures.cpp: dynamic lights, anti-aliasing, ...) get one Options > Video
-- entry each, for the graphics API that is *running*: a feature the API cannot do has no entry, and the levels and the default are the ones
-- that API offers. The options module may be loaded before the device exists (reading the Graphics API option imports it), so the entries
-- are not added when options.lua loads but each time the options data is asked for, as soon as the engine knows the API; they are added once
-- per API. The level is stored as the key of the chosen state and applied to the feature's console variable. Changing the Graphics API needs
-- a restart, after which the list is built for the new API.
--
-- The Lua blocks of options.lua (and FAF's own file) keep working next to the registry: a feature whose key is already an option of the tab
-- (a block of options.lua, or FAF's file) is left out here, so every option shows once and a profile that stores the key keeps working.
do
    local baseGetOptionsData = GetOptionsData
    local syncedApi = nil

    function GetOptionsData()
        local data = baseGetOptionsData()
        if GetRenderFeatures then
            local info = GetRenderFeatures()
            -- The options of the ray-traced shadows (options.lua marks them requiresRayTracing) are listed wherever the engine has the
            -- commands; they do something only on a device that traces rays, so the others are left out once the device is known.
            if info.api ~= '' and not info.rayTracing then
                local video = data and data.video
                if video and video.items then
                    local kept = {}
                    for _, item in video.items do
                        if item.requiresRayTracing then
                            optionItemMap[item.key] = nil
                        else
                            table.insert(kept, item)
                        end
                    end
                    video.items = kept
                end
            end
            if info.api ~= '' and info.api ~= syncedApi then
                syncedApi = info.api
                local video = data and data.video
                if video and video.items then
                    -- drop the entries of an earlier sync, then add the ones of this API after the Graphics API entry
                    local kept = {}
                    for _, item in video.items do
                        if item.renderFeature then
                            optionItemMap[item.key] = nil
                        else
                            table.insert(kept, item)
                        end
                    end
                    video.items = kept
                    local position = table.getn(video.items) + 1
                    for index, item in video.items do
                        if item.key == 'graphics_api' then
                            position = index + 1
                            break
                        end
                    end
                    for _, feature in info.features do
                        if not optionItemMap[feature.key] then
                            local states = {}
                            local levelOfKey = {}
                            for _, state in feature.states do
                                table.insert(states, { text = state.text, key = state.key })
                                levelOfKey[state.key] = state.level
                            end
                            local console = feature.console
                            local item = {
                                title = feature.title,
                                key = feature.key,
                                type = 'toggle',
                                default = feature.default,
                                restart = feature.restart,
                                tip = feature.tip,
                                renderFeature = true,
                                set = function(key, value, startup)
                                    if console and console ~= '' and levelOfKey[value] then
                                        ConExecute(console .. ' ' .. tostring(levelOfKey[value]))
                                    end
                                end,
                                custom = { states = states },
                            }
                            table.insert(video.items, position, item)
                            optionItemMap[feature.key] = item
                            position = position + 1
                        end
                    end
                end
            end
        end
        return data
    end
end
