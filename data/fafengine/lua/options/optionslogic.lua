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
                    local function PositionAfter(key)
                        for index, item in video.items do
                            if item.key == key then
                                return index + 1
                            end
                        end
                        return nil
                    end
                    -- A feature is listed after the entry it names (a neighbour from FAF's file or another feature,
                    -- which is placed first when it is part of this list too). One that names none, or whose
                    -- neighbour is not on this tab, goes after the Graphics API entry, in the order the features
                    -- were registered, each after the last one placed that way.
                    local fallbackKey = 'graphics_api'
                    local function Place(feature)
                        if not optionItemMap[feature.key] then
                            local position = (feature.after ~= '' and PositionAfter(feature.after))
                            if not position then
                                position = PositionAfter(fallbackKey) or PositionAfter('graphics_api')
                                    or (table.getn(video.items) + 1)
                                fallbackKey = feature.key
                            end
                            -- The value a state sends to the console variable (the level when it names none), and
                            -- the keys a profile stores as numbers (options that existed before the registry). A
                            -- feature with numericKeys has only numbers; otherwise a key that is a whole number
                            -- ("0", "-1" of the ambient occlusion entry, which the old On / Off toggle stored as
                            -- numbers) is a number too, the others stay text.
                            local numeric = feature.numericKeys
                            local function KeyOf(text)
                                if numeric then
                                    return tonumber(text)
                                end
                                local number = tonumber(text)
                                if number ~= nil and tostring(number) == text then
                                    return number
                                end
                                return text
                            end
                            local states = {}
                            local valueOfKey = {}
                            for _, state in feature.states do
                                table.insert(states, { text = state.text, key = KeyOf(state.key) })
                                if state.value ~= '' then
                                    valueOfKey[KeyOf(state.key)] = state.value
                                else
                                    valueOfKey[KeyOf(state.key)] = tostring(state.level)
                                end
                            end
                            local console = feature.console
                            local item = {
                                title = feature.title,
                                key = feature.key,
                                type = 'toggle',
                                default = KeyOf(feature.default),
                                restart = feature.restart,
                                tip = feature.tip,
                                renderFeature = true,
                                set = function(key, value, startup)
                                    -- a profile written while such a key was text ("0") still selects its state
                                    local send = valueOfKey[value]
                                    if send == nil and type(value) == 'string' and tonumber(value) ~= nil then
                                        send = valueOfKey[tonumber(value)]
                                    end
                                    if console and console ~= '' and send then
                                        ConExecute(console .. ' ' .. send)
                                    end
                                end,
                                custom = { states = states },
                            }
                            table.insert(video.items, position, item)
                            optionItemMap[feature.key] = item
                        end
                    end
                    local pending = info.features
                    while table.getn(pending) > 0 do
                        local waiting = {}
                        for _, feature in pending do
                            local anchorPending = false
                            if feature.after ~= '' and not PositionAfter(feature.after) then
                                for _, other in pending do
                                    if other.key == feature.after and other.key ~= feature.key then
                                        anchorPending = true
                                    end
                                end
                            end
                            if anchorPending then
                                table.insert(waiting, feature)
                            else
                                Place(feature)
                            end
                        end
                        if table.getn(waiting) == table.getn(pending) then
                            -- features that name each other: list them in registration order
                            for _, feature in waiting do
                                Place(feature)
                            end
                            waiting = {}
                        end
                        pending = waiting
                    end
                end
            end
        end
        return data
    end
end
