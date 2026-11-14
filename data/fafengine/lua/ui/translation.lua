-- Local display only. Native worker uses private pipes and offline language packs.
local uid = '02eeb8d2-e873-4dba-88cc-78756b16d2e5'
local pending = {}
local polling = false
local generation = 0
local warned = false

function Reset()
    generation = generation + 1
    pending = {}
end

function Enabled()
    local mods = GetPreference('active_mods', {})
    return mods and mods[uid] and MicrochipQueueTranslation and MicrochipPollTranslations
end

function Translate(text, display)
    if not Enabled() or type(text) ~= 'string' or string.len(text) < 4 then return end
    local count = 0
    for _, item in pending do count = count + 1 end
    if count >= 32 then return end
    local id = MicrochipQueueTranslation(text)
    if not id or id == 0 then return end
    pending[id] = {display = display, generation = generation, expires = GetSystemTimeSeconds() + 35}
    if polling then return end
    polling = true
    ForkThread(function()
        while true do
            WaitSeconds(0.25)
            for _, result in MicrochipPollTranslations() do
                local item = pending[result.id]
                pending[result.id] = nil
                if item and item.generation == generation and item.expires > GetSystemTimeSeconds() then
                    if result.language == 'unavailable' then
                        if not warned then
                            warned = true
                            pcall(item.display, '[Offline translator could not start or respond. Original chat is unaffected.]')
                        end
                    elseif result.text and result.text ~= '' then
                        pcall(item.display, '[English / ' .. string.upper(result.language) .. '] ' .. result.text)
                    end
                end
            end
            local any = false
            for key, item in pending do
                if item.expires <= GetSystemTimeSeconds() then pending[key] = nil
                else any = true end
            end
            if not any then break end
        end
        polling = false
    end)
end
