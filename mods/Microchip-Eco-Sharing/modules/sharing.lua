local Prefs = import('/lua/user/prefs.lua')
local Allocate = import('/mods/Microchip-Eco-Sharing/modules/allocation.lua')
local settings, scores, lastSent = false, {}, {}
local initialized, owner, lastTick = false, false, -1
local lastRoundTick, lastRoundTime = false, false
local status = 'Automatic sharing is off'

function Settings()
    if not settings then
        settings = Prefs.GetFromCurrentProfile('microchip_eco_sharing') or Allocate.Defaults()
        local defaults = Allocate.Defaults()
        for key, value in pairs(defaults) do if settings[key] == nil then settings[key]=value end end
    end
    return settings
end

function Save(value)
    settings=value
    Prefs.SetToCurrentProfile('microchip_eco_sharing', value)
    status = value.enabled and 'Waiting for fresh allied economy data' or 'Automatic sharing is off'
end

function Status() return status end

function SelectionCount(value)
    local count = 0
    for _, ally in ipairs(Allies()) do
        local selected = value.targets[ally.name] or {}
        if selected.MASS or selected.ENERGY then count = count + 1 end
    end
    return count
end

local function Announce(focus, mass, energy, recipients)
    local army = GetArmiesTable().armiesTable[focus]
    local destination = table.getn(recipients) == 1 and recipients[1] or (table.getn(recipients) .. ' allies')
    -- Fractions are processed asynchronously; the normal FAF receipt reports exact amounts received.
    local message = string.format('[Auto-share] Sending about %d mass and %d energy to %s.', mass, energy, destination)
    local ok, problem = pcall(function()
        local chat = import('/lua/ui/game/chat/ChatController.lua')
        SessionSendChatMessage(chat.FindClients(), {from=army.nickname, to='allies', Chat=true, text=message})
    end)
    if not ok then WARN('Microchip Eco Sharing chat: ' .. tostring(problem)) end
end

function Allies()
    local result, focus = {}, GetFocusArmy()
    if focus < 1 or IsObserver() then return result end
    local info = SessionGetScenarioInfo()
    local ratings = info and info.Options and info.Options.Ratings or {}
    for index, army in pairs(GetArmiesTable().armiesTable or {}) do
        if index ~= focus and not army.civilian and not army.outOfGame and IsAlly(focus,index) then
            local rating = tonumber(ratings[army.nickname])
            table.insert(result,{id=index,name=army.nickname or ('Army '..index),colour=army.color or 'ffffffff',rating=rating})
        end
    end
    table.sort(result,function(a,b) return a.id<b.id end)
    return result
end

local function Receive(data)
    local tick, focus = GameTick(), GetFocusArmy()
    if tick < lastTick or owner ~= focus then
        scores={}; lastSent={}; lastRoundTick=false; lastRoundTime=false
    end
    lastTick=tick; owner=focus
    if SessionIsReplay() or IsObserver() or focus < 1 then return end
    -- This table is the same allied economy information the normal scoreboard displays.
    for id, row in pairs(data or {}) do scores[id]={data=row,tick=tick} end
    local current = Settings()
    if not current.enabled then status='Automatic sharing is off'; return end
    if SelectionCount(current) == 0 then
        status='Choose Energy or Mass for at least one ally in ECO.'
        return
    end
    local now = GetSystemTimeSeconds()
    -- One sharing round can include several allies, but rounds never run faster than
    -- three real seconds OR three simulation seconds, including at faster game speeds.
    if lastRoundTick and (tick - lastRoundTick < 30 or now - lastRoundTime < 3) then
        status='Waiting for the three-second sharing interval'
        return
    end
    local allies = Allies()
    local plan = Allocate.Plan(current,GetEconomyTotals(),allies,scores,tick,lastSent)
    local sent, mass, energy, recipients = false, 0, 0, {}
    for _, gift in ipairs(plan) do
        -- Recheck alliance and authority immediately before normal UI callbacks.
        if GetFocusArmy() ~= focus or IsObserver() then break end
        if IsAlly(focus,gift.id) then
            SimCallback({Func='GiveResourcesToPlayer',Args={From=focus,To=gift.id,Mass=gift.Mass,Energy=gift.Energy}},false)
            lastSent[gift.id]=lastSent[gift.id] or {}
            if gift.Mass>0 then lastSent[gift.id].MASS=tick end
            if gift.Energy>0 then lastSent[gift.id].ENERGY=tick end
            status='Shared surplus with '..gift.name
            mass=mass+(gift.MassAmount or 0); energy=energy+(gift.EnergyAmount or 0)
            table.insert(recipients, gift.name)
            sent=true
        end
    end
    if sent then
        lastRoundTick=tick; lastRoundTime=now
        Announce(focus, mass, energy, recipients)
    else
        status='Waiting for surplus above reserves and empty selected allies'
    end
end

function Initialize()
    if initialized then return end
    initialized=true
    Settings()
    AddOnSyncHashedCallback(Receive,'Score','MicrochipEcoSharing')
end

function Stop()
    if initialized then RemoveOnSyncHashedCallback('Score','MicrochipEcoSharing') end
    initialized=false; settings=false; scores={}; lastSent={}; owner=false; lastTick=-1
    lastRoundTick=false; lastRoundTime=false
end
