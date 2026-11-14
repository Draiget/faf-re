-- Pure allocation logic. Values are resource units; callback fractions are calculated last.
function Defaults()
    return {enabled=false, energyReserve=75, massReserve=60, mode='Equal', targets={}, order={}}
end

local function Number(value)
    -- The game's Lua 5.0 has no math.huge. NaN and infinities fail this subtraction check.
    return type(value) == 'number' and value == value and value - value == 0
end

function Ordered(allies, override)
    local result, positions = {}, {}
    for i, name in ipairs(override or {}) do positions[name] = i end
    for _, ally in ipairs(allies) do table.insert(result, ally) end
    table.sort(result, function(a,b)
        local ap, bp = positions[a.name], positions[b.name]
        if ap or bp then
            if not ap then return false end
            if not bp then return true end
            if ap ~= bp then return ap < bp end
        end
        local ar, br = a.rating or -1e30, b.rating or -1e30
        if ar ~= br then return ar > br end
        return a.id < b.id
    end)
    return result
end

-- Allocate only to selected allies whose current, visible storage bar is empty.
-- Equal mode redistributes shares that a small receiver cannot store.
function Plan(settings, own, allies, scores, tick, lastSent)
    local result = {}
    if not settings.enabled or not own or not own.stored or not own.maxStorage then return result end
    local ordered = Ordered(allies, settings.order)
    for _, resource in ipairs({'Energy','Mass'}) do
        local key = string.upper(resource)
        local stored, capacity = own.stored[key], own.maxStorage[key]
        local reserve = settings[string.lower(resource)..'Reserve']
        if Number(stored) and Number(capacity) and capacity > 0 and stored > 0 and Number(reserve) then
            -- One unit of headroom also prevents tiny fractional gift spam at the threshold.
            local budget = math.max(0, stored - capacity * math.max(0,math.min(100,reserve))/100 - 1)
            local eligible = {}
            for _, ally in ipairs(ordered) do
                local target = settings.targets[ally.name] or {}
                local snapshot = scores[ally.id]
                local storage = snapshot and snapshot.data and snapshot.data.resources and snapshot.data.resources.storage
                local last = lastSent[ally.id] and lastSent[ally.id][key]
                local current, maximum = storage and storage['stored'..resource], storage and storage['max'..resource]
                if target[key] and snapshot and tick >= snapshot.tick and tick - snapshot.tick <= 30
                    and (not last or tick - last >= 30) and Number(current) and Number(maximum)
                    and current >= 0 and current <= 1 and maximum > current then
                    table.insert(eligible, {ally=ally, room=maximum-current, amount=0})
                end
            end
            if settings.mode == 'Rank' then
                for _, entry in ipairs(eligible) do
                    entry.amount = math.min(budget,entry.room)
                    budget = budget-entry.amount
                end
            else
                local active = eligible
                while budget >= 1 and table.getn(active) > 0 do
                    local share, remaining = budget/table.getn(active), {}
                    for _, entry in ipairs(active) do
                        local amount = math.min(share,entry.room-entry.amount)
                        entry.amount = entry.amount+amount; budget=budget-amount
                        if entry.room-entry.amount > 0.001 then table.insert(remaining,entry) end
                    end
                    active = remaining
                end
            end
            -- A gift is a fraction of what is currently stored, not of storage capacity.
            -- Each subsequent callback sees the resource already removed by previous gifts.
            local remaining = stored
            for _, entry in ipairs(eligible) do
                local amount = math.floor(entry.amount)
                if amount >= 1 then
                    local gift = result[entry.ally.id] or {id=entry.ally.id, name=entry.ally.name, Mass=0,Energy=0}
                    gift[resource] = amount/remaining
                    gift[resource..'Amount'] = amount
                    result[entry.ally.id] = gift
                    remaining = remaining-amount
                end
            end
        end
    end
    -- Keep the dispatch order identical to the order used for sequential fractions above.
    local list = {}
    for _, ally in ipairs(ordered) do if result[ally.id] then table.insert(list,result[ally.id]) end end
    return list
end
