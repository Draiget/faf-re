-- Reads existing engine diagnostics only. A suspected link is not proof of a bad route.
function New()
    local tracker = {since = {}, keys = {}, last = nil}
    function tracker:Update(clients, now)
        local labels, names, keys, active = {}, {}, {}, {}
        local full = false
        for id, client in pairs(clients or {}) do
            names[id] = tostring(client.name or ('Player ' .. tostring(id)))
            keys[id] = tostring(client.uid or names[id])
            if type(client.fafReNetwork) == 'table' and client.fafReNetwork.version == 1 then full = true end
            active[id] = client.connected and type(client.quiet) == 'number' and client.quiet < 3000
        end
        if now < (self.last or now) then self.since = {} end
        for id, key in pairs(self.keys) do
            if keys[id] ~= key then self.since = {}; break end
        end
        for id, key in pairs(keys) do
            if self.keys[id] ~= key then self.since = {}; break end
        end
        self.keys, self.last = keys, now
        local pending = {}
        for receiver, client in pairs(clients or {}) do
            local data = client.fafReNetwork
            local lowest, highest, count = nil, nil, 0
            if active[receiver] and type(data) == 'table' and data.version == 1
                and type(data.dispatched) == 'number' and data.dispatched > 0
                and type(data.buffers) == 'table' then
                for sender, buffer in pairs(data.buffers) do
                    if sender ~= receiver and active[sender] and type(buffer) == 'number'
                        and buffer == buffer and math.abs(buffer) < 100000 then
                        count = count + 1
                        lowest = lowest and math.min(lowest, buffer) or buffer
                        highest = highest and math.max(highest, buffer) or buffer
                    end
                end
                -- Compare two or more incoming sources. A uniformly slow simulation,
                -- a normal zero buffer, and ping alone do not establish a remote pair.
                if count >= 2 and lowest <= 0 and highest - lowest >= 5 then
                    local waiting = {}
                    for sender, buffer in pairs(data.buffers) do
                        if sender ~= receiver and active[sender] and type(buffer) == 'number'
                            and buffer <= 0 and highest - buffer >= 5 and math.abs(buffer) < 100000 then
                            local key = tostring(receiver) .. ':' .. tostring(sender)
                            pending[key] = self.since[key] or now
                            if now - pending[key] >= 1.5 then
                                table.insert(waiting, {name = names[sender], buffer = buffer})
                            end
                        end
                    end
                    table.sort(waiting, function(a, b)
                        return a.buffer < b.buffer or (a.buffer == b.buffer and a.name < b.name)
                    end)
                    if waiting[1] then
                        labels[receiver] = ' [waits for ' .. string.sub(waiting[1].name, 1, 16) ..
                            (table.getn(waiting) > 1 and (' +' .. tostring(table.getn(waiting) - 1)) or '') .. '?]'
                    end
                end
            end
            if not client['local'] then
                if not client.connected then labels[receiver] = ' [disconnected from you]'
                elseif type(client.quiet) == 'number' and client.quiet >= 3000 then
                    labels[receiver] = ' [no packets to you]'
                elseif not labels[receiver] and type(client.ping) == 'number' and client.ping >= 400 then
                    labels[receiver] = ' [high ping to you]'
                end
            elseif not full then
                labels[receiver] = ' [local links only]'
            end
        end
        self.since = pending
        return labels, full
    end
    return tracker
end
local function Finite(value)
    return type(value) == 'number' and value == value and math.abs(value) < 1000000000
end
function FormatWaitDuration(seconds)
    if not Finite(seconds) or seconds < 0 then return '--' end
    local tenths = math.floor(seconds * 10 + 0.5)
    if tenths < 600 then return string.format('%.1fs', tenths / 10) end
    if tenths < 36000 then return string.format('%d:%04.1f', math.floor(tenths / 600), math.mod(tenths, 600) / 10) end
    return string.format('%d:%02d:%02d', math.floor(tenths / 36000), math.floor(math.mod(tenths, 36000) / 600), math.floor(math.mod(tenths, 600) / 10))
end
function Ranked(clients)
    local rows = {}
    for id, client in pairs(clients or {}) do
        if not client['local'] then
            local data = type(client.fafReNetwork) == 'table' and client.fafReNetwork or {}
            local valid = data.waitVersion == 1 and Finite(data.waitObservedSeconds) and data.waitObservedSeconds > 0
                and Finite(data.waitPercent) and data.waitPercent >= 0 and data.waitPercent <= 100.001
                and Finite(data.longestWaitMs) and data.longestWaitMs >= 0 and data.longestWaitMs <= 30000.001
            local gameValid = Finite(data.gameWaitPercent) and Finite(data.gameWaitSeconds) and data.gameWaitSeconds > 0
                and data.gameWaitPercent >= 0 and data.gameWaitPercent <= 100.001
            table.insert(rows, {id = id, client = client, measured = valid and client.connected,
                percent = valid and data.waitPercent or 0, longest = valid and data.longestWaitMs or 0,
                gamePercent = gameValid and data.gameWaitPercent or nil,
                -- gameWaitSeconds is active match duration, not the peer's wait total.
                -- Recover the cumulative counter from its unrounded engine percentage.
                averageWaitMs = gameValid and Finite(data.gameAverageWaitMs) and data.gameAverageWaitMs >= 0
                    and Finite(data.gameWaitEpisodes) and data.gameWaitEpisodes >= 0 and data.gameAverageWaitMs or nil,
                totalWaitSeconds = gameValid and data.gameWaitSeconds * math.min(100, data.gameWaitPercent) / 100 or nil})
        end
    end
    table.sort(rows, function(a, b)
        if not not a.client.connected ~= not not b.client.connected then return not not a.client.connected end
        if not not a.measured ~= not not b.measured then return not not a.measured end
        if a.measured and a.percent ~= b.percent then return a.percent > b.percent end
        if a.measured and a.longest ~= b.longest then return a.longest > b.longest end
        local an, bn = tostring(a.client.name or ''), tostring(b.client.name or '')
        if an ~= bn then return an < bn end
        return tostring(a.id) < tostring(b.id)
    end)
    return rows
end
return {New = New, Ranked = Ranked, FormatWaitDuration = FormatWaitDuration}
