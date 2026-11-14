-- Pure formatting/state for a passive, local-only multiplayer recorder.
local function Number(value)
    if type(value) == 'number' and value == value and math.abs(value) < 1000000000000 then
        return string.format('%.3f', value)
    end
    return '-'
end
local function Text(value)
    return string.sub(string.gsub(tostring(value or '-'), '[%c"|]', '_'), 1, 80)
end
function New()
    local recorder = {}
    function recorder:Capture(clients, now, tick)
        local elapsed = self.time and now - self.time or nil
        local tps = elapsed and elapsed > 0 and type(tick) == 'number' and type(self.tick) == 'number'
            and tick >= self.tick and (tick - self.tick) / elapsed or nil
        local lines = {'MicrochipNetDiag SAMPLE wall=' .. Number(now) .. ' elapsed=' .. Number(elapsed) ..
            ' tick=' .. Number(tick) .. ' ticks_per_second=' .. Number(tps)}
        self.time, self.tick = now, tick
        local ids = {}
        for id in pairs(clients) do
            if type(id) == 'number' then table.insert(ids, id) end
        end
        table.sort(ids)
        for position, id in ipairs(ids) do
            if position > 32 then break end
            local client = clients[id]
            local data = type(client.fafReNetwork) == 'table' and client.fafReNetwork or {}
            local buffers = {}
            for _, sender in ipairs(ids) do
                if table.getn(buffers) >= 32 then break end
                if type(data.buffers) == 'table' and type(data.buffers[sender]) == 'number' then
                    table.insert(buffers, tostring(sender) .. ':' .. Number(data.buffers[sender]))
                end
            end
            table.insert(lines, 'MicrochipNetDiag PEER id=' .. tostring(id) .. ' engine_index=' .. tostring(id - 1) .. ' name="' .. Text(client.name) ..
                '" local=' .. tostring(client['local'] == true) .. ' connected=' .. tostring(client.connected == true) ..
                ' maxsp=' .. Number(client.maxSP) .. ' ping_ms=' .. Number(client.ping) .. ' quiet_ms=' .. Number(client.quiet) ..
                ' dispatched=' .. Number(data.dispatched) .. ' available=' .. Number(data.available) ..
                ' wait_pct=' .. Number(data.waitPercent) .. ' longest_wait_ms=' .. Number(data.longestWaitMs) ..
                ' observed_seconds=' .. Number(data.waitObservedSeconds) .. ' actual_rate=' .. Number(data.actualRate) .. ' requested_rate=' .. Number(data.requestedRate) ..
                ' bottleneck="' .. Text(data.bottleneck) .. '" buffers=[' .. table.concat(buffers, ',') .. ']')
        end
        return lines
    end
    return recorder
end
return {New = New}
