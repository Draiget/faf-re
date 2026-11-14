-- Pure scoring logic. This measures lobby probe replies, not simulation ticks.
Deadline = 0.5
SampleCount = 240
Interval = 0.25

function New()
    local score = {sent = 0, onTime = 0, pending = {}}
    function score:Send(sequence, now)
        self.sent = self.sent + 1
        self.pending[sequence] = now
    end
    function score:Reply(sequence, now)
        local sent = self.pending[sequence]
        if sent == nil then return end
        self.pending[sequence] = nil
        if now >= sent and now - sent <= Deadline then
            self.onTime = self.onTime + 1
        end
    end
    return score
end

function Worst(reports, player, roster)
    local report = reports[player]
    if type(report) ~= 'table' then return nil, nil, 'Waiting' end
    if report.invalid then return nil, nil, 'Inconclusive: local pause' end
    local worst, other
    for id, name in pairs(roster) do
        if id ~= player then
            local peerReport = reports[id]
            if type(peerReport) == 'table' and peerReport.invalid then
                return nil, nil, 'Inconclusive: peer paused'
            end
            local link = type(report.links) == 'table' and report.links[id]
            if type(link) ~= 'table' or link.sent ~= SampleCount or type(link.onTime) ~= 'number'
                or link.onTime < 0 or link.onTime > link.sent
                or link.onTime ~= math.floor(link.onTime) then
                return nil, nil, 'Incomplete'
            end
            local value = 100 * link.onTime / link.sent
            if worst == nil or value < worst or (value == worst and name < other) then
                worst, other = value, name
            end
        end
    end
    if worst == nil then return nil, nil, 'No opponents' end
    -- Do not present a final score before every peer reports scheduler health.
    for id in pairs(roster) do
        if type(reports[id]) ~= 'table' then return nil, nil, 'Waiting' end
    end
    return worst, other
end

return {New = New, Worst = Worst, Deadline = Deadline, SampleCount = SampleCount, Interval = Interval}
