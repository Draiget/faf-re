-- Connection-probe test over the lobby's actual peer links. All peers need this hook.
local Score = import('/fafengine/lua/ui/lobby/connectionscore.lua')
local UIUtil = import('/lua/ui/uiutil.lua')
local Layout = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Popup = import('/lua/ui/controls/popups/popup.lua').Popup

local comm, host, generation = nil, nil, 0
local capable, greeted, roster, reports = {}, {}, {}, {}
local current, resultToken, reportDeadline, button, checksumButton, popup, body
local messageType = 'FafConnectionTest1'
local receiveLimits, lastStart = {}, -100

local function CleanReport(report)
    if type(report) ~= 'table' or type(report.links) ~= 'table' then return nil end
    local clean = {links = {}, invalid = report.invalid and true or nil}
    for id in pairs(roster) do
        local link = report.links[id]
        if type(link) == 'table' and link.sent == Score.SampleCount
            and type(link.onTime) == 'number' and link.onTime >= 0
            and link.onTime <= Score.SampleCount and link.onTime == math.floor(link.onTime) then
            clean.links[id] = {sent = Score.SampleCount, onTime = link.onTime}
        end
    end
    return clean
end

local function LocalID() return tonumber(comm:GetLocalPlayerID()) end
local function Peers()
    local peers = {}
    for _, peer in pairs(comm:GetPeers()) do
        if peer.status == 'Established' then peers[tonumber(peer.id)] = peer.name end
    end
    peers[LocalID()] = comm:GetLocalPlayerName()
    return peers
end
local function SameRoster(a, b)
    for id, name in pairs(a) do if b[id] ~= name then return false end end
    for id, name in pairs(b) do if a[id] ~= name then return false end end
    return true
end
local function Send(id, action, extra)
    local data = extra or {}
    data.Type, data.action, data.version = messageType, action, 1
    -- A disconnect can race with an echo or report; never interrupt the lobby.
    return pcall(function() comm:SendData(id, data) end)
end
local function Broadcast(action, extra)
    for id in pairs(roster) do
        if id ~= LocalID() then Send(id, action, extra) end
    end
end
local function Summary()
    local names, lines = {}, {}
    for id, name in pairs(roster) do table.insert(names, {id = id, name = name}) end
    table.sort(names, function(a, b) return a.name < b.name end)
    for _, player in ipairs(names) do
        local value, other, reason = Score.Worst(reports, player.id, roster)
        if reason == 'Waiting' and reportDeadline and GetSystemTimeSeconds() > reportDeadline then
            reason = 'Missing report'
        end
        table.insert(lines, player.name .. ': ' .. (value and
            string.format('%.1f%% -> %s', value, other) or reason))
    end
    return table.concat(lines, '\n')
end
local status = 'Host: press Lag Test. Everyone needs the connection-test hook.'
local function Refresh()
    if body then
        if not current and next(reports) then
            local complete = true
            for id in pairs(roster) do if not reports[id] then complete = false end end
            status = complete and 'Test complete.' or
                (reportDeadline and GetSystemTimeSeconds() > reportDeadline and
                    'Incomplete: missing peer reports. Run a fresh test.' or 'Waiting for outstanding peer reports.')
        end
        body:SetText(status .. '\n\n' .. Summary() ..
            '\n\nScore: replies within 500 ms / 240 probes per peer.\n' ..
            'Higher is better. Worst link shown for each player.\n' ..
            'Probe RTT includes both directions and scheduling.\n' ..
            'Not a simulation test or a guarantee of game performance.')
    end
end

local function Begin(token)
    reports, resultToken, reportDeadline = {}, token, nil
    local now = GetSystemTimeSeconds()
    lastStart = now
    current = {token = token, start = now, last = now, next = now,
        sequence = 0, links = {}, received = {}, invalid = nil}
    for id in pairs(roster) do if id ~= LocalID() then current.links[id] = Score.New() end end
    status = 'Testing for about 60 seconds. Keep the game responsive; avoid CPU benchmarks.'
    Refresh()
end

local function Start()
    if not comm:IsHost() then status = 'Only the host can start the test.'; Refresh(); return end
    if current then return end
    if GetSystemTimeSeconds() - lastStart < 65 then
        status = 'Please wait before starting another test.'; Refresh(); return
    end
    roster, reports = Peers(), {}
    local count = 0
    for id, name in pairs(roster) do
        count = count + 1
        if id ~= LocalID() and not capable[id] then
            status = 'Cannot test: ' .. name .. ' has not advertised this test hook.'
            Refresh(); return
        end
    end
    if count < 2 then status = 'At least two connected players are needed.'; Refresh(); return end
    generation = generation + 1
    local token = tostring(LocalID()) .. ':' .. tostring(GetSystemTimeSeconds()) .. ':' .. generation
    Broadcast('start', {token = token})
    Begin(token)
end

function Show(parent, anchor)
    if button and not IsDestroyed(button) then button:Destroy() end
    if checksumButton and not IsDestroyed(checksumButton) then checksumButton:Destroy() end
    if popup and IsDestroyed(popup) then popup, body = nil, nil end
    local checksums = GetPreference('microchip_extra_checksums', true) ~= false
    local function ApplyChecksums()
        ConExecute('net_CheckOrderStreams ' .. (checksums and '1' or '0'))
        -- Extra ACK digests exceed the original 2 KB/s budget in large lobbies.
        if checksums then ConExecute('net_MaxSendRate 8192') end
        LOG('Microchip lobby: extra checksums ' .. (checksums and 'on; send limit 8192 bytes/sec' or 'off'))
    end
    ApplyChecksums()
    button = UIUtil.CreateButtonStd(parent, '/BUTTON/medium/', 'Lag Test', 12)
    Layout.SetDimensions(button, 130, 32)
    if anchor then
        Layout.AtHorizontalCenterIn(button, anchor:GetParent())
        button.Top:Set(function() return anchor.Bottom() + 4 end)
    else
        Layout.AtRightTopIn(button, parent, 25, 45)
    end
    Layout.DepthOverParent(button, parent, 100)
    checksumButton = UIUtil.CreateButtonStd(parent, '/BUTTON/medium/', checksums and 'Checksums: On' or 'Checksums: Off', 12)
    Layout.SetDimensions(checksumButton, 130, 32)
    if anchor then
        Layout.AtHorizontalCenterIn(button, anchor:GetParent(), -69)
        Layout.AtHorizontalCenterIn(checksumButton, anchor:GetParent(), 69)
        checksumButton.Top:Set(function() return anchor.Bottom() + 4 end)
    else
        Layout.AtRightTopIn(checksumButton, parent, 163, 45)
    end
    Layout.DepthOverParent(checksumButton, parent, 100)
    checksumButton.OnClick = function()
        checksums = not checksums
        SetPreference('microchip_extra_checksums', checksums)
        ApplyChecksums()
        checksumButton.label:SetText(checksums and 'Checksums: On' or 'Checksums: Off')
    end
    button.OnClick = function()
        if popup then popup:Destroy(); popup = nil; body = nil end
        local content = Group(parent)
        content.Width:Set(640); content.Height:Set(600)
        local title = UIUtil.CreateText(content, 'Connection score - worst peer link', 18, UIUtil.titleFont)
        Layout.AtLeftTopIn(title, content, 20, 15)
        body = import('/lua/ui/controls/textarea.lua').TextArea(content, 600, 480)
        body:SetFont(UIUtil.bodyFont, 14)
        Layout.AtLeftTopIn(body, content, 20, 55)
        local run = UIUtil.CreateButtonStd(content, '/BUTTON/medium/', 'Lag Test', 12)
        Layout.SetDimensions(run, 130, 32)
        Layout.AtLeftBottomIn(run, content, 20, 15)
        run.OnClick = Start
        local close = UIUtil.CreateButtonStd(content, '/BUTTON/medium/', 'Close', 12)
        Layout.SetDimensions(close, 130, 32)
        Layout.AtRightBottomIn(close, content, 20, 15)
        popup = Popup(parent, content)
        local function Close() popup:Destroy(); popup = nil; body = nil end
        close.OnClick = Close
        popup.OnEscapePressed = Close
        popup.OnShadowClicked = Close
        if not current then roster = Peers() end
        Refresh()
    end
end

function Attach(connection)
    if comm == connection then return end
    comm, host, capable, greeted, reports, roster, current, resultToken, reportDeadline = connection, nil, {}, {}, {}, {}, nil, nil, nil
    receiveLimits, lastStart = {}, -100
    local this = comm
    local oldHosting, oldConnected = comm.Hosting, comm.ConnectionToHostEstablished
    comm.Hosting = function(self)
        host = LocalID()
        oldHosting(self)
    end
    comm.ConnectionToHostEstablished = function(self, localId, localName, hostId)
        host = tonumber(hostId)
        oldConnected(self, localId, localName, hostId)
    end
    local oldReceive = comm.DataReceived
    comm.DataReceived = function(self, data)
        if data.Type ~= messageType then return oldReceive(self, data) end
        local sender = tonumber(data.SenderID)
        if data.version ~= 1 or not sender then return end
        local now = GetSystemTimeSeconds()
        local limit = receiveLimits[sender]
        if not limit or now - limit.start >= 1 then
            limit = {start = now, count = 0}; receiveLimits[sender] = limit
        end
        limit.count = limit.count + 1
        if limit.count > 32 or not Peers()[sender] then return end
        if data.action == 'hello' then
            if capable[sender] then return end
            capable[sender] = true
            Send(sender, 'helloReply')
        elseif data.action == 'helloReply' then capable[sender] = true
        elseif data.action == 'start' and sender == host and type(data.token) == 'string'
            and string.len(data.token) < 100 and not current
            and data.token ~= resultToken and now - lastStart >= 65 then
            roster = Peers()
            Begin(data.token)
        elseif current and data.token == current.token and roster[sender] then
            if data.action == 'probe' and type(data.sequence) == 'number'
                and data.sequence >= 1 and data.sequence <= Score.SampleCount
                and data.sequence == math.floor(data.sequence) then
                local received = current.received[sender] or {}
                current.received[sender] = received
                if received[data.sequence] then return end
                received[data.sequence] = true
                Send(sender, 'echo', {token = data.token, sequence = data.sequence})
            elseif data.action == 'echo' and current.links[sender] then
                current.links[sender]:Reply(data.sequence, GetSystemTimeSeconds())
            elseif data.action == 'report' and type(data.report) == 'table' and not reports[sender] then
                -- Only the engine-authenticated sender can provide its own row.
                reports[sender] = CleanReport(data.report)
            end
        elseif not current and data.action == 'report' and type(data.report) == 'table'
            and roster[sender] and not reports[sender] and data.token == resultToken then
            reports[sender] = CleanReport(data.report)
        end
        Refresh()
    end
    local oldDestroy = comm.Destroy
    comm.Destroy = function(self)
        if button then button:Destroy(); button = nil end
        if popup then popup:Destroy(); popup = nil; body = nil end
        comm, current = nil, nil
        oldDestroy(self)
    end
    ForkThread(function()
        while comm == this do
            local peers, now = Peers(), GetSystemTimeSeconds()
            for id in pairs(peers) do
                if id ~= LocalID() and not greeted[id] then greeted[id] = true; Send(id, 'hello') end
            end
            if current then
                if not SameRoster(peers, roster) then
                    current, resultToken, reportDeadline = nil, nil, nil; reports = {}; status = 'Lobby changed. Run a fresh test.'
                else
                    -- Local scheduling stalls contaminate RTT; never blame a route for them.
                    if now - current.last > 0.2 then current.invalid = 'Inconclusive: local pause' end
                    current.last = now
                    if now >= current.next and current.sequence < Score.SampleCount then
                        current.sequence = current.sequence + 1
                        current.next = now + Score.Interval
                        for id, score in pairs(current.links) do
                            score:Send(current.sequence, now)
                            Send(id, 'probe', {token = current.token, sequence = current.sequence})
                        end
                    elseif current.sequence == Score.SampleCount and now >= current.next + Score.Deadline then
                        local report = {links = {}, invalid = current.invalid}
                        for id, score in pairs(current.links) do
                            report.links[id] = {sent = score.sent, onTime = score.onTime}
                        end
                        reports[LocalID()] = report
                        reportDeadline = now + 5
                        Broadcast('report', {token = current.token, report = report})
                        current = nil
                        status = 'Test complete. Waiting for any outstanding peer reports.'
                    end
                end
                Refresh()
            elseif not SameRoster(peers, roster) and next(reports) then
                reports, roster, resultToken, reportDeadline = {}, peers, nil, nil
                status = 'Lobby changed. Results cleared; run a fresh test.'
                Refresh()
            end
            for id in pairs(greeted) do
                if not peers[id] then greeted[id], capable[id], receiveLimits[id] = nil, nil, nil end
            end
            if not current and reportDeadline then Refresh() end
            WaitSeconds(0.05)
        end
    end)
end
