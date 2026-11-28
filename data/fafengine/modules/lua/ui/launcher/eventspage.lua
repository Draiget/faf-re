-- The launcher's Events page (under News): FAF's calendar from three sources, as the FAF Rust client merges them
-- (ui/src/features/events at 70c88a5): the community events catalogue (FafLibrary_Events: that client's published
-- calendar.json, one-off and repeating entries people add by a reviewed GitHub issue), FAF's tournaments (the API's
-- Challonge list) and FAF's game patches (the patch notes' dates). Three views: what's coming (a list), a week and a
-- month, each in this computer's time zone; the chosen day's or event's details on the right. "Suggest an event"
-- fills in a catalogue entry and opens it as a prefilled issue in the browser, where the player sends it themselves:
-- the launcher posts nothing in anyone's name.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local Kit = import('/fafengine/modules/lua/ui/launcher/kit.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kViews = { { 'upcoming', 'Coming up' }, { 'week', 'Week' }, { 'month', 'Month' } }
local kWeekdays = { 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' }
local kMonths = { 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
    'November', 'December' }
-- Categories as the catalogue spells them, with the name and colour players see.
local kCategories = {
    tournament = { 'Tournament', C.gold },
    patch = { 'Game update', C.accent },
    cgn = { 'Casted game night', 'ffc792ea' },
    meetup = { 'Meetup', C.good },
    ladderPool = { 'Ladder pool', 'ff7fb4ff' },
    other = { 'Other', C.muted },
}
local kCategoryOrder = { 'meetup', 'cgn', 'tournament', 'patch', 'ladderPool', 'other' }
local kUpcomingDays = 60
local kChipsPerCell = 3

------------------------------------------------------------------------------------------------------------------------
-- Dates: day numbers since 1970-01-01 (days_from_civil, H. Hinnant), weekdays from Monday.

function DaysFromCivil(y, m, d)
    if m <= 2 then
        y = y - 1
    end
    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local mp = m > 2 and (m - 3) or (m + 9)
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    return era * 146097 + doe - 719468
end

function CivilFromDays(z)
    z = z + 719468
    local era = math.floor(z / 146097)
    local doe = z - era * 146097
    local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
    local y = yoe + era * 400
    local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
    local mp = math.floor((5 * doy + 2) / 153)
    local d = doy - math.floor((153 * mp + 2) / 5) + 1
    local m = mp < 10 and (mp + 3) or (mp - 9)
    if m <= 2 then
        y = y + 1
    end
    return y, m, d
end

--- 1 (Monday) to 7 (Sunday).
function Weekday(day)
    return math.mod(math.mod(day + 3, 7) + 7, 7) + 1
end

local function DayText(day)
    local y, m, d = CivilFromDays(day)
    return string.format('%04d-%02d-%02d', y, m, d)
end

--- "Sat 5 Dec 2026": the list's short form.
local function ShortDay(day)
    local y, m, d = CivilFromDays(day)
    return kWeekdays[Weekday(day)] .. ' ' .. d .. ' ' .. string.sub(kMonths[m], 1, 3) .. ' ' .. y
end

local function LongDay(day)
    local y, m, d = CivilFromDays(day)
    return kWeekdays[Weekday(day)] .. ' ' .. d .. ' ' .. kMonths[m] .. ' ' .. y
end

--- A catalogue time: { day = UTC day number, minute = minutes into that day } for a moment ("2026-09-12T18:00:00Z",
--- "+02:00" offsets too), or { day = day number } for a bare date ("2026-09-12"); nil for anything else. Never seconds
--- since 1970: the game's Lua numbers are 32-bit floats, which hold those only to about two minutes.
function ParseTime(text)
    if type(text) ~= 'string' then
        return nil
    end
    local _, _, y, m, d, rest = string.find(text, '^(%d%d%d%d)%-(%d%d)%-(%d%d)(.*)$')
    if not y then
        return nil
    end
    local day = DaysFromCivil(tonumber(y), tonumber(m), tonumber(d))
    if rest == '' then
        return { day = day }
    end
    local _, _, hh, mi, ss, zone = string.find(rest, '^[T ](%d%d):(%d%d):?(%d*)%.?%d*(.*)$')
    if not hh then
        return { day = day }
    end
    local minute = tonumber(hh) * 60 + tonumber(mi)
    local _, _, sign, oh, om = string.find(zone or '', '^([%+%-])(%d%d):?(%d%d)$')
    if sign then
        local offset = tonumber(oh) * 60 + tonumber(om)
        minute = minute + (sign == '+' and -offset or offset)
    end
    day = day + math.floor(minute / 1440)
    minute = minute - math.floor(minute / 1440) * 1440
    return { day = day, minute = minute }
end

--- A UTC moment {day, minute} as FAF's API writes one.
local function Iso(moment)
    return string.format('%sT%02d:%02d:00Z', DayText(moment.day), math.floor(moment.minute / 60),
        math.mod(moment.minute, 60))
end

--- A UTC moment in this computer's time zone: its day number and "HH:MM" (summer time as on that day).
local function Local(moment)
    local text = rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(Iso(moment)) or ''
    local _, _, y, m, d, clock = string.find(text, '^(%d+)%-(%d+)%-(%d+) (%d+:%d+)')
    if y then
        return DaysFromCivil(tonumber(y), tonumber(m), tonumber(d)), clock
    end
    return moment.day, string.format('%02d:%02d', math.floor(moment.minute / 60), math.mod(moment.minute, 60))
end

--- Today's day number here.
local function Today()
    local now = rawget(_G, 'FafLibrary_UtcNow') and FafLibrary_UtcNow()
    -- A float of seconds is good to a couple of minutes: enough to name the day.
    local text = now and rawget(_G, 'FafLibrary_LocalTime') and FafLibrary_LocalTime(now) or ''
    local _, _, y, m, d = string.find(text, '^(%d+)%-(%d+)%-(%d+)')
    if y then
        return DaysFromCivil(tonumber(y), tonumber(m), tonumber(d))
    end
    local utc = ParseTime(rawget(_G, 'FafLibrary_UtcDate') and FafLibrary_UtcDate(0) or '1970-01-01')
    return utc and utc.day or 0
end

--- This computer's offset from UTC in minutes on `day` (noon UTC of that day, so summer time counts).
local function Offset(day)
    local localDay, clock = Local({ day = day, minute = 720 })
    local _, _, hh, mi = string.find(clock or '', '(%d+):(%d+)')
    if not hh then
        return 0
    end
    return (localDay - day) * 1440 + tonumber(hh) * 60 + tonumber(mi) - 720
end

------------------------------------------------------------------------------------------------------------------------
-- The entries and their occurrences.

local function Category(name)
    return kCategories[name] and name or 'other'
end

--- Catalogue entries as the page keeps them: id, title, summary, category, origin, host, start (ParseTime), finish,
--- recurrence ('weekly' with interval, 'monthly' or nil), untilDay, links {{label, url}}, source.
local function FromCatalogue(doc)
    local list = {}
    for _, raw in (type(doc) == 'table' and doc.events) or {} do
        local start = type(raw) == 'table' and type(raw.title) == 'string' and raw.title ~= '' and ParseTime(raw.startsAt)
        if start then
            local entry = { id = 'catalogue:' .. tostring(raw.id or raw.title), title = raw.title,
                summary = type(raw.summary) == 'string' and raw.summary or '', category = Category(raw.category),
                origin = raw.origin == 'official' and 'official' or 'community',
                host = type(raw.host) == 'string' and raw.host or '', start = start, finish = ParseTime(raw.endsAt),
                links = {}, source = 'catalogue' }
            if raw.allDay == true and start.minute then
                entry.start = { day = (Local(start)) }
            end
            if raw.recurrence == 'monthly' then
                entry.recurrence = 'monthly'
            elseif type(raw.recurrence) == 'table' and type(raw.recurrence.weekly) == 'table' then
                entry.recurrence = 'weekly'
                entry.interval = math.max(1, math.floor(tonumber(raw.recurrence.weekly.interval) or 1))
            end
            local untilTime = ParseTime(raw.recursUntil)
            if untilTime then
                entry.untilDay = untilTime.minute and (Local(untilTime)) or untilTime.day
            end
            for _, link in (type(raw.links) == 'table' and raw.links) or {} do
                if type(link) == 'table' and type(link.url) == 'string' and string.find(link.url, '^https://%S+$') then
                    table.insert(entry.links, { label = type(link.label) == 'string' and link.label ~= '' and link.label or
                        'Open', url = link.url })
                end
            end
            table.insert(list, entry)
        end
    end
    return list
end

--- The occurrences of an entry here in [from, to]: { {day = local day number, clock = "HH:MM" or nil}, ... }. A
--- repeating entry repeats on its own (UTC) calendar; each occurrence is turned into local time on its own, so summer
--- time moves its clock and not its day.
local function Days(entry, from, to)
    local list = {}
    local last = entry.untilDay and math.min(to, entry.untilDay) or to
    local function Add(utcDay)
        local day, clock
        if entry.start.minute then
            day, clock = Local({ day = utcDay, minute = entry.start.minute })
        else
            day = utcDay
        end
        if day >= from and day <= last then
            table.insert(list, { day = day, clock = clock })
        end
    end
    local first = entry.start.day
    if entry.recurrence == 'weekly' then
        local step = 7 * entry.interval
        local d = first
        if d < from - 1 then
            d = first + math.floor((from - 1 - first) / step) * step
        end
        while d <= last + 1 do
            if d >= first then
                Add(d)
            end
            d = d + step
        end
    elseif entry.recurrence == 'monthly' then
        local _, _, dom = CivilFromDays(first)
        local y, m = CivilFromDays(math.max(first, from - 1))
        while true do
            local d = DaysFromCivil(y, m, dom)
            local _, mm = CivilFromDays(d)
            if d > last + 1 then
                break
            end
            if mm == m and d >= first then -- the 31st skips a month without one
                Add(d)
            end
            m = m + 1
            if m > 12 then
                m, y = 1, y + 1
            end
        end
    else
        Add(first)
    end
    return list
end

------------------------------------------------------------------------------------------------------------------------
-- Suggesting an event: the Rust client's catalogue entry and issue (eventSubmission.ts), filled in here.

local function Json(value)
    if type(value) == 'table' then
        if value[1] ~= nil then
            local parts = {}
            for _, item in value do
                table.insert(parts, Json(item))
            end
            return '[' .. table.concat(parts, ', ') .. ']'
        end
        local parts = {}
        for _, key in value.__order or {} do
            if value[key] ~= nil then
                table.insert(parts, '"' .. key .. '": ' .. Json(value[key]))
            end
        end
        return '{ ' .. table.concat(parts, ', ') .. ' }'
    elseif type(value) == 'string' then
        local text = string.gsub(value, '\\', '\\\\')
        text = string.gsub(text, '"', '\\"')
        text = string.gsub(text, '\n', '\\n')
        return '"' .. text .. '"'
    elseif type(value) == 'boolean' then
        return value and 'true' or 'false'
    end
    return tostring(value)
end

local function UrlEncode(text)
    return (string.gsub(text, '([^%w%-%._~])', function(c) return string.format('%%%02X', string.byte(c)) end))
end

--- What's wrong with a suggestion, or nil; and its catalogue entry.
function Entry(draft)
    local title = string.gsub(draft.title or '', '^%s*(.-)%s*$', '%1')
    if title == '' then
        return 'Give the event a title.'
    end
    local date = ParseTime(draft.day or '')
    if not date or not date.day or not string.find(draft.day, '^%d%d%d%d%-%d%d%-%d%d$') then
        return 'Give its date as year-month-day, 2026-12-05.'
    end
    local function Clock(text)
        local _, _, hh, mi = string.find(text or '', '^(%d%d?):(%d%d)$')
        if hh and tonumber(hh) < 24 and tonumber(mi) < 60 then
            return tonumber(hh) * 3600 + tonumber(mi) * 60
        end
        return nil
    end
    local start = draft.time ~= '' and Clock(draft.time) or nil
    if draft.time ~= '' and not start then
        return 'Give the time as hours:minutes, 19:30.'
    end
    local finish = draft.endTime ~= '' and Clock(draft.endTime) or nil
    if draft.endTime ~= '' and (not start or not finish or finish <= start) then
        return 'The end comes after the start, on the same day.'
    end
    if draft.url ~= '' and not string.find(draft.url, '^https://%S+$') then
        return 'A link starts with https://.'
    end
    local offset = Offset(date.day)
    local function Utc(seconds)
        local minute = math.floor(seconds / 60) - offset
        local day = date.day + math.floor(minute / 1440)
        minute = minute - math.floor(minute / 1440) * 1440
        return Iso({ day = day, minute = minute })
    end
    local slug = string.gsub(string.lower(title), '[^a-z0-9]+', '-')
    slug = string.gsub(string.gsub(slug, '^%-+', ''), '%-+$', '')
    local entry = { __order = { 'id', 'title', 'category', 'origin', 'startsAt', 'summary', 'host', 'endsAt', 'allDay',
        'recurrence', 'links' }, id = slug ~= '' and (slug .. '-' .. draft.day) or draft.day, title = title,
        category = draft.category, origin = 'community', startsAt = start and Utc(start) or draft.day }
    local summary = string.gsub(draft.summary or '', '%s+', ' ')
    summary = string.gsub(summary, '^ (.-) ?$', '%1')
    if summary ~= '' then
        entry.summary = string.sub(summary, 1, 280)
    end
    if draft.host ~= '' then
        entry.host = draft.host
    end
    if finish then
        entry.endsAt = Utc(finish)
    end
    if not start then
        entry.allDay = true
    end
    if draft.repeats == 'weekly' or draft.repeats == 'fortnightly' then
        entry.recurrence = { __order = { 'weekly' }, weekly = { __order = { 'interval' },
            interval = draft.repeats == 'weekly' and 1 or 2 } }
    elseif draft.repeats == 'monthly' then
        entry.recurrence = 'monthly'
    end
    if draft.url ~= '' then
        entry.links = { { __order = { 'label', 'url' }, label = 'Open', url = draft.url } }
    end
    return nil, entry
end

--- The prefilled issue's address for an entry, on the catalogue's submit page; nil when that isn't a GitHub one.
function IssueUrl(submitUrl, draft, entry)
    local base = string.gsub(string.gsub(submitUrl or '', '/choose/?$', ''), '/$', '')
    if not string.find(base, '^https://github%.com/[%w%.%-_]+/[%w%.%-_]+/issues/new$') then
        return nil
    end
    local times = entry.allDay and 'This is a whole-day entry.' or ('Local time as entered: ' .. draft.day .. ' ' ..
        draft.time .. (draft.endTime ~= '' and (' to ' .. draft.endTime) or '') .. '.')
    local body = 'Submitted from the FAForever client. The block below is the catalogue entry;\n' ..
        'the bot commits it as it stands, so edit the block rather than the prose.\n\nTimes are UTC. ' .. times ..
        '\n\n```json\n' .. Json(entry) .. '\n```'
    return base .. '?title=' .. UrlEncode('Event: ' .. entry.title) .. '&body=' .. UrlEncode(body) .. '&labels=event'
end

------------------------------------------------------------------------------------------------------------------------
-- The page.

local function Chip(parent, view)
    local chip = Theme.Panel(parent, 'ff0d2130', C.line)
    LayoutHelpers.SetHeight(chip, 20)
    chip.bar = Theme.Rect(chip, C.accent)
    chip.bar.Left:Set(chip.Left)
    chip.bar.Top:Set(chip.Top)
    chip.bar.Bottom:Set(chip.Bottom)
    chip.bar.Width:Set(Scale(3))
    chip.bar:DisableHitTest()
    chip.label = Theme.Cell(chip, 11, C.text)
    chip.label.Left:Set(function() return chip.Left() + Scale(8) end)
    chip.label.Right:Set(function() return chip.Right() - Scale(4) end)
    LayoutHelpers.AtVerticalCenterIn(chip.label, chip)
    chip.Set = function(self, occurrence)
        self.occurrence = occurrence
        Theme.SetVisible(self, occurrence ~= nil)
        if occurrence then
            local color = kCategories[occurrence.entry.category][2]
            self.bar:SetSolidColor(color)
            self.label:SetText((occurrence.clock and (occurrence.clock .. '  ') or '') .. occurrence.entry.title)
            local chosen = view.chosen and view.chosen.key == occurrence.key
            self:SetColors(chosen and C.selected or 'ff0d2130', chosen and C.accent or Theme.WithAlpha(color, 0.35))
        end
    end
    Theme.HitArea(chip, function(self, event)
        if event.Type == 'ButtonPress' and event.Modifiers.Left and chip.occurrence then
            Theme.ClickSound()
            view.chosen = chip.occurrence
            view.day = chip.occurrence.day
            view:Paint()
            return true
        end
        return false
    end).Depth:Set(function() return chip.Depth() + 40 end)
    return chip
end

function Build(launcher, page)
    local view = { mode = 'upcoming', jobs = {}, entries = {}, sources = {} }
    launcher.eventsView = view
    local today = Today()
    view.today = today
    view.day = today
    view.anchor = today

    local title = Theme.Title(page, 'Events', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    view.tabs = Widgets.Tabs(page, kViews, function(key)
        view.mode = key
        view.anchor = view.day
        view:Paint()
    end)
    view.tabs.Left:Set(function() return title.Right() + Scale(40) end)
    LayoutHelpers.AtTopIn(view.tabs, page, 0)
    view.tabs.Right:Set(function() return page.Right() - Scale(560) end)
    view.suggest = Theme.Button(page, 'Suggest an event', function() view:Suggest() end, 'secondary',
        { icon = 'plus', width = 190 })
    view.suggest.Right:Set(page.Right)
    LayoutHelpers.AtTopIn(view.suggest, page, 2)
    view.next = Theme.Button(page, '', function() view:Move(1) end, 'ghost', { icon = 'chevronRight', width = 40 })
    view.next.Right:Set(function() return view.suggest.Left() - Scale(18) end)
    view.next.Top:Set(view.suggest.Top)
    view.todayButton = Theme.Button(page, 'Today', function()
        view.day = view.today
        view.anchor = view.today
        view.chosen = nil
        view:Paint()
    end, 'secondary', { width = 90 })
    view.todayButton.Right:Set(function() return view.next.Left() - Scale(6) end)
    view.todayButton.Top:Set(view.suggest.Top)
    view.prev = Theme.Button(page, '', function() view:Move(-1) end, 'ghost', { icon = 'arrowLeft', width = 40 })
    view.prev.Right:Set(function() return view.todayButton.Left() - Scale(6) end)
    view.prev.Top:Set(view.suggest.Top)
    view.range = Theme.Text(page, '', 15, C.text, true)
    view.range.Right:Set(function() return view.prev.Left() - Scale(14) end)
    LayoutHelpers.AtVerticalCenterIn(view.range, view.suggest)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return view.tabs.Bottom() end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    -- Details on the right: the chosen event, or the chosen day's.
    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Right:Set(page.Right)
    detail.Top:Set(function() return divider.Bottom() + Scale(18) end)
    detail.Bottom:Set(page.Bottom)
    detail.Width:Set(function() return math.min(Scale(440), math.floor((page.Right() - page.Left()) * 0.3)) end)
    detail.Left:Set(function() return detail.Right() - detail.Width() end)
    detail.Height:Set(function() return detail.Bottom() - detail.Top() end)
    view.detailTitle = Theme.Paragraph(detail, 18, C.text)
    view.detailTitle.Left:Set(function() return detail.Left() + Scale(24) end)
    view.detailTitle.Right:Set(function() return detail.Right() - Scale(24) end)
    view.detailTitle.Top:Set(function() return detail.Top() + Scale(24) end)
    view.detailTag = Theme.Tag(detail, '', C.accent)
    view.detailTag.Left:Set(view.detailTitle.Left)
    view.detailTag.Top:Set(function() return view.detailTitle.Bottom() + Scale(10) end)
    view.detailOrigin = Theme.Tag(detail, 'Official', C.accent)
    view.detailOrigin.Left:Set(function() return view.detailTag.Right() + Scale(8) end)
    view.detailOrigin.Top:Set(view.detailTag.Top)
    view.detail = Widgets.TextView(detail)
    view.detail.Left:Set(view.detailTitle.Left)
    view.detail.Right:Set(function() return detail.Right() - Scale(12) end)
    view.detail.Top:Set(function() return view.detailTag.Bottom() + Scale(14) end)
    view.detail.Bottom:Set(function() return detail.Bottom() - Scale(70) end)
    view.detail.Width:Set(function() return view.detail.Right() - view.detail.Left() end)
    view.detail.Height:Set(function() return view.detail.Bottom() - view.detail.Top() end)
    view.open = Theme.Button(detail, 'Open', function() view:OpenChosen() end, 'primary', { icon = 'external', width = 200 })
    view.open.Left:Set(view.detailTitle.Left)
    LayoutHelpers.AtBottomIn(view.open, detail, 20)

    -- The calendar on the left.
    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(function() return detail.Left() - Scale(24) end)
    area.Top:Set(detail.Top)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    area:DisableHitTest()
    view.area = area
    view.note = Theme.Text(area, '', 13, C.subtle)
    view.note.Left:Set(area.Left)
    view.note.Bottom:Set(area.Bottom)

    -- Coming up: a list of the next weeks' occurrences.
    view.list = Widgets.VirtualList(area, {
        { 'When', 0.23, function(item) return ShortDay(item.day) .. (item.clock and ('  ' .. item.clock) or '') end, C.muted },
        { 'Event', 0.39, function(item) return item.entry.title end },
        { 'Kind', 0.18, function(item)
            local category = kCategories[item.entry.category]
            return { category[1], category[2] }
        end, kind = 'badge' },
        { 'Host', 0.20, function(item) return item.entry.host end, C.subtle },
    }, function(item)
        view.chosen = item
        view.day = item.day
        view:Paint()
    end)
    view.list.Left:Set(area.Left)
    view.list.Right:Set(area.Right)
    view.list.Top:Set(area.Top)
    view.list.Bottom:Set(function() return view.note.Top() - Scale(10) end)

    -- Week and month: a grid of day cells, each with its chips.
    view.grid = Group(area)
    view.grid.Left:Set(area.Left)
    view.grid.Right:Set(area.Right)
    view.grid.Top:Set(area.Top)
    view.grid.Bottom:Set(function() return view.note.Top() - Scale(10) end)
    Theme.SizeFromEdges(view.grid)
    view.grid:DisableHitTest()
    local heads = {}
    for i = 1, 7 do
        local head = Theme.Text(view.grid, string.upper(kWeekdays[i]), 10, C.subtle, true)
        local column = i - 1
        head.Left:Set(function() return view.grid.Left() + math.floor(column * view.grid.Width() / 7) + Scale(8) end)
        head.Top:Set(view.grid.Top)
        heads[i] = head
    end
    view.cells = {}
    for index = 1, 42 do
        local cell = Theme.Panel(view.grid, 'ff0a1620', C.line)
        local column = math.mod(index - 1, 7)
        local row = math.floor((index - 1) / 7)
        local function Rows()
            return view.mode == 'week' and 1 or 6
        end
        cell.Left:Set(function() return view.grid.Left() + math.floor(column * view.grid.Width() / 7) end)
        cell.Width:Set(function() return math.floor(view.grid.Width() / 7) - Scale(4) end)
        cell.Top:Set(function()
            local top = heads[1].Bottom() + Scale(8)
            return top + math.floor(row * (view.grid.Bottom() - top) / Rows())
        end)
        cell.Height:Set(function()
            local top = heads[1].Bottom() + Scale(8)
            return math.floor((view.grid.Bottom() - top) / Rows()) - Scale(4)
        end)
        cell.number = Theme.Text(cell, '', 12, C.muted, true)
        LayoutHelpers.AtLeftTopIn(cell.number, cell, 8, 6)
        cell.more = Theme.Text(cell, '', 10, C.subtle)
        cell.more.Left:Set(function() return cell.Left() + Scale(8) end)
        cell.more.Bottom:Set(function() return cell.Bottom() - Scale(4) end)
        cell.chips = {}
        for slot = 1, kChipsPerCell + 5 do
            local chip = Chip(cell, view)
            local s = slot - 1
            chip.Left:Set(function() return cell.Left() + Scale(4) end)
            chip.Right:Set(function() return cell.Right() - Scale(4) end)
            chip.Width:Set(function() return chip.Right() - chip.Left() end)
            chip.Top:Set(function() return cell.number.Bottom() + Scale(6) + s * Scale(24) end)
            cell.chips[slot] = chip
        end
        Theme.HitArea(cell, function(self, event)
            if event.Type == 'ButtonPress' and event.Modifiers.Left and cell.day then
                Theme.ClickSound()
                view.day = cell.day
                view.chosen = nil
                view:Paint()
                return true
            end
            return false
        end)
        view.cells[index] = cell
    end

    ----------------------------------------------------------------------------------------------------------------

    function view:Load()
        self.failure = nil
        if rawget(_G, 'FafLibrary_Events') then
            self.jobs.catalogue = { id = FafLibrary_Events(), done = function(doc)
                view.sources.catalogue = FromCatalogue(doc)
                view.submitUrl = type(doc.submitUrl) == 'string' and doc.submitUrl or nil
            end }
        end
        if rawget(_G, 'FafLibrary_Api') then
            local id = FafLibrary_Api('/challonge/v1/tournaments.json', { ['page[size]'] = '100', ['page[number]'] = '1' })
            if id then
                self.jobs.tournaments = { id = id, done = function(data)
                    local list = {}
                    for _, raw in (type(data) == 'table' and data) or {} do
                        local t = type(raw) == 'table' and (raw.tournament or raw) or {}
                        local start = ParseTime(t.start_at)
                        if start and type(t.name) == 'string' then
                            local entry = { id = 'tourney:' .. tostring(t.id), title = t.name, summary =
                                tostring(t.tournament_type or '') .. (t.participants_count and ('  -  ' ..
                                t.participants_count .. ' players') or ''), category = 'tournament', origin = 'official',
                                host = 'FAF tournaments', start = start, links = {}, source = 'tourney' }
                            local url = t.open_signup and t.sign_up_url or t.full_challonge_url
                            if type(url) == 'string' and string.find(url, '^https://') then
                                table.insert(entry.links, { label = t.open_signup and 'Sign up' or 'Bracket', url = url })
                            end
                            table.insert(list, entry)
                        end
                    end
                    view.sources.tourney = list
                end }
            end
        end
        -- FAF's patches with their dates, as the Changelog page reads them.
        local list = {}
        local ok, overview = pcall(import, '/lua/ui/lobby/changelog/generated/overview.lua')
        for _, patch in (ok and overview and overview.Overview and overview.Overview.Changelogs) or {} do
            local start = ParseTime(type(patch.Date) == 'string' and string.sub(patch.Date, 1, 10) or nil)
            if start then
                table.insert(list, { id = 'patch:' .. tostring(patch.Version), title = 'Game update ' ..
                    tostring(patch.Version) .. (patch.Name and patch.Name ~= '' and (': ' .. patch.Name) or ''),
                    summary = 'FAF\'s game patch ' .. tostring(patch.Version) .. '. Its notes are on the Changelog page.',
                    category = 'patch', origin = 'official', host = 'FAForever', start = start, links = {},
                    source = 'patch', version = patch.Version })
            end
        end
        self.sources.patch = list
        self:Merge()
    end

    function view:Merge()
        self.entries = {}
        for _, key in { 'catalogue', 'tourney', 'patch' } do
            for _, entry in self.sources[key] or {} do
                table.insert(self.entries, entry)
            end
        end
    end

    --- The occurrences in [from, to], by day then time.
    function view:Occurrences(from, to)
        local list = {}
        for _, entry in self.entries do
            for _, at in Days(entry, from, to) do
                table.insert(list, { key = entry.id .. '@' .. at.day, entry = entry, day = at.day, clock = at.clock })
            end
        end
        table.sort(list, function(a, b)
            if a.day ~= b.day then
                return a.day < b.day
            end
            return (a.clock or '') < (b.clock or '')
        end)
        return list
    end

    function view:Move(step)
        if self.mode == 'month' then
            local y, m = CivilFromDays(self.anchor)
            m = m + step
            if m < 1 then
                m, y = 12, y - 1
            elseif m > 12 then
                m, y = 1, y + 1
            end
            self.anchor = DaysFromCivil(y, m, 1)
        else
            self.anchor = self.anchor + step * (self.mode == 'week' and 7 or kUpcomingDays)
        end
        self.day = self.anchor
        self.chosen = nil
        self:Paint()
    end

    --- The first and last day the view shows.
    function view:Range()
        if self.mode == 'week' then
            local first = self.anchor - (Weekday(self.anchor) - 1)
            return first, first + 6
        elseif self.mode == 'month' then
            local y, m = CivilFromDays(self.anchor)
            local firstOfMonth = DaysFromCivil(y, m, 1)
            local first = firstOfMonth - (Weekday(firstOfMonth) - 1)
            return first, first + 41
        end
        local first = math.max(self.anchor, self.today)
        return first, first + kUpcomingDays - 1
    end

    function view:Poll()
        local changed = false
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if not state or state.state ~= 'working' then
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: events: ' .. tostring(err))
                    end
                elseif key == 'catalogue' then
                    self.failure = 'The events catalogue didn\'t load: ' .. tostring(state and state.message or '?')
                end
                changed = true
            end
        end
        if changed then
            self:Merge()
            self:Paint()
        end
    end

    function view:Refresh()
        self:Poll()
    end

    function view:Paint()
        self.tabs:Set(self.mode, {})
        local from, to = self:Range()
        local shown = self:Occurrences(from, to)
        self.shown = shown
        local listMode = self.mode == 'upcoming'
        Theme.SetVisible(self.list, listMode)
        Theme.SetVisible(self.grid, not listMode)
        if listMode then
            Theme.SetText(self.range, 'From ' .. LongDay(from))
            self.list.selectedKey = self.chosen and self.chosen.key or false
            self.list:SetItems(shown)
        else
            local y, m = CivilFromDays(self.anchor)
            Theme.SetText(self.range, self.mode == 'month' and (kMonths[m] .. ' ' .. y) or
                (LongDay(from) .. '  -  ' .. LongDay(to)))
            local byDay = {}
            for _, occurrence in shown do
                byDay[occurrence.day] = byDay[occurrence.day] or {}
                table.insert(byDay[occurrence.day], occurrence)
            end
            local count = self.mode == 'week' and 7 or 42
            local room = self.mode == 'week' and (kChipsPerCell + 5) or kChipsPerCell
            for index, cell in self.cells do
                local visible = index <= count
                Theme.SetVisible(cell, visible)
                if visible then
                    local day = from + index - 1
                    cell.day = day
                    local _, cm, cd = CivilFromDays(day)
                    Theme.SetText(cell.number, tostring(cd))
                    local inMonth = self.mode ~= 'month' or cm == m
                    Theme.SetColor(cell.number, day == self.today and C.accent or (inMonth and C.text or C.subtle))
                    cell:SetColors(day == self.day and 'ff10222f' or (inMonth and 'ff0a1620' or 'ff070f16'),
                        day == self.today and C.accent or (day == self.day and Theme.WithAlpha(C.accent, 0.5) or C.line))
                    local list = byDay[day] or {}
                    for slot, chip in cell.chips do
                        chip:Set(slot <= room and list[slot] or nil)
                    end
                    local extra = table.getn(list) - room
                    Theme.SetText(cell.more, extra > 0 and ('+' .. extra .. ' more') or '')
                end
            end
        end
        self:PaintDetail()
        local counts = {}
        for _, key in kCategoryOrder do
            counts[key] = 0
        end
        for _, occurrence in shown do
            counts[occurrence.entry.category] = counts[occurrence.entry.category] + 1
        end
        local loading = next(self.jobs) ~= nil
        Theme.SetText(self.note, self.failure or ((loading and 'Reading the calendar...  ' or '') .. table.getn(shown) ..
            ' events shown  -  times in your time zone'))
        Theme.SetColor(self.note, self.failure and C.bad or C.subtle)
    end

    function view:PaintDetail()
        local chosen = self.chosen
        local blocks = {}
        if chosen then
            local entry = chosen.entry
            local category = kCategories[entry.category]
            self.detailTitle:SetText(entry.title, C.text)
            self.detailTag:SetTag(category[1], category[2])
            Theme.SetVisible(self.detailTag, true)
            Theme.SetVisible(self.detailOrigin, entry.origin == 'official')
            local when = LongDay(chosen.day) .. (chosen.clock and ('  at ' .. chosen.clock) or '  (all day)')
            if entry.finish and entry.finish.minute then
                local _, endClock = Local(entry.finish)
                when = when .. ' to ' .. endClock
            end
            table.insert(blocks, { style = 'h3', text = when })
            if entry.recurrence == 'weekly' then
                table.insert(blocks, { style = 'text', text = entry.interval == 1 and 'Every week' or
                    ('Every ' .. entry.interval .. ' weeks') })
            elseif entry.recurrence == 'monthly' then
                table.insert(blocks, { style = 'text', text = 'Every month' })
            end
            if entry.host ~= '' then
                table.insert(blocks, { style = 'text', text = 'Run by ' .. entry.host })
            end
            if entry.summary ~= '' then
                table.insert(blocks, { style = 'gap', text = '' })
                table.insert(blocks, { style = 'text', text = entry.summary })
            end
            local link = entry.links[1]
            self.open:SetLabel(link and link.label or (entry.source == 'patch' and 'Read the notes' or 'Open'))
            Theme.SetVisible(self.open, link ~= nil or entry.source == 'patch')
        else
            self.detailTitle:SetText(LongDay(self.day), C.text)
            Theme.SetVisible(self.detailTag, false)
            Theme.SetVisible(self.detailOrigin, false)
            local any = false
            for _, occurrence in self.shown or {} do
                if occurrence.day == self.day then
                    any = true
                    table.insert(blocks, { style = 'h3', text = (occurrence.clock or 'All day') .. '   ' ..
                        occurrence.entry.title })
                    table.insert(blocks, { style = 'text', text = kCategories[occurrence.entry.category][1] ..
                        (occurrence.entry.host ~= '' and ('  -  ' .. occurrence.entry.host) or '') })
                end
            end
            if not any then
                table.insert(blocks, { style = 'text', text = 'Nothing on this day. Pick an event, or a day with ' ..
                    'events, to read about it.' })
            end
            Theme.SetVisible(self.open, false)
        end
        self.detail:SetBlocks(blocks)
    end

    function view:OpenChosen()
        local entry = self.chosen and self.chosen.entry
        if not entry then
            return
        end
        if entry.links[1] then
            LOG('LAUNCHER: events: opening ' .. entry.links[1].url)
            OpenURL(entry.links[1].url)
        elseif entry.source == 'patch' then
            launcher:ShowPage('changelog')
        end
    end

    function view:Suggest()
        Suggest(launcher, view)
    end

    view:Load()
    view:Paint()
    return view
end

------------------------------------------------------------------------------------------------------------------------
-- "Suggest an event": the form, its checks, and the issue it opens.

local currentSuggest = false

function Suggest(launcher, view)
    if currentSuggest then
        currentSuggest:Close()
    end
    local width, height = Widgets.FrameUnits()
    local cover = Widgets.Modal(launcher.root, 760, math.min(620, height - 60))
    local panel = cover.panel
    local form = { category = 'meetup', repeats = 'none', cover = cover }
    currentSuggest = form
    local x = 26
    local title = Theme.Title(panel, 'Suggest an event', 18, C.text)
    LayoutHelpers.AtLeftTopIn(title, panel, x, 22)
    local close = Theme.Button(panel, '', function() form:Close() end, 'ghost', { icon = 'close', width = 40 })
    LayoutHelpers.AtRightTopIn(close, panel, 16, 16)
    local intro = Theme.Paragraph(panel, 12, C.muted)
    intro.Left:Set(title.Left)
    intro.Right:Set(function() return panel.Right() - Scale(x) end)
    intro.Top:Set(function() return title.Bottom() + Scale(10) end)
    intro:SetText('The calendar is a public list people add to through GitHub. Fill this in and the launcher opens a ' ..
        'ready issue in your browser; you send it from there, and a reviewer adds it.', C.muted)

    local function Field(caption, widthUnits, hint, maxChars, above, left)
        local label = Theme.Text(panel, string.upper(caption), 10, C.accent, true)
        local field = Theme.TextField(panel, widthUnits, hint, nil, maxChars)
        if left then
            label.Left:Set(function() return left.Right() + Scale(14) end)
        else
            label.Left:Set(title.Left)
        end
        label.Top:Set(function() return above.Bottom() + Scale(14) end)
        field.Left:Set(label.Left)
        field.Top:Set(function() return label.Bottom() + Scale(6) end)
        return field
    end
    form.title = Field('Title', 708, 'What is it called?', 120, intro)
    form.day = Field('Date', 200, '2026-12-05', 10, form.title)
    form.time = Field('Starts (your time)', 200, '19:30, or empty for all day', 5, form.title, form.day)
    form.endTime = Field('Ends', 200, '22:00 (optional)', 5, form.title, form.time)
    form.host = Field('Who runs it', 346, 'You, a clan, a caster...', 80, form.day)
    form.url = Field('Link', 348, 'https://... (optional)', 300, form.day, form.host)
    form.summary = Field('In a sentence or two', 708, 'What happens, who it is for', 280, form.host)
    local kindLabel = Theme.Text(panel, 'KIND', 10, C.accent, true)
    kindLabel.Left:Set(title.Left)
    kindLabel.Top:Set(function() return form.summary.Bottom() + Scale(14) end)
    form.kinds = {}
    local before = nil
    for _, key in { 'meetup', 'cgn', 'tournament', 'other' } do
        local value = key
        local choice = Theme.Choice(panel, kCategories[key][1], 166, function()
            form.category = value
            form:Paint()
        end)
        choice.value = value
        local after = before
        choice.Left:Set(function() return after and (after.Right() + Scale(8)) or title.Left() end)
        choice.Top:Set(function() return kindLabel.Bottom() + Scale(6) end)
        table.insert(form.kinds, choice)
        before = choice
    end
    local repeatLabel = Theme.Text(panel, 'REPEATS', 10, C.accent, true)
    repeatLabel.Left:Set(title.Left)
    repeatLabel.Top:Set(function() return form.kinds[1].Bottom() + Scale(14) end)
    form.repeatChoices = {}
    before = nil
    for _, entry in { { 'none', 'Once' }, { 'weekly', 'Every week' }, { 'fortnightly', 'Every two weeks' },
        { 'monthly', 'Every month' } } do
        local value = entry[1]
        local choice = Theme.Choice(panel, entry[2], 166, function()
            form.repeats = value
            form:Paint()
        end)
        choice.value = value
        local after = before
        choice.Left:Set(function() return after and (after.Right() + Scale(8)) or title.Left() end)
        choice.Top:Set(function() return repeatLabel.Bottom() + Scale(6) end)
        table.insert(form.repeatChoices, choice)
        before = choice
    end
    form.status = Theme.Cell(panel, 12, C.subtle)
    form.status.Left:Set(title.Left)
    form.status.Right:Set(function() return panel.Right() - Scale(330) end)
    form.status.Bottom:Set(function() return panel.Bottom() - Scale(28) end)
    form.send = Theme.Button(panel, 'Open on GitHub', function() form:Send() end, 'primary',
        { icon = 'external', width = 190 })
    LayoutHelpers.AtRightIn(form.send, panel, x)
    LayoutHelpers.AtBottomIn(form.send, panel, 20)
    form.cancel = Theme.Button(panel, 'Cancel', function() form:Close() end, 'secondary', { width = 110 })
    form.cancel.Right:Set(function() return form.send.Left() - Scale(10) end)
    form.cancel.Bottom:Set(form.send.Bottom)
    form.day.edit:SetText(DayText(view.day))

    function form:Draft()
        local function Text(field)
            return string.gsub(field.edit:GetText() or '', '^%s*(.-)%s*$', '%1')
        end
        return { title = Text(self.title), day = Text(self.day), time = Text(self.time), endTime = Text(self.endTime),
            host = Text(self.host), url = Text(self.url), summary = Text(self.summary), category = self.category,
            repeats = self.repeats }
    end

    function form:Paint()
        for _, choice in self.kinds do
            choice.selected = choice.value == self.category
            choice:Paint(false)
        end
        for _, choice in self.repeatChoices do
            choice.selected = choice.value == self.repeats
            choice:Paint(false)
        end
        local why = Entry(self:Draft())
        self.send:SetEnabled(why == nil)
        Theme.SetText(self.status, self.statusText or why or 'Ready: the issue opens in your browser.')
        Theme.SetColor(self.status, (not self.statusText and why) and C.bad or C.subtle)
    end

    function form:Send()
        local draft = self:Draft()
        local why, entry = Entry(draft)
        if why then
            self.statusText = why
            self:Paint()
            return
        end
        local url = IssueUrl(view.submitUrl or 'https://github.com/FAForeverRustClient/events/issues/new/choose', draft, entry)
        if not url then
            self.statusText = 'The calendar has no place to send suggestions to right now.'
        else
            self.issueUrl = url
            self.json = Json(entry)
            LOG('LAUNCHER: events: suggestion opened, ' .. string.len(url) .. ' characters: ' .. self.json)
            if not form.dryRun then
                OpenURL(url)
            end
            self.statusText = 'Opened in your browser: send the issue there.'
        end
        self:Paint()
    end

    function form:Close()
        if currentSuggest == form then
            currentSuggest = false
        end
        cover:Destroy()
    end

    for _, field in { form.title, form.day, form.time, form.endTime, form.host, form.url, form.summary } do
        field:OnChange(function()
            form.statusText = nil
            form:Paint()
        end)
    end
    form:Paint()
    return form
end

--- The suggestion form on screen (tests), or false.
function CurrentSuggest()
    return currentSuggest
end
