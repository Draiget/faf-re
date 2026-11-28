-- The launcher's design kit: the pieces every page draws its facts with, so a number, a player, a rating or a chart
-- looks the same everywhere. Stat boxes (a number over a caption), fact rows (label and value), rating cards (one
-- leaderboard), headings, a row layout, the rating chart (interactive) and a sparkline (a small, quiet line).
-- Badges are Theme.Tag, players Widgets.PlayerTag (and VirtualList's 'player' columns).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kMonths = { 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' }

--- "6 Dec 2021" from FAF's ISO time ("2021-12-06T12:34:56Z"), '' for none.
function DateText(iso)
    local _, _, year, month, day = string.find(tostring(iso or ''), '^(%d+)-(%d+)-(%d+)')
    if not year then
        return ''
    end
    return tonumber(day) .. ' ' .. (kMonths[tonumber(month)] or month) .. ' ' .. year
end

function Thousands(n)
    local text = tostring(math.floor(n or 0))
    local out = ''
    while string.len(text) > 3 do
        out = ',' .. string.sub(text, -3) .. out
        text = string.sub(text, 1, -4)
    end
    return text .. out
end

function Percent(part, whole)
    if not whole or whole <= 0 then
        return '-'
    end
    return string.format('%.1f%%', part * 100 / whole)
end

------------------------------------------------------------------------------------------------------------------------
-- Pieces.

--- A caption in the accent colour, with a quieter note after it.
function Heading(parent, text)
    local caption = Theme.Text(parent, string.upper(text), 12, C.accent, true)
    caption.note = Theme.Text(parent, '', 12, C.subtle)
    caption.note.Left:Set(function() return caption.Right() + Scale(12) end)
    LayoutHelpers.AtVerticalCenterIn(caption.note, caption)
    return caption
end

--- Label and value on one line inside `box`, the value to the right; :Set(value, color).
function FactRow(box, label, top)
    local row = Group(box)
    row:DisableHitTest()
    row.Left:Set(function() return box.Left() + Scale(16) end)
    row.Right:Set(function() return box.Right() - Scale(16) end)
    row.Top:Set(function() return box.Top() + Scale(top) end)
    LayoutHelpers.SetHeight(row, 30)
    row.label = Theme.Text(row, label, 13, C.muted)
    LayoutHelpers.AtLeftIn(row.label, row, 0)
    LayoutHelpers.AtVerticalCenterIn(row.label, row)
    row.value = Theme.Text(row, '', 13, C.text)
    LayoutHelpers.AtRightIn(row.value, row, 0)
    LayoutHelpers.AtVerticalCenterIn(row.value, row)
    local line = Theme.Rect(row, C.line)
    line.Left:Set(row.Left)
    line.Right:Set(row.Right)
    line.Bottom:Set(row.Bottom)
    line.Height:Set(1)
    line.Width:Set(function() return line.Right() - line.Left() end)
    line:DisableHitTest()
    row.Set = function(self, value, color)
        Theme.SetText(self.value, value or '')
        Theme.SetColor(self.value, color or C.text)
    end
    return row
end

--- One leaderboard's card: name, rating, mean and deviation, games, wins, win rate, and a link to its history.
function RatingCard(parent, onHistory)
    local card = Theme.Panel(parent, 'ff08121a', C.line)
    LayoutHelpers.SetHeight(card, 212)
    card.name = Theme.Text(card, '', 11, C.muted, true)
    LayoutHelpers.AtLeftTopIn(card.name, card, 14, 14)
    card.rating = Theme.Text(card, '', 30, C.gold, true)
    LayoutHelpers.AtLeftTopIn(card.rating, card, 14, 34)
    card.spread = Theme.Text(card, '', 11, C.subtle)
    LayoutHelpers.AtLeftTopIn(card.spread, card, 14, 74)
    card.rows = {}
    for i, label in { 'Games', 'Wins', 'Win rate' } do
        local offset = 98 + (i - 1) * 26 -- Lua 5.0: a closure keeps the loop's last value, not this one
        local row = Group(card)
        row:DisableHitTest()
        row.Left:Set(function() return card.Left() + Scale(14) end)
        row.Right:Set(function() return card.Right() - Scale(14) end)
        row.Top:Set(function() return card.Top() + Scale(offset) end)
        LayoutHelpers.SetHeight(row, 24)
        row.label = Theme.Text(row, label, 12, C.muted)
        LayoutHelpers.AtLeftIn(row.label, row, 0)
        LayoutHelpers.AtVerticalCenterIn(row.label, row)
        row.value = Theme.Text(row, '', 12, C.text)
        LayoutHelpers.AtRightIn(row.value, row, 0)
        LayoutHelpers.AtVerticalCenterIn(row.value, row)
        card.rows[i] = row
    end
    card.link = Theme.Text(card, 'View history  >', 12, C.accent)
    LayoutHelpers.AtLeftIn(card.link, card, 14)
    LayoutHelpers.AtBottomIn(card.link, card, 14)
    Theme.HitArea(card, function(self, event)
        if not card.board then
            return false
        end
        if event.Type == 'MouseEnter' then
            card:SetColors('ff0c1a24', C.lineStrong)
            Theme.SetColor(card.link, C.text)
        elseif event.Type == 'MouseExit' then
            card:SetColors('ff08121a', C.line)
            Theme.SetColor(card.link, C.accent)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            Theme.ClickSound()
            onHistory(card.board)
            return true
        end
        return false
    end)
    card.Set = function(self, board)
        self.board = board
        Theme.SetText(self.name, string.upper(board.name))
        Theme.SetText(self.rating, tostring(board.rating))
        Theme.SetText(self.spread, string.format('%d  +/-  %d', math.floor(board.mean + 0.5),
            math.floor(board.deviation + 0.5)))
        Theme.SetText(self.rows[1].value, Thousands(board.games))
        Theme.SetText(self.rows[2].value, Thousands(board.wins))
        Theme.SetText(self.rows[3].value, Percent(board.wins, board.games))
    end
    return card
end

--- A number over a caption, for the history's summary and the clan's head.
--- compact: 60 units high, no note line (for a side panel). The value's text shrinks to fit the box's width.
function StatBox(parent, caption, compact)
    local box = Theme.Panel(parent, 'ff08121a', C.line)
    LayoutHelpers.SetHeight(box, compact and 60 or 84)
    box.caption = Theme.Text(box, string.upper(caption), 10, C.muted, true)
    LayoutHelpers.AtLeftTopIn(box.caption, box, compact and 12 or 14, compact and 9 or 12)
    local sizes = compact and { 18, 15, 13 } or { 22, 18, 15 }
    box.value = Theme.Text(box, '', sizes[1], C.text, true)
    LayoutHelpers.AtLeftTopIn(box.value, box, compact and 12 or 14, compact and 27 or 30)
    box.note = Theme.Text(box, '', 11, C.subtle)
    LayoutHelpers.AtLeftTopIn(box.note, box, 14, 62)
    Theme.SetVisible(box.note, not compact)
    box.Set = function(self, value, color, note)
        Theme.SetText(self.value, value or '-')
        Theme.SetColor(self.value, color or C.text)
        Theme.SetText(self.note, note or '')
        -- The largest of the sizes the value fits in, the box's padding on both sides.
        local room = self.Width() - Scale(compact and 24 or 28)
        for _, size in sizes do
            self.value:SetFont(Theme.Fonts.bold, size)
            if room <= 0 or self.value:GetStringAdvance(value or '-') <= room then
                break
            end
        end
    end
    return box
end

--- Lays `items` out in a row inside `area` from `top`, `gap` units apart, each as wide as the row allows.
function Row(area, items, top, gap)
    local count = table.getn(items)
    for i, item in items do
        local index = i - 1
        item.Left:Set(function()
            local width = (area.Width() - Scale(gap) * (count - 1)) / count
            return area.Left() + math.floor(index * (width + Scale(gap)))
        end)
        item.Width:Set(function() return math.floor((area.Width() - Scale(gap) * (count - 1)) / count) end)
        item.Top:Set(function() return area.Top() + Scale(top) end)
    end
end

------------------------------------------------------------------------------------------------------------------------
-- The rating chart: the rating (mean - 3 deviations) as a line of short bars, the mean fainter behind it. Interactive:
-- the mouse shows the game under it (its date, result, rating, mean and change), the wheel zooms around the mouse,
-- dragging moves along the games, a double click shows them all again.

local kMinSpan = 10 -- the fewest games a zoom shows

function Chart(parent)
    local chart = Theme.Panel(parent, 'ff060d13', C.line)
    chart.marks = {}
    chart.labels = {}
    chart.used = 0
    chart.points = {}
    chart.first = 1
    chart.last = 0
    chart.legend = Theme.Text(chart, '', 12, C.subtle)
    LayoutHelpers.AtRightTopIn(chart.legend, chart, 16, 12)
    local key = Theme.Rect(chart, C.gold)
    LayoutHelpers.SetDimensions(key, 18, 3)
    LayoutHelpers.AtLeftTopIn(key, chart, 60, 20)
    key:DisableHitTest()
    local keyText = Theme.Text(chart, 'Rating (mean - 3 deviations)', 12, C.muted)
    keyText.Left:Set(function() return key.Right() + Scale(8) end)
    LayoutHelpers.AtVerticalCenterIn(keyText, key)
    local meanKey = Theme.Rect(chart, Theme.WithAlpha(C.accent, 0.55))
    LayoutHelpers.SetDimensions(meanKey, 18, 3)
    meanKey.Left:Set(function() return keyText.Right() + Scale(24) end)
    meanKey.Top:Set(key.Top)
    meanKey:DisableHitTest()
    local meanText = Theme.Text(chart, 'Mean', 12, C.muted)
    meanText.Left:Set(function() return meanKey.Right() + Scale(8) end)
    LayoutHelpers.AtVerticalCenterIn(meanText, meanKey)
    chart.hint = Theme.Text(chart, 'Wheel: zoom  -  drag: move  -  double click: all games', 11, C.subtle)
    LayoutHelpers.AtRightIn(chart.hint, chart, 16)
    LayoutHelpers.AtBottomIn(chart.hint, chart, 8)
    chart.empty = Theme.Text(chart, '', 13, C.subtle)
    LayoutHelpers.AtCenterIn(chart.empty, chart)

    -- The plot's edges inside the chart, in pixels from its top left.
    local function Plot()
        return Scale(60), chart.Width() - Scale(24), Scale(48), chart.Height() - Scale(42)
    end

    local function Mark(color, x, y, w, h)
        chart.used = chart.used + 1
        local mark = chart.marks[chart.used]
        if not mark then
            mark = Bitmap(chart)
            mark:DisableHitTest()
            chart.marks[chart.used] = mark
        end
        mark:SetSolidColor(color)
        mark.Left:Set(function() return chart.Left() + x end)
        mark.Top:Set(function() return chart.Top() + y end)
        mark.Width:Set(math.max(1, w))
        mark.Height:Set(math.max(1, h))
        Theme.SetVisible(mark, true)
    end
    local labelsUsed = 0
    local function Label(text, x, y, right)
        labelsUsed = labelsUsed + 1
        local label = chart.labels[labelsUsed]
        if not label then
            label = Theme.Text(chart, '', 11, C.subtle)
            chart.labels[labelsUsed] = label
        end
        Theme.SetText(label, text)
        if right then
            label.Left:Set(function() return chart.Left() + x - label.Width() end)
        else
            label.Left:Set(function() return chart.Left() + x end)
        end
        label.Top:Set(function() return chart.Top() + y end)
        Theme.SetVisible(label, true)
    end

    -- What the mouse points at: a line down the plot, a dot on each line and a box with the game's numbers.
    local over = {}
    local function Above(control, depth)
        control.Depth:Set(function() return chart.Depth() + depth end)
        control:DisableHitTest()
        return control
    end
    over.line = Above(Theme.Rect(chart, Theme.WithAlpha(C.text, 0.3)), 20)
    over.rating = Above(Theme.Dot(chart, 9, C.gold), 21)
    over.mean = Above(Theme.Dot(chart, 9, C.accent), 21)
    over.tip = Above(Theme.Panel(chart, 'ff0a141c', C.lineStrong), 22)
    LayoutHelpers.SetDimensions(over.tip, 236, 112)
    over.lines = {}
    for i, style in { { 11, C.subtle }, { 18, C.gold, true }, { 12, C.muted }, { 12, C.text } } do
        local line = Theme.Text(over.tip, '', style[1], style[2], style[3])
        line.Depth:Set(function() return over.tip.Depth() + 1 end)
        LayoutHelpers.AtLeftIn(line, over.tip, 12)
        over.lines[i] = line
    end
    LayoutHelpers.AtTopIn(over.lines[1], over.tip, 10)
    LayoutHelpers.AtTopIn(over.lines[2], over.tip, 30)
    LayoutHelpers.AtTopIn(over.lines[3], over.tip, 60)
    LayoutHelpers.AtTopIn(over.lines[4], over.tip, 82)
    local function HideOver()
        for _, control in { over.line, over.rating, over.mean, over.tip } do
            Theme.SetVisible(control, false)
        end
        chart.overIndex = nil
    end
    HideOver()

    local function Y(value)
        local _, _, top, bottom = Plot()
        return math.floor(bottom - (value - chart.low) * (bottom - top) / (chart.high - chart.low))
    end
    local function X(index)
        local left, right = Plot()
        return left + math.floor((index - chart.first) * (right - left) / math.max(1, chart.last - chart.first))
    end
    --- The game under screen position x (within the shown ones).
    local function IndexAt(x)
        local left, right = Plot()
        local share = (x - chart.Left() - left) / math.max(1, right - left)
        share = math.max(0, math.min(1, share))
        return math.floor(chart.first + share * (chart.last - chart.first) + 0.5)
    end

    --- Draws the games first..last of the points.
    function chart:Redraw()
        self.used = 0
        labelsUsed = 0
        local points = self.points
        local count = table.getn(points)
        Theme.SetText(self.empty, count == 0 and 'No rated games on this leaderboard yet.' or '')
        Theme.SetVisible(self.hint, count > 1)
        if count > 0 then
            local left, right, top, bottom = Plot()
            local first, last = self.first, self.last
            local low, high = points[first].rating, points[first].mean
            for i = first, last do
                low = math.min(low, points[i].rating, points[i].mean)
                high = math.max(high, points[i].rating, points[i].mean)
            end
            -- Grid lines every 100, 200, 400... rating points, at most six of them.
            local step = 100
            while (high - low) / step > 6 do
                step = step * 2
            end
            low = math.floor(low / step) * step
            high = math.ceil(high / step) * step
            if high <= low then
                high = low + step
            end
            self.low, self.high = low, high
            for value = low, high, step do
                Mark(C.line, left, Y(value), right - left, 1)
                Label(tostring(value), left - Scale(8), Y(value) - Scale(7), true)
            end
            -- One column per pixel pair: the games that fall into it average into one value.
            local shown = last - first + 1
            local columns = math.max(1, math.min(shown, math.floor((right - left) / 2)))
            local width = (right - left) / columns
            local lastRating, lastMean
            for column = 1, columns do
                local from = first + math.floor((column - 1) * shown / columns)
                local to = math.max(from, first + math.floor(column * shown / columns) - 1)
                local rating, mean = 0, 0
                for i = from, to do
                    rating = rating + points[i].rating
                    mean = mean + points[i].mean
                end
                rating = Y(rating / (to - from + 1))
                mean = Y(mean / (to - from + 1))
                local x = left + math.floor((column - 1) * width)
                local w = math.max(2, math.ceil(width))
                local fromMean = lastMean or mean
                Mark(Theme.WithAlpha(C.accent, 0.45), x, math.min(fromMean, mean), w, math.abs(mean - fromMean) + 2)
                local fromRating = lastRating or rating
                Mark(C.gold, x, math.min(fromRating, rating), w, math.abs(rating - fromRating) + 2)
                lastRating, lastMean = rating, mean
            end
            -- Game numbers along the bottom: the first shown, the last shown and three between.
            for i = 0, 4 do
                local game = math.floor(first + i * (last - first) / 4 + 0.5)
                Label((i == 0 and 'game ' or '') .. Thousands(game), X(game) - (i == 4 and Scale(30) or 0),
                    bottom + Scale(8))
            end
        end
        for i = self.used + 1, table.getn(self.marks) do
            Theme.SetVisible(self.marks[i], false)
        end
        for i = labelsUsed + 1, table.getn(self.labels) do
            Theme.SetVisible(self.labels[i], false)
        end
        if self.overIndex then
            self:ShowOver(self.overIndex)
        end
    end

    --- The game `index` under the mouse: the line, the dots and the box beside them.
    function chart:ShowOver(index)
        local point = self.points[index]
        if not point then
            HideOver()
            return
        end
        self.overIndex = index
        local left, right, top, bottom = Plot()
        local x = X(index)
        over.line.Left:Set(function() return chart.Left() + x end)
        over.line.Top:Set(function() return chart.Top() + top end)
        over.line.Width:Set(1)
        over.line.Height:Set(bottom - top)
        local ratingY, meanY = Y(point.rating), Y(point.mean)
        over.rating.Left:Set(function() return chart.Left() + x - math.floor(over.rating.Width() / 2) end)
        over.rating.Top:Set(function() return chart.Top() + ratingY - math.floor(over.rating.Height() / 2) end)
        over.mean.Left:Set(function() return chart.Left() + x - math.floor(over.mean.Width() / 2) end)
        over.mean.Top:Set(function() return chart.Top() + meanY - math.floor(over.mean.Height() / 2) end)
        -- The box on the side with more room, level with the rating's dot.
        local onRight = x < (left + right) / 2
        over.tip.Left:Set(function()
            if onRight then
                return chart.Left() + x + Scale(14)
            end
            return chart.Left() + x - Scale(14) - over.tip.Width()
        end)
        over.tip.Top:Set(function()
            local y = math.max(top, math.min(ratingY - math.floor(over.tip.Height() / 2), bottom - over.tip.Height()))
            return chart.Top() + y
        end)
        local result = point.result and (string.upper(string.sub(point.result, 1, 1)) ..
            string.lower(string.sub(point.result, 2))) or ''
        Theme.SetText(over.lines[1], 'Game ' .. Thousands(index) .. '  -  ' .. DateText(point.when) ..
            (result ~= '' and ('  -  ' .. result) or ''))
        Theme.SetText(over.lines[2], tostring(math.floor(point.rating + 0.5)))
        Theme.SetText(over.lines[3], string.format('Mean %d  +/-  %d', math.floor(point.mean + 0.5),
            math.floor((point.deviation or 0) + 0.5)))
        local before = self.points[index - 1]
        local change = before and math.floor(point.rating - before.rating + 0.5) or nil
        Theme.SetText(over.lines[4], change and ('Change ' .. (change > 0 and '+' or '') .. change) or 'First game')
        Theme.SetColor(over.lines[4], (change and change > 0 and C.good) or (change and change < 0 and C.bad) or C.muted)
        Theme.SetColor(over.lines[1], result == 'Victory' and C.good or (result == 'Defeat' and C.bad or C.subtle))
        for _, control in { over.line, over.rating, over.mean, over.tip } do
            Theme.SetVisible(control, true)
        end
    end

    --- Shows games first..last (kept inside the points and at least kMinSpan of them).
    function chart:ShowRange(first, last)
        local count = table.getn(self.points)
        local span = math.max(math.min(kMinSpan, count), last - first + 1)
        span = math.min(span, count)
        first = math.max(1, math.min(math.floor(first + 0.5), count - span + 1))
        last = first + span - 1
        if first ~= self.first or last ~= self.last then
            self.first, self.last = first, last
            self:Redraw()
        end
    end

    --- points: { {rating=, mean=, deviation=, when=, result=}, ... } oldest first; shows them all.
    chart.Draw = function(self, points, legend)
        self.points = points or {}
        self.first, self.last = 1, table.getn(self.points)
        self.overIndex = nil
        HideOver()
        Theme.SetText(self.legend, legend or '')
        self:Redraw()
    end

    Theme.HitArea(chart, function(self, event)
        local count = table.getn(chart.points)
        if count < 2 then
            return false
        end
        if event.Type == 'MouseMotion' then
            if chart.dragging then
                -- Dragging moves the shown games with the mouse.
                local left, right = Plot()
                local perPixel = (chart.dragLast - chart.dragFirst) / math.max(1, right - left)
                local shift = (chart.dragX - event.MouseX) * perPixel
                chart:ShowRange(chart.dragFirst + shift, chart.dragLast + shift)
            end
            chart:ShowOver(IndexAt(event.MouseX))
            return true
        elseif event.Type == 'MouseExit' then
            chart.dragging = false
            HideOver()
        elseif event.Type == 'ButtonDClick' then
            chart:ShowRange(1, count)
            return true
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            chart.dragging = true
            chart.dragX = event.MouseX
            chart.dragFirst, chart.dragLast = chart.first, chart.last
            return true
        elseif event.Type == 'ButtonRelease' then
            chart.dragging = false
            return true
        elseif event.Type == 'WheelRotation' then
            -- Zooms around the game under the mouse: it stays where it is.
            local at = IndexAt(event.MouseX)
            local span = chart.last - chart.first
            local newSpan = math.max(kMinSpan - 1, math.min(count - 1, math.floor(span * (event.WheelRotation > 0 and 0.8 or 1.25) + 0.5)))
            local share = (at - chart.first) / math.max(1, span)
            local first = at - share * newSpan
            chart:ShowRange(first, first + newSpan)
            chart:ShowOver(IndexAt(event.MouseX))
            return true
        end
        return false
    end)
    return chart
end

------------------------------------------------------------------------------------------------------------------------
-- A sparkline: values as a small line of short bars, no axes, the last value marked; for a trend beside a number.
-- :Draw(values, color) (oldest first).

function Sparkline(parent)
    local spark = Group(parent)
    spark:DisableHitTest()
    spark.marks = {}
    spark.dot = Theme.Dot(spark, 7, C.gold)
    spark.dot:DisableHitTest()
    spark.Draw = function(self, values, color)
        color = color or C.gold
        local count = table.getn(values or {})
        local used = 0
        local function Mark(x, y, w, h)
            used = used + 1
            local mark = self.marks[used]
            if not mark then
                mark = Bitmap(self)
                mark:DisableHitTest()
                self.marks[used] = mark
            end
            mark:SetSolidColor(color)
            mark.Left:Set(function() return self.Left() + x end)
            mark.Top:Set(function() return self.Top() + y end)
            mark.Width:Set(math.max(1, w))
            mark.Height:Set(math.max(1, h))
            Theme.SetVisible(mark, true)
        end
        if count >= 2 then
            local low, high = values[1], values[1]
            for _, value in values do
                low = math.min(low, value)
                high = math.max(high, value)
            end
            if high <= low then
                high = low + 1
            end
            local width, height = self.Width(), self.Height() - Scale(4)
            local columns = math.max(1, math.min(count, math.floor(width / 2)))
            local step = width / columns
            local last
            for column = 1, columns do
                local from = 1 + math.floor((column - 1) * count / columns)
                local to = math.max(from, math.floor(column * count / columns))
                local sum = 0
                for i = from, to do
                    sum = sum + values[i]
                end
                local y = Scale(2) + math.floor(height - (sum / (to - from + 1) - low) * height / (high - low))
                local x = math.floor((column - 1) * step)
                local fromY = last or y
                Mark(x, math.min(fromY, y), math.max(2, math.ceil(step)), math.abs(y - fromY) + 2)
                last = y
            end
            self.dot:SetSolidColor(color)
            self.dot.Left:Set(function() return self.Right() - math.floor(self.dot.Width() / 2) end)
            self.dot.Top:Set(function() return self.Top() + last - math.floor(self.dot.Height() / 2) + 1 end)
        end
        Theme.SetVisible(self.dot, count >= 2)
        for i = used + 1, table.getn(self.marks) do
            Theme.SetVisible(self.marks[i], false)
        end
    end
    return spark
end
