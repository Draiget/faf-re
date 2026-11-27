-- The launcher's Units page: every unit of the game, by faction, as the build bar shows them (icon on its land, air or
-- sea background, tech level), filtered by tech level and kind and searchable by name or id. The chosen unit's card:
-- its icon, name and role, health, shield, vision, speed, costs, build time and total damage per second, its weapons
-- (damage, damage per second, range) and its abilities. The blueprints and the numbers come from FAF's own unit
-- analyzer (/lua/ui/lobby/unitsanalyzer.lua, which FAF's lobby uses for unit restrictions), read once in the
-- background the first time the page shows.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local UIUtil = import('/lua/ui/uiutil.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local kTile = 92        -- a tile's width
local kTileHeight = 112 -- icon frame and name
local kGap = 10
local kFactions = {
    { 'UEF', 'UEF' }, { 'AEON', 'Aeon' }, { 'CYBRAN', 'Cybran' }, { 'SERAPHIM', 'Seraphim' }, { 'NOMADS', 'Nomads' },
}
local kTechs = {
    { 'all', 'All' }, { 'T1', 'Tech 1' }, { 'T2', 'Tech 2' }, { 'T3', 'Tech 3' }, { 'T4', 'Experimental' },
    { 'command', 'Command' },
}
local kTypes = { { 'all', 'All' }, { 'LAND', 'Land' }, { 'AIR', 'Air' }, { 'NAVAL', 'Naval' }, { 'BASE', 'Structures' } }
local kTechOrder = { command = 0, T1 = 1, T2 = 2, T3 = 3, T4 = 4 }
local kTypeOrder = { LAND = 1, AIR = 2, NAVAL = 3, BASE = 4 }
local kTechNames = { T1 = 'Tech 1', T2 = 'Tech 2', T3 = 'Tech 3', T4 = 'Experimental', command = 'Command' }
local kTypeNames = { LAND = 'Land', AIR = 'Air', NAVAL = 'Naval', BASE = 'Structure' }

local function Number(value)
    if not value then
        return '-'
    end
    local text = tostring(math.floor(value + 0.5))
    -- Thousands apart: 12 500.
    local count = 1
    while count > 0 do
        text, count = string.gsub(text, '^(-?%d+)(%d%d%d)', '%1 %2')
    end
    return text
end

--- The game's build-bar picture of a unit: its icon and the background of its kind (land, air, sea, amphibious).
local function Pictures(bp, analyzer)
    local icon = analyzer.GetImagePath(bp, bp.Faction or '')
    local back = nil
    local kind = bp.General and bp.General.Icon
    if kind then
        local path = UIUtil.UIFile('/icons/units/' .. kind .. '_up.dds')
        if path and DiskGetFileInfo(path) then
            back = path
        end
    end
    return icon, back
end

local function UnitOf(bp, analyzer)
    local tech = bp.Tech
    if tech == '' then
        tech = 'command'
    end
    local kind = bp.Type == 'HOVER' and 'LAND' or bp.Type
    local proper = bp.General and bp.General.UnitName and LOC(bp.General.UnitName) or ''
    local role = LOC(bp.Description or (bp.Interface and bp.Interface.HelpText) or '') or ''
    local icon, back = Pictures(bp, analyzer)
    return {
        key = bp.ID, id = bp.ID, bp = bp, faction = bp.Faction, tech = tech, kind = kind,
        name = proper ~= '' and proper or role, role = proper ~= '' and role or '', icon = icon, back = back,
        search = string.lower(bp.ID .. ' ' .. proper .. ' ' .. role),
    }
end

function Build(launcher, page)
    local view = { faction = 'UEF', tech = 'all', kind = 'all', top = 0, tiles = {}, units = nil, progress = 0 }
    launcher.unitsView = view

    local title = Theme.Title(page, 'Units', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 6)
    local factionEntries = {}
    for _, faction in kFactions do
        table.insert(factionEntries, { faction[1], faction[2] })
    end
    view.tabs = Widgets.Tabs(page, factionEntries, function(key)
        view.faction = key
        view.top = 0
        view.chosen = nil
        view:Filter()
    end)
    view.tabs.Left:Set(function() return title.Right() + Scale(40) end)
    LayoutHelpers.AtTopIn(view.tabs, page, 0)
    view.tabs.Right:Set(page.Right)
    local divider = Theme.Rect(page, C.line)
    divider.Left:Set(page.Left)
    divider.Right:Set(page.Right)
    divider.Top:Set(function() return view.tabs.Bottom() end)
    divider.Height:Set(1)
    divider.Width:Set(function() return divider.Right() - divider.Left() end)
    divider:DisableHitTest()

    view.search = Theme.TextField(page, 260, 'Find a unit by name or id', 'search', 40)
    LayoutHelpers.AtLeftIn(view.search, page, 0)
    view.search.Top:Set(function() return divider.Bottom() + Scale(16) end)
    view.search:OnChange(function()
        view.top = 0
        view:Filter()
    end)
    -- Tech and kind as two rows of choices beside the search.
    local function ChoiceRow(entries, field, left, top)
        local row = {}
        local before = nil
        for _, entry in entries do
            local key = entry[1]
            -- About 8 units a letter at 13 px, and room around it.
            local choice = Theme.Choice(page, entry[2], math.max(56, string.len(entry[2]) * 8 + 28), function()
                view[field] = key
                view.top = 0
                view:Filter()
            end)
            choice.key = key
            choice.field = field
            local after = before
            choice.Left:Set(function() return after and (after.Right() + Scale(6)) or left() end)
            choice.Top:Set(top)
            table.insert(row, choice)
            before = choice
        end
        return row
    end
    view.techChoices = ChoiceRow(kTechs, 'tech', function() return view.search.Right() + Scale(20) end,
        function() return view.search.Top() end)
    view.kindChoices = ChoiceRow(kTypes, 'kind', function() return view.search.Right() + Scale(20) end,
        function() return view.techChoices[1].Bottom() + Scale(8) end)

    -- The tiles on the left, the chosen unit on the right.
    local detail = Theme.Panel(page, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Right:Set(page.Right)
    detail.Top:Set(function() return view.kindChoices[1].Bottom() + Scale(18) end)
    detail.Bottom:Set(page.Bottom)
    LayoutHelpers.SetWidth(detail, 480)
    detail.Left:Set(function() return detail.Right() - detail.Width() end)
    detail.Height:Set(function() return detail.Bottom() - detail.Top() end)
    local area = Group(page)
    area.Left:Set(page.Left)
    area.Right:Set(function() return detail.Left() - Scale(24) end)
    area.Top:Set(detail.Top)
    area.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(area)
    view.area = area
    view.note = Theme.Paragraph(area, 14, C.subtle)
    view.note.Left:Set(area.Left)
    view.note.Right:Set(function() return area.Left() + math.min(area.Width(), Scale(600)) end)
    view.note.Top:Set(function() return area.Top() + Scale(8) end)
    view.loader = Theme.Loader(area)
    LayoutHelpers.AtCenterIn(view.loader, area)
    Theme.HitArea(area, function(self, event)
        if event.Type == 'WheelRotation' then
            view.top = math.max(0, view.top + (event.WheelRotation > 0 and -1 or 1))
            view:Paint()
            return true
        end
        return false
    end).Depth:Set(function() return area.Depth() - 1 end)

    -- The card: picture, name, role and what it is; the numbers; weapons; abilities.
    local x = 24
    view.frame = Theme.Panel(detail, 'ff08121a', C.line)
    LayoutHelpers.SetDimensions(view.frame, 84, 84)
    LayoutHelpers.AtLeftTopIn(view.frame, detail, x, 22)
    view.back = Bitmap(view.frame)
    view.back:DisableHitTest()
    LayoutHelpers.FillParentFixedBorder(view.back, view.frame, 1)
    view.back.Depth:Set(function() return view.frame.Depth() + 1 end)
    view.icon = Bitmap(view.frame)
    view.icon:DisableHitTest()
    LayoutHelpers.FillParentFixedBorder(view.icon, view.frame, 1)
    view.icon.Depth:Set(function() return view.frame.Depth() + 2 end)
    view.name = Theme.Text(detail, '', 20, C.text, true)
    view.name.Left:Set(function() return view.frame.Right() + Scale(16) end)
    view.name.Top:Set(function() return view.frame.Top() + Scale(4) end)
    view.role = Theme.Cell(detail, 13, C.muted)
    view.role.Left:Set(view.name.Left)
    view.role.Right:Set(function() return detail.Right() - Scale(x) end)
    view.role.Top:Set(function() return view.name.Bottom() + Scale(4) end)
    view.what = Theme.Cell(detail, 12, C.subtle)
    view.what.Left:Set(view.name.Left)
    view.what.Right:Set(view.role.Right)
    view.what.Top:Set(function() return view.role.Bottom() + Scale(6) end)

    view.stats = {}
    local labels = { 'Health', 'Shield', 'Vision', 'Speed', 'Mass', 'Energy', 'Build time', 'Damage / s' }
    local colors = { C.good, C.accent, C.text, C.text, C.gold, C.warn, C.text, C.bad }
    for i, label in labels do
        local column = math.mod(i - 1, 4)
        local line = math.floor((i - 1) / 4)
        local key = Theme.Text(detail, string.upper(label), 10, C.subtle, true)
        key.Left:Set(function()
            return detail.Left() + Scale(x) + math.floor((detail.Width() - Scale(2 * x)) * column / 4)
        end)
        key.Top:Set(function() return view.frame.Bottom() + Scale(20 + line * 46) end)
        local value = Theme.Text(detail, '', 16, colors[i] or C.text, true)
        value.Left:Set(key.Left)
        value.Top:Set(function() return key.Bottom() + Scale(4) end)
        view.stats[i] = value
    end
    local lastValue = view.stats[8]

    view.abilities = Theme.Paragraph(detail, 12, C.muted)
    view.abilities.Left:Set(function() return detail.Left() + Scale(x) end)
    view.abilities.Right:Set(function() return detail.Right() - Scale(x) end)
    view.abilities.Top:Set(function() return lastValue.Bottom() + Scale(16) end)
    local weaponsCaption = Theme.Caption(detail, 'Weapons', C.accent)
    weaponsCaption.Left:Set(view.abilities.Left)
    weaponsCaption.Top:Set(function() return view.abilities.Bottom() + Scale(14) end)
    view.weapons = Widgets.VirtualList(detail, {
        { 'Weapon', 0.46, function(item) return item.name end },
        { 'Damage', 0.18, function(item) return item.damage end, C.muted },
        { 'Per s', 0.18, function(item) return item.dps end, C.bad },
        { 'Range', 0.18, function(item) return item.range end, C.muted },
    }, function(item) end)
    view.weapons.Left:Set(view.abilities.Left)
    view.weapons.Right:Set(view.abilities.Right)
    view.weapons.Top:Set(function() return weaponsCaption.Bottom() + Scale(8) end)
    view.weapons.Bottom:Set(function() return detail.Bottom() - Scale(40) end)
    view.footnote = Theme.Text(detail, "* not in damage per second: an upgrade's weapon, overcharge or a defence", 11,
        C.subtle)
    view.footnote.Left:Set(view.abilities.Left)
    view.footnote.Bottom:Set(function() return detail.Bottom() - Scale(16) end)
    Theme.SizeFromEdges(view.weapons)
    view.noWeapons = Theme.Text(detail, 'No weapons.', 12, C.subtle)
    view.noWeapons.Left:Set(view.abilities.Left)
    view.noWeapons.Top:Set(function() return weaponsCaption.Bottom() + Scale(36) end)

    local function Tile(index)
        local tile = view.tiles[index]
        if tile then
            return tile
        end
        tile = Theme.Panel(area, 'ff0d1c27', C.line)
        LayoutHelpers.SetDimensions(tile, kTile, kTileHeight)
        tile.frame = Group(tile)
        LayoutHelpers.SetDimensions(tile.frame, 64, 64)
        LayoutHelpers.AtHorizontalCenterIn(tile.frame, tile)
        LayoutHelpers.AtTopIn(tile.frame, tile, 10)
        tile.back = Bitmap(tile.frame)
        tile.back:DisableHitTest()
        LayoutHelpers.FillParent(tile.back, tile.frame)
        tile.back.Depth:Set(function() return tile.Depth() + 2 end)
        tile.icon = Bitmap(tile.frame)
        tile.icon:DisableHitTest()
        LayoutHelpers.FillParent(tile.icon, tile.frame)
        tile.icon.Depth:Set(function() return tile.Depth() + 3 end)
        tile.tech = Theme.Text(tile, '', 10, C.text, true)
        LayoutHelpers.AtLeftTopIn(tile.tech, tile, 6, 4)
        tile.tech.Depth:Set(function() return tile.Depth() + 4 end)
        tile.name = Theme.Cell(tile, 11, C.muted)
        tile.name.Left:Set(function() return tile.Left() + Scale(6) end)
        tile.name.Right:Set(function() return tile.Right() - Scale(6) end)
        tile.name.Top:Set(function() return tile.frame.Bottom() + Scale(8) end)
        Theme.HitArea(tile, function(self, event)
            if not tile.unit then
                return false
            end
            if event.Type == 'MouseEnter' then
                tile.over = true
                view:Paint()
            elseif event.Type == 'MouseExit' then
                tile.over = false
                view:Paint()
            elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
                Theme.ClickSound()
                view.chosen = tile.unit
                view:Paint()
                return true
            elseif event.Type == 'WheelRotation' then
                view.top = math.max(0, view.top + (event.WheelRotation > 0 and -1 or 1))
                view:Paint()
                return true
            end
            return false
        end)
        view.tiles[index] = tile
        return tile
    end

    ----------------------------------------------------------------------------------------------------------------

    --- Reads every unit's blueprint through FAF's analyzer, in the background with its progress.
    function view:Load()
        self.loading = true
        local ok, why = pcall(function()
            local analyzer = import('/lua/ui/lobby/unitsanalyzer.lua')
            local notifier = import('/lua/ui/lobby/tasknotifier.lua').Create()
            notifier.OnProgressCallback = function(task)
                view.progress = notifier.totalProgress or 0
            end
            notifier.OnCompleteCallback = function()
                local done, err = pcall(function() view:Loaded(analyzer) end)
                if not done then
                    view.failure = tostring(err)
                    WARN('LAUNCHER: units: ' .. tostring(err))
                end
            end
            analyzer.FetchBlueprints({}, false, notifier)
        end)
        if not ok then
            self.failure = tostring(why)
            WARN('LAUNCHER: units: the blueprints did not load: ' .. tostring(why))
        end
    end

    function view:Loaded(analyzer)
        local all = analyzer.GetBlueprintsList().All or {}
        local units = {}
        local counts = {}
        for id, bp in all do
            if bp.Type ~= 'UPGRADE' and bp.Faction and bp.Faction ~= 'UNKNOWN' and kTechOrder[bp.Tech == '' and 'command' or bp.Tech] then
                local unit = UnitOf(bp, analyzer)
                table.insert(units, unit)
                counts[unit.faction] = (counts[unit.faction] or 0) + 1
            end
        end
        table.sort(units, function(a, b)
            local ta, tb = kTechOrder[a.tech] or 9, kTechOrder[b.tech] or 9
            if ta ~= tb then
                return ta < tb
            end
            local ka, kb = kTypeOrder[a.kind] or 9, kTypeOrder[b.kind] or 9
            if ka ~= kb then
                return ka < kb
            end
            return a.id < b.id
        end)
        self.analyzer = analyzer
        self.units = units
        self.counts = counts
        self.loading = false
        LOG('LAUNCHER: units: ' .. table.getn(units) .. ' units read')
        self:Filter()
    end

    function view:Filter()
        if not self.units then
            return
        end
        local text = string.lower(self.search.edit:GetText() or '')
        local shown = {}
        for _, unit in self.units do
            if unit.faction == self.faction and (self.tech == 'all' or unit.tech == self.tech) and
                (self.kind == 'all' or unit.kind == self.kind) and (text == '' or string.find(unit.search, text, 1, true)) then
                table.insert(shown, unit)
            end
        end
        self.shown = shown
        -- The chosen unit stays while the filter still shows it.
        local still = false
        for _, unit in shown do
            still = still or unit == self.chosen
        end
        if not still then
            self.chosen = shown[1]
        end
        self:Paint()
    end

    --- The chosen unit's numbers and weapons, read once per unit.
    function view:Facts(unit)
        if unit.facts then
            return unit.facts
        end
        local bp = unit.bp
        local analyzer = self.analyzer
        local eco = analyzer.GetEconomyStats(bp)
        local weapons = {}
        local okWeapons, list = pcall(analyzer.GetWeaponsStats, bp)
        -- The total counts the weapons the unit fires as built. Not counted, and marked "*": an upgrade's weapon (an
        -- ACU's missiles), overcharge (an ability paid with energy, not steady fire) and defensive weapons.
        local total = { DPS = 0 }
        local uncounted = false
        if okWeapons then
            for i, weapon in list do
                local upgrade = weapon.EnabledByEnhancement ~= nil and weapon.EnabledByEnhancement ~= ''
                local overcharge = weapon.OverChargeWeapon or string.find(string.lower(weapon.Label or ''), 'overcharge')
                local category = weapon.Category or weapon.WeaponCategory
                local counted = not upgrade and not overcharge and category ~= 'Defense' and category ~= 'Death' and
                    category ~= 'Teleport'
                uncounted = uncounted or not counted
                table.insert(weapons, {
                    key = tostring(i),
                    name = (counted and '' or '* ') .. LOC(weapon.DisplayName or '?') ..
                        ((weapon.Count or 1) > 1 and ('  x' .. weapon.Count) or ''),
                    damage = Number(weapon.Damage), dps = weapon.DPS and weapon.DPS >= 0 and Number(weapon.DPS) or '-',
                    range = Number(weapon.Range),
                })
                if counted and weapon.DPS and weapon.DPS > 0 then
                    total.DPS = total.DPS + weapon.DPS
                end
            end
        end
        local speed = bp.Air and bp.Air.MaxAirspeed and bp.Air.MaxAirspeed > 0 and bp.Air.MaxAirspeed or
            (bp.Physics and bp.Physics.MaxSpeed)
        local abilities = {}
        for _, ability in (bp.Display and bp.Display.Abilities or {}) do
            table.insert(abilities, LOC(ability))
        end
        unit.facts = {
            values = {
                Number(bp.Defense and bp.Defense.MaxHealth),
                Number(bp.Defense and bp.Defense.Shield and bp.Defense.Shield.ShieldMaxHealth),
                Number(bp.Intel and bp.Intel.VisionRadius),
                speed and speed > 0 and string.format('%.1f', speed) or '-',
                Number(eco.BuildCostMass), Number(eco.BuildCostEnergy), Number(eco.BuildTime),
                total.DPS and total.DPS > 0 and Number(total.DPS) or '-',
            },
            weapons = weapons,
            uncounted = uncounted,
            abilities = table.concat(abilities, '  -  '),
        }
        return unit.facts
    end

    function view:Paint()
        local counts = {}
        for faction, count in (self.counts or {}) do
            counts[faction] = count
        end
        self.tabs:Set(self.faction, counts)
        -- Nomads only when a mod brings them.
        for _, tab in self.tabs.items do
            if tab.key == 'NOMADS' then
                Theme.SetVisible(tab, (counts.NOMADS or 0) > 0)
            end
        end
        for _, list in { self.techChoices, self.kindChoices } do
            for _, choice in list do
                choice.selected = choice.key == self[choice.field]
                choice:Paint(false)
            end
        end
        Theme.SetVisible(self.loader, self.units == nil and not self.failure)
        local note = ''
        if self.failure then
            note = 'The units didn\'t load: ' .. self.failure
        elseif not self.units then
            note = 'Reading the units\' blueprints...  ' .. math.floor((self.progress or 0) * 100) .. '%'
        elseif self.shown and table.getn(self.shown) == 0 then
            note = 'No unit matches.'
        end
        self.note:SetText(note, self.failure and C.bad or C.subtle)

        -- The tiles, a row at a time from `top`.
        local shown = self.shown or {}
        local perRow = math.max(1, math.floor((self.area.Width() + Scale(kGap)) / Scale(kTile + kGap)))
        local rows = math.max(1, math.floor((self.area.Height() + Scale(kGap)) / Scale(kTileHeight + kGap)))
        local maxTop = math.max(0, math.ceil(table.getn(shown) / perRow) - rows)
        self.top = math.min(self.top, maxTop)
        local first = self.top * perRow
        for i = 1, perRow * rows do
            local tile = Tile(i)
            local unit = shown[first + i]
            tile.unit = unit
            Theme.SetVisible(tile, unit ~= nil)
            if unit then
                local slot = i - 1
                tile.Left:Set(function() return self.area.Left() + math.mod(slot, perRow) * Scale(kTile + kGap) end)
                tile.Top:Set(function() return self.area.Top() + math.floor(slot / perRow) * Scale(kTileHeight + kGap) end)
                if tile.shownIcon ~= unit.icon then
                    tile.shownIcon = unit.icon
                    tile.icon:SetTexture(unit.icon)
                end
                if unit.back and tile.shownBack ~= unit.back then
                    tile.shownBack = unit.back
                    tile.back:SetTexture(unit.back)
                end
                Theme.SetVisible(tile.back, unit.back ~= nil)
                Theme.SetText(tile.tech, unit.tech == 'command' and 'ACU' or unit.tech)
                Theme.SetText(tile.name, unit.name)
                local chosen = self.chosen == unit
                Theme.SetColor(tile.name, chosen and C.accent or (tile.over and C.text or C.muted))
                tile:SetColors(chosen and 'ff123145' or (tile.over and C.raised or 'ff0d1c27'),
                    chosen and C.accent or (tile.over and C.lineStrong or C.line))
            end
        end
        for i = perRow * rows + 1, table.getn(self.tiles) do
            Theme.SetVisible(self.tiles[i], false)
        end

        -- The card.
        local unit = self.chosen
        Theme.SetVisible(self.frame, unit ~= nil)
        if unit then
            if self.shownIcon ~= unit.icon then
                self.shownIcon = unit.icon
                self.icon:SetTexture(unit.icon)
            end
            if unit.back and self.shownBack ~= unit.back then
                self.shownBack = unit.back
                self.back:SetTexture(unit.back)
            end
            Theme.SetVisible(self.back, unit.back ~= nil)
        end
        Theme.SetText(self.name, unit and unit.name or '')
        Theme.SetText(self.role, unit and unit.role or '')
        Theme.SetText(self.what, unit and ((kTechNames[unit.tech] or unit.tech) .. '  -  ' .. (kTypeNames[unit.kind] or
            unit.kind) .. '  -  ' .. string.upper(unit.id)) or '')
        local facts = unit and self:Facts(unit)
        for i, value in self.stats do
            Theme.SetText(value, facts and facts.values[i] or '')
        end
        if self.abilitiesFor ~= unit then
            self.abilitiesFor = unit
            self.abilities:SetText(facts and facts.abilities or '', C.muted)
        end
        local weapons = facts and facts.weapons or {}
        if self.weapons.items ~= weapons then
            self.weapons.top = 1
            self.weapons:SetItems(weapons)
        end
        Theme.SetVisible(self.noWeapons, unit ~= nil and table.getn(weapons) == 0)
        Theme.SetVisible(self.footnote, facts ~= nil and facts.uncounted)
    end

    function view:Refresh()
        if not self.units and not self.loading and not self.failure then
            self:Load()
        end
        self:Paint()
    end

    return view
end
