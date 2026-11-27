-- The in-game launcher's look: a command console inside the game. Deep navy panels over the game's own background,
-- one cyan accent, square edges with cyan corner brackets, the game's title font for headings, colour-coded tags.
-- Icons, brackets and dots are pictures the engine draws at runtime (FafUi_Icon, FafUi_Box; moho/ui/UiArt.h), so no
-- image file ships with them; on an engine without those functions the same pieces appear without them.

local UIUtil = import('/lua/ui/uiutil.lua')
local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Group = import('/lua/maui/group.lua').Group
local Edit = import('/lua/maui/edit.lua').Edit
local Icons = import('/fafengine/modules/lua/ui/launcher/icons.lua').Icons

Colors = {
    page = 'ff060b10',
    rail = 'f0071017',
    panel = 'e40b161e',
    field = 'ff08121a',
    raised = 'ff102131',
    hover = 'ff15303f',
    selected = 'ff143a4e',
    line = 'ff1b3140',
    lineStrong = 'ff2b5165',
    accent = 'ff38c4f0',
    accentDeep = 'ff0f4c66',
    accentHover = 'ff16698b',
    text = 'ffe8f2f7',
    muted = 'ff9fb4c1',
    subtle = 'ff6b8392',
    good = 'ff62d08a',
    warn = 'fff0b450',
    bad = 'ffef6a6a',
    gold = 'ffe0b55a',
    violet = 'ffa98bf5',
    clear = '00000000',
}

--- Team colours, in team order (the balance bar, the player lists).
TeamColors = { 'ff38c4f0', 'ffef6a6a', 'ffa98bf5', 'fff0c14e', 'ff62d08a', 'fff08bd0', 'ff8be0d8', 'ffc8c8c8' }

Fonts = {
    body = 'Arial',
    bold = 'Arial Bold',
    title = UIUtil.titleFont,
}

function Scale(units)
    return LayoutHelpers.ScaleNumber(units)
end

-- Controls that keep some of their pieces hidden (a check mark, brackets) repaint after a Show on an ancestor, which
-- shows every piece. Weak, so destroyed controls drop out.
local paintables = setmetatable({}, { __mode = 'k' })

--- Registers a control whose :Paint(false) hides again the pieces it keeps hidden; RepaintAll calls it after a Show
--- on an ancestor showed them.
function Paintable(control)
    paintables[control] = true
end

--- Paints every live control that hides some of its pieces again (after a Show on an ancestor).
function RepaintAll()
    for control in paintables do
        pcall(control.Paint, control, false)
    end
end

local function Channels(color)
    if string.len(color) == 6 then
        color = 'ff' .. color
    end
    return tonumber(string.sub(color, 1, 2), 16), tonumber(string.sub(color, 3, 4), 16),
        tonumber(string.sub(color, 5, 6), 16), tonumber(string.sub(color, 7, 8), 16)
end

--- A colour at another opacity (0..1).
function WithAlpha(color, alpha)
    local _, r, g, b = Channels(color)
    return string.format('%02x%02x%02x%02x', math.floor(alpha * 255 + 0.5), r, g, b)
end

--- Width and Height from the edges: a Bitmap's stay its texture's otherwise (maui/bitmap.lua ResetLayout).
function SizeFromEdges(control)
    control.Width:Set(function() return control.Right() - control.Left() end)
    control.Height:Set(function() return control.Bottom() - control.Top() end)
end

function Rect(parent, color)
    local rect = Bitmap(parent)
    rect:SetSolidColor(color)
    return rect
end

--- A rectangle filling `parent` (by its edges, with its size).
function Fill(parent, color)
    local rect = Rect(parent, color)
    LayoutHelpers.FillParent(rect, parent)
    SizeFromEdges(rect)
    rect:DisableHitTest()
    return rect
end

--- A text that takes no clicks.
function Text(parent, text, size, color, bold)
    local label = UIUtil.CreateText(parent, text or '', size or 13, bold and Fonts.bold or Fonts.body)
    label:SetColor(color or Colors.text)
    label:DisableHitTest()
    return label
end

--- A heading in the game's title font, spaced out.
function Title(parent, text, size, color)
    local spaced = string.gsub(string.upper(text), '(.)', '%1 ')
    local label = UIUtil.CreateText(parent, string.sub(spaced, 1, -2), size or 26, Fonts.title)
    label:SetColor(color or Colors.text)
    label:DisableHitTest()
    return label
end

--- Small bold capitals over a section.
function Caption(parent, text, color)
    return Text(parent, string.upper(text), 10, color or Colors.subtle, true)
end

--- A text cut at a width; its left and right are set by the caller.
function Cell(parent, size, color, bold)
    local label = Text(parent, '', size, color, bold)
    label:SetClipToWidth(true)
    return label
end

function SetText(label, text)
    if label.shown ~= text then
        label.shown = text
        label:SetText(text)
    end
end

function SetColor(label, color)
    if label.shownColor ~= color then
        label.shownColor = color
        label:SetColor(color)
    end
end

--- Hides or shows only on a change (Show on a parent shows every child). `visible` must be a boolean.
function SetVisible(control, visible)
    visible = visible and true or false
    if visible == control:IsHidden() then
        if visible then
            control:Show()
        else
            control:Hide()
        end
    end
end

local function Picture(bitmap, path, px, fallback)
    if path then
        bitmap:SetTexture(path)
    else
        bitmap:SetSolidColor(fallback or Colors.clear)
    end
    bitmap.Width:Set(px)
    bitmap.Height:Set(px)
end

--- An icon of the launcher's set as a texture path (drawn for `size` units at the current scale), or nil when this
--- build can't draw it.
function IconTexture(name, size, color, stroke)
    local svg = Icons[name]
    if not svg or not rawget(_G, 'FafUi_Icon') then
        return nil
    end
    return FafUi_Icon(svg, Scale(size), color or Colors.text, stroke or 1.8)
end

--- An icon of the launcher's set, `size` units square, in `color`. :SetIcon(name, color) changes it.
function Icon(parent, name, size, color, stroke)
    local px = Scale(size)
    local icon = Bitmap(parent)
    icon:DisableHitTest()
    icon.SetIcon = function(self, iconName, iconColor)
        if self.iconName == iconName and self.iconColor == iconColor then
            return
        end
        self.iconName = iconName
        self.iconColor = iconColor
        local svg = Icons[iconName]
        Picture(self, svg and rawget(_G, 'FafUi_Icon') and FafUi_Icon(svg, px, iconColor, stroke or 1.8) or nil, px)
    end
    icon:SetIcon(name, color or Colors.text)
    return icon
end

-- FAF's logo, as the FAF Rust client ships it (ui/public/assets/faflogo.svg, a 703 x 374 drawing), filled.
local kFafLogo = '<polygon fill="currentColor" stroke="none" points="561.3 187.18 653.75 347.29 594.8 347.29 473.49 136.23 659.6 136.23 689 187.16 561.32 187.16 561.3 187.18"/>' ..
    '<polygon fill="currentColor" stroke="none" points="410.52 26.71 596.34 26.71 628.74 82.81 442.76 82.81 410.52 26.71"/>' ..
    '<path fill="currentColor" stroke="none" d="M354.05,26.71h-1.49L167.47,347.29h56.78l44-76.23H435.89l44,76.23h58.43ZM305.57,207.25l46.52-80.56,46.51,80.56Z"/>' ..
    '<polygon fill="currentColor" stroke="none" points="74.26 82.81 106.66 26.71 295.93 26.71 263.53 82.81 74.26 82.81"/>' ..
    '<polygon fill="currentColor" stroke="none" points="110.82 347.29 49.23 347.29 141.68 187.18 14 187.18 43.4 136.25 232.67 136.25 110.82 347.29"/>'

--- FAF's logo, `width` units wide, in `color`. The picture is square (the drawing's 703 units on both sides) with the
--- logo in its top 53 %: lay out under it from :LogoBottom().
function Logo(parent, width, color)
    local px = Scale(width)
    local logo = Bitmap(parent)
    logo:DisableHitTest()
    local path = rawget(_G, 'FafUi_Icon') and FafUi_Icon(kFafLogo, px, color or Colors.accent, 1, 703) or nil
    Picture(logo, path, px)
    logo.LogoBottom = function(self)
        return self.Top() + math.floor(px * 374 / 703)
    end
    if not path then
        local text = Title(parent, 'FAF', 30, color or Colors.accent)
        LayoutHelpers.AtLeftTopIn(text, logo, 0, 0)
    end
    return logo
end

--- A filled circle, `size` units across. :SetDotColor(color) changes it.
function Dot(parent, size, color)
    local px = Scale(size)
    local dot = Bitmap(parent)
    dot:DisableHitTest()
    dot.SetDotColor = function(self, dotColor)
        if self.dotColor ~= dotColor then
            self.dotColor = dotColor
            Picture(self, rawget(_G, 'FafUi_Box') and FafUi_Box(px, px, px / 2, dotColor) or nil, px, dotColor)
        end
    end
    dot:SetDotColor(color)
    return dot
end

-- The corner brackets, one L each, on a 12-unit grid.
local kBrackets = {
    '<path d="M1.5 11V1.5H11" />',
    '<path d="M1 1.5h9.5V11" />',
    '<path d="M10.5 1v9.5H1" />',
    '<path d="M11 10.5H1.5V1" />',
}

--- Cyan brackets on two opposite corners of `control` (top left and bottom right), or all four.
function Brackets(control, color, all, size)
    local px = Scale(size or 12)
    local made = {}
    for i = 1, 4 do
        if all or i == 1 or i == 3 then
            local bracket = Bitmap(control)
            bracket:DisableHitTest()
            Picture(bracket, rawget(_G, 'FafUi_Icon') and FafUi_Icon(kBrackets[i], px, color or Colors.accent, 2, 12) or nil, px)
            bracket.Depth:Set(function() return control.Depth() + 40 end)
            if i == 1 or i == 4 then
                bracket.Left:Set(function() return control.Left() - Scale(1) end)
            else
                bracket.Right:Set(function() return control.Right() + Scale(1) end)
            end
            if i == 1 or i == 2 then
                bracket.Top:Set(function() return control.Top() - Scale(1) end)
            else
                bracket.Bottom:Set(function() return control.Bottom() + Scale(1) end)
            end
            made[i] = bracket
        end
    end
    return made
end

--- A square panel: a fill and a one-pixel line around it. :SetColors(fill, line) recolours it; its pieces lie
--- under its children.
function Panel(parent, fill, line)
    local panel = Group(parent)
    panel:DisableHitTest()
    local back = Bitmap(panel)
    back:DisableHitTest()
    LayoutHelpers.FillParent(back, panel)
    SizeFromEdges(back)
    back.Depth:Set(function() return panel.Depth() end)
    local edges = {}
    local function Edge(left, top, right, bottom)
        local edge = Bitmap(panel)
        edge:DisableHitTest()
        edge.Left:Set(left)
        edge.Top:Set(top)
        edge.Right:Set(right)
        edge.Bottom:Set(bottom)
        SizeFromEdges(edge)
        edge.Depth:Set(function() return panel.Depth() end)
        table.insert(edges, edge)
    end
    Edge(panel.Left, panel.Top, panel.Right, function() return panel.Top() + 1 end)
    Edge(panel.Left, function() return panel.Bottom() - 1 end, panel.Right, panel.Bottom)
    Edge(panel.Left, panel.Top, function() return panel.Left() + 1 end, panel.Bottom)
    Edge(function() return panel.Right() - 1 end, panel.Top, panel.Right, panel.Bottom)
    panel.SetColors = function(self, newFill, newLine)
        if self.fill ~= newFill then
            self.fill = newFill
            back:SetSolidColor(newFill)
        end
        newLine = newLine or newFill
        if self.line ~= newLine then
            self.line = newLine
            for _, edge in edges do
                edge:SetSolidColor(newLine)
            end
        end
    end
    panel:SetColors(fill or Colors.panel, line or Colors.line)
    return panel
end

--- A transparent control over `under` that takes its clicks (panels and groups don't).
function HitArea(under, handler)
    local area = Rect(under, Colors.clear)
    LayoutHelpers.FillParent(area, under)
    SizeFromEdges(area)
    area.Depth:Set(function() return under.Depth() + 30 end)
    area.HandleEvent = handler
    return area
end

function ClickSound()
    PlaySound(Sound({ Cue = 'UI_Menu_MouseDown_Sml', Bank = 'Interface' }))
end

function HoverSound()
    PlaySound(Sound({ Cue = 'UI_Menu_Rollover_Sml', Bank = 'Interface' }))
end

--- A button. kind: 'primary' (cyan, bracketed), 'secondary' (bordered), 'ghost' (only on hover), 'danger'.
--- opts: icon, width (units; else it fits its label), height (default 34), size (text), caps (default for primary).
function Button(parent, label, onClick, kind, opts)
    opts = opts or {}
    kind = kind or 'secondary'
    local styles = {
        primary = { fill = Colors.accentDeep, hover = Colors.accentHover, line = Colors.accent, text = Colors.text },
        secondary = { fill = Colors.raised, hover = Colors.hover, line = Colors.line, hoverLine = Colors.lineStrong,
            text = Colors.text },
        ghost = { fill = Colors.clear, hover = Colors.raised, line = Colors.clear, text = Colors.muted,
            hoverText = Colors.text },
        danger = { fill = Colors.raised, hover = Colors.hover, line = WithAlpha(Colors.bad, 0.6), text = Colors.bad },
    }
    local style = styles[kind]
    local caps = opts.caps
    if caps == nil then
        caps = kind == 'primary'
    end
    local button = Panel(parent, style.fill, style.line)
    local text = nil
    if label ~= '' then
        text = Text(button, caps and string.upper(label) or label, opts.size or 13, style.text, kind == 'primary')
    end
    local icon = opts.icon and Icon(button, opts.icon, 16, style.text) or nil
    LayoutHelpers.SetHeight(button, opts.height or 34)
    if text and icon then
        LayoutHelpers.AtVerticalCenterIn(icon, button)
        LayoutHelpers.AtVerticalCenterIn(text, button)
        icon.Left:Set(function()
            return button.Left() + math.floor((button.Width() - icon.Width() - Scale(8) - text.Width()) / 2)
        end)
        text.Left:Set(function() return icon.Right() + Scale(8) end)
    elseif text then
        LayoutHelpers.AtCenterIn(text, button)
    elseif icon then
        LayoutHelpers.AtCenterIn(icon, button)
    end
    if opts.width then
        LayoutHelpers.SetWidth(button, opts.width)
    else
        button.Width:Set(function()
            local w = Scale(32)
            if text then w = w + text.Width() end
            if icon then w = w + icon.Width() + (text and Scale(8) or 0) end
            return w
        end)
    end
    if kind == 'primary' then
        button.brackets = Brackets(button, Colors.text, false, 8)
    end
    button.enabled = true
    button.text = text
    button.icon = icon
    local function Paint(over)
        local textColor = style.text
        if not button.enabled then
            button:SetColors(kind == 'primary' and Colors.raised or style.fill, kind == 'primary' and Colors.line or style.line)
            textColor = Colors.subtle
        else
            button:SetColors(over and style.hover or style.fill, over and style.hoverLine or style.line)
            if over and style.hoverText then
                textColor = style.hoverText
            end
        end
        if text then
            SetColor(text, textColor)
        end
        if icon then
            icon:SetIcon(opts.icon, textColor)
        end
        if button.brackets then
            -- A child shown under a hidden parent still draws: only while the button itself shows.
            for _, bracket in button.brackets do
                SetVisible(bracket, button.enabled and not button:IsHidden())
            end
        end
    end
    button.SetEnabled = function(self, enabled)
        if self.enabled ~= enabled then
            self.enabled = enabled
            Paint(false)
        end
    end
    button.Paint = function(self, over)
        Paint(over)
    end
    if button.brackets then
        Paintable(button)
    end
    button.SetLabel = function(self, newLabel)
        if text then
            SetText(text, caps and string.upper(newLabel) or newLabel)
        end
    end
    button.onClick = onClick -- what a click runs (the launcher's test walk presses buttons with it)
    HitArea(button, function(self, event)
        if not button.enabled then
            return false
        end
        if event.Type == 'MouseEnter' then
            Paint(true)
        elseif event.Type == 'MouseExit' then
            Paint(false)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            ClickSound()
            onClick(button)
            return true
        end
        return false
    end)
    return button
end

--- Three dots that pulse one after the other: something is on its way. They only move while shown.
function Loader(parent, color)
    local loader = Group(parent)
    loader:DisableHitTest()
    LayoutHelpers.SetDimensions(loader, 44, 10)
    local dots = {}
    for i = 1, 3 do
        local dot = Dot(loader, 8, color or Colors.accent)
        LayoutHelpers.AtLeftIn(dot, loader, (i - 1) * 18)
        LayoutHelpers.AtVerticalCenterIn(dot, loader)
        dots[i] = dot
    end
    loader.time = 0
    loader:SetNeedsFrameUpdate(true)
    loader.OnFrame = function(self, delta)
        self.time = self.time + delta
        for i, dot in dots do
            -- Each dot brightens for a third of a 1.2 s cycle, the next one a third later.
            local phase = math.mod(self.time / 1.2 - (i - 1) / 3 + 1, 1)
            dot:SetAlpha(phase < 0.5 and (0.3 + 1.4 * phase) or (1.0 - 1.4 * (phase - 0.5)))
        end
    end
    return loader
end

--- A small tag: square, bordered and lettered in one colour.
function Tag(parent, text, color)
    local tag = Panel(parent, WithAlpha(color, 0.08), WithAlpha(color, 0.6))
    local label = Text(tag, string.upper(text), 10, color, true)
    LayoutHelpers.AtCenterIn(label, tag)
    tag.Width:Set(function() return label.Width() + Scale(12) end)
    LayoutHelpers.SetHeight(tag, 18)
    tag.SetTag = function(self, newText, newColor)
        SetText(label, string.upper(newText))
        SetColor(label, newColor)
        self:SetColors(WithAlpha(newColor, 0.08), WithAlpha(newColor, 0.6))
    end
    return tag
end

--- A one-line text field with a hint and an optional icon at its start. :OnChange(fn) is told each new text.
function TextField(parent, width, hint, iconName, maxChars)
    local field = Panel(parent, Colors.field, Colors.line)
    LayoutHelpers.SetDimensions(field, width, 34)
    LayoutHelpers.AtLeftTopIn(field, parent, 0, 0) -- the caller places it; the edit needs some place until then
    local start = 10
    if iconName then
        local icon = Icon(field, iconName, 16, Colors.subtle)
        LayoutHelpers.AtLeftIn(icon, field, 10)
        LayoutHelpers.AtVerticalCenterIn(icon, field)
        start = 34
    end
    local edit = Edit(field)
    LayoutHelpers.AtLeftIn(edit, field, start)
    LayoutHelpers.AtRightIn(edit, field, 10)
    LayoutHelpers.AtVerticalCenterIn(edit, field)
    edit.Height:Set(function() return edit:GetFontHeight() end)
    UIUtil.SetupEditStd(edit, Colors.text, '00000000', Colors.text, 'ff1d4a60', Fonts.body, 14, maxChars or 60)
    local hintText = Text(field, hint or '', 13, Colors.subtle)
    LayoutHelpers.AtLeftIn(hintText, field, start)
    LayoutHelpers.AtVerticalCenterIn(hintText, field)
    field.edit = edit
    local changed = function() end
    field.OnChange = function(self, fn)
        changed = fn
    end
    field.Refresh = function(self)
        SetVisible(hintText, edit:GetText() == '')
    end
    edit.OnTextChanged = function(self, newText, oldText)
        field:Refresh()
        changed(newText)
    end
    local area = HitArea(field, function(self, event)
        if event.Type == 'ButtonPress' then
            edit:AcquireFocus()
            return true
        end
        return false
    end)
    area.Depth:Set(function() return field.Depth() + 1 end)
    edit.Depth:Set(function() return field.Depth() + 5 end)
    return field
end

--- A checkbox with its label, as a filter. onToggle(self) after the change; :SetOn(on).
function Checkbox(parent, label, onToggle)
    local row = Group(parent)
    local box = Panel(row, Colors.field, Colors.lineStrong)
    LayoutHelpers.SetDimensions(box, 16, 16)
    LayoutHelpers.AtLeftIn(box, row, 0)
    LayoutHelpers.AtVerticalCenterIn(box, row)
    local check = Icon(box, 'check', 12, Colors.page, 2.6)
    LayoutHelpers.AtCenterIn(check, box)
    local text = Text(row, label, 13, Colors.muted)
    LayoutHelpers.AtVerticalCenterIn(text, row)
    text.Left:Set(function() return box.Right() + Scale(8) end)
    LayoutHelpers.SetHeight(row, 34)
    -- Box, gap and label: not from Left, so a caller may place the checkbox by its right edge.
    row.Width:Set(function() return Scale(28) + text.Width() end)
    row.on = false
    row.Paint = function(self, over)
        box:SetColors(self.on and Colors.accent or Colors.field, (self.on or over) and Colors.accent or Colors.lineStrong)
        SetVisible(check, self.on)
        SetColor(text, (self.on or over) and Colors.text or Colors.muted)
    end
    row.SetOn = function(self, on)
        self.on = on and true or false
        self:Paint(false)
    end
    Paintable(row)
    HitArea(row, function(self, event)
        if event.Type == 'MouseEnter' then
            row:Paint(true)
        elseif event.Type == 'MouseExit' then
            row:Paint(false)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            ClickSound()
            row.on = not row.on
            onToggle(row)
            row:Paint(true)
            return true
        end
        return false
    end)
    row:Paint(false)
    return row
end

--- One cell of a choice (featured mod, who sees it): selected in cyan. opts.enabled false greys it.
function Choice(parent, label, width, onPick)
    local choice = Panel(parent, Colors.field, Colors.line)
    LayoutHelpers.SetDimensions(choice, width, 32)
    local text = Text(choice, label, 13, Colors.muted)
    LayoutHelpers.AtCenterIn(text, choice)
    choice.selected = false
    choice.enabled = true
    choice.onPick = onPick -- what a click runs (the launcher's test walk picks with it)
    choice.Paint = function(self, over)
        if self.selected then
            self:SetColors(Colors.selected, Colors.accent)
            SetColor(text, Colors.accent)
        elseif not self.enabled then
            self:SetColors(Colors.field, Colors.line)
            SetColor(text, Colors.subtle)
        else
            self:SetColors(over and Colors.raised or Colors.field, over and Colors.lineStrong or Colors.line)
            SetColor(text, over and Colors.text or Colors.muted)
        end
    end
    HitArea(choice, function(self, event)
        if not choice.enabled then
            -- A greyed choice can still say why (onDisabledHover(true) on enter, (false) on exit).
            if choice.onDisabledHover and event.Type == 'MouseEnter' then
                choice.onDisabledHover(true)
            elseif choice.onDisabledHover and event.Type == 'MouseExit' then
                choice.onDisabledHover(false)
            end
            return false
        end
        if event.Type == 'MouseEnter' then
            choice:Paint(true)
        elseif event.Type == 'MouseExit' then
            choice:Paint(false)
        elseif event.Type == 'ButtonPress' and event.Modifiers.Left then
            ClickSound()
            onPick(choice)
            return true
        end
        return false
    end)
    choice:Paint(false)
    return choice
end

--- A login's colour for its avatar: one of eight, the same for the same name.
function NameColor(name)
    local hash = 0
    for i = 1, string.len(name or '') do
        hash = math.mod(hash * 31 + string.byte(name, i), 997)
    end
    return TeamColors[math.mod(hash, 8) + 1]
end

--- A round avatar with the login's first letter. :SetLogin(login).
function Avatar(parent, login, size)
    local avatar = Dot(parent, size, WithAlpha(NameColor(login), 0.35))
    local letter = Text(parent, '', math.floor(size * 0.5), Colors.text, true)
    LayoutHelpers.AtCenterIn(letter, avatar)
    letter.Depth:Set(function() return avatar.Depth() + 1 end)
    avatar.SetLogin = function(self, newLogin)
        newLogin = newLogin or ''
        self:SetDotColor(WithAlpha(NameColor(newLogin), 0.35))
        SetText(letter, newLogin ~= '' and string.upper(string.sub(newLogin, 1, 1)) or '?')
    end
    avatar:SetLogin(login)
    avatar.letter = letter
    return avatar
end
