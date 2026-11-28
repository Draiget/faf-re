-- The launcher's motion: short eased tweens on a control's opacity and position, all driven from one frame update
-- (a hidden control on the root whose OnFrame runs while any tween does). What moves, and why:
--   * a page coming in fades in and slides a little from the side it comes from, so the player sees where they went;
--   * a dialog fades in and rises a little; its cover darkens with it;
--   * a list's rows fade in one after another when the list fills, so new content reads as new;
--   * a toast fades in.
-- Every tween is short (120 to 260 ms) and eases out (fast start, soft stop), and none blocks input: a click during a
-- tween acts on the end state. "Reduce motion" (Options, fafre_reduce_motion, or the startup switch /reducemotion)
-- puts everything at its end at once.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Prefs = import('/lua/user/prefs.lua')

local driver = false
local tweens = {}
local count = 0

--- Easing curves on 0..1.
Ease = {
    out = function(t)
        local u = 1 - t
        return 1 - u * u * u
    end,
    inOut = function(t)
        if t < 0.5 then
            return 4 * t * t * t
        end
        local u = -2 * t + 2
        return 1 - u * u * u / 2
    end,
    linear = function(t) return t end,
}

--- Whether motion is off: the player's option, or the startup switch.
function ReduceMotion()
    if HasCommandLineArg('/reducemotion') then
        return true
    end
    local value = Prefs.GetOption('fafre_reduce_motion')
    return value == true or value == 1 or value == 'on'
end

local function Step(delta)
    local running = false
    for key, tween in tweens do
        tween.elapsed = tween.elapsed + delta
        local progress = math.min(1, tween.elapsed / tween.duration)
        if progress > 0 then
            local ok = pcall(tween.apply, tween.ease(progress))
            if not ok then
                progress = 1
            end
        end
        if progress >= 1 then
            tweens[key] = nil
            count = count - 1
            if tween.done then
                pcall(tween.done)
            end
        else
            running = true
        end
    end
    if not running and driver then
        driver:SetNeedsFrameUpdate(false)
    end
end

--- Makes the driver on `root` (once; the launcher's root).
function Attach(root)
    if driver then
        driver:Destroy()
    end
    tweens = {}
    count = 0
    driver = Group(root, 'launcher motion')
    driver:DisableHitTest()
    LayoutHelpers.AtLeftTopIn(driver, root)
    driver.Width:Set(1)
    driver.Height:Set(1)
    driver.OnFrame = function(self, delta)
        Step(delta)
    end
    driver.OnDestroy = function(self)
        driver = false
        tweens = {}
        count = 0
    end
end

--- Runs apply(eased progress 0..1) over `seconds` (after `delay`), then done(); a later tween with the same key
--- takes this one's place. With motion off, or no driver, apply(1) and done() run at once.
function Run(key, seconds, apply, done, opts)
    opts = opts or {}
    if tweens[key] then
        local old = tweens[key]
        tweens[key] = nil
        count = count - 1
        if old.done then
            pcall(old.done)
        end
    end
    if ReduceMotion() or not driver or seconds <= 0 then
        pcall(apply, 1)
        if done then
            pcall(done)
        end
        return
    end
    pcall(apply, 0)
    tweens[key] = { duration = seconds, elapsed = -(opts.delay or 0), apply = apply, done = done,
        ease = opts.ease or Ease.out }
    count = count + 1
    driver:SetNeedsFrameUpdate(true)
end

--- How many tweens run (tests).
function Running()
    return count
end

--- Fades `control` (and its children) in from transparent.
function FadeIn(control, seconds, delay)
    Run(control, seconds or 0.18, function(t)
        control:SetAlpha(t, true)
    end, function()
        control:SetAlpha(1, true)
    end, { delay = delay })
end

--- A page coming in: from `from` units to its side (positive: from the right), fading in, over its parent's place.
--- The page's left and right edges return to `parent`'s at the end.
function PageIn(page, parent, from)
    local offset = 0
    local Scale = LayoutHelpers.ScaleNumber
    page.Left:Set(function() return parent.Left() + offset end)
    page.Right:Set(function() return parent.Right() + offset end)
    Run(page, 0.22, function(t)
        offset = math.floor(Scale(from or 24) * (1 - t))
        page.Left:Set(function() return parent.Left() + offset end)
        page.Right:Set(function() return parent.Right() + offset end)
        page:SetAlpha(t, true)
    end, function()
        page.Left:Set(parent.Left)
        page.Right:Set(parent.Right)
        page:SetAlpha(1, true)
    end)
end

--- A dialog opening: its cover darkens in and its panel rises a little into place while it fades in.
function DialogIn(cover, panel, root)
    local Scale = LayoutHelpers.ScaleNumber
    Run(cover, 0.2, function(t)
        cover:SetAlpha(t, true)
        local rise = math.floor(Scale(16) * (1 - t))
        panel.Top:Set(function() return root.Top() + math.floor((root.Height() - panel.Height()) / 2) + rise end)
    end, function()
        cover:SetAlpha(1, true)
        LayoutHelpers.AtCenterIn(panel, root)
    end)
end

--- Rows filling a list: each fades in a little after the one above it (at most `limit` rows staggered).
function RowsIn(rows, limit)
    for i, row in rows do
        if i > (limit or 12) then
            break
        end
        local control = row
        Run(control, 0.16, function(t)
            control:SetAlpha(t, true)
        end, function()
            control:SetAlpha(1, true)
        end, { delay = (i - 1) * 0.02 })
    end
end
