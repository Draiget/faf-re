-- Keep the fixture compatible with FAF Lua 5.0 and stock Lua 5.3.
if not table.getn then
    table.getn = function(t)
        return rawlen(t)
    end
end

local rawLoadfile = loadfile
local function loadfile(path, mode, env)
    if setfenv then
        local f, err = rawLoadfile(path)
        if f and env then
            setfenv(f, env)
        end
        return f, err
    end
    return rawLoadfile(path, mode, env)
end

local base = arg[1]
for i = 0, 4 do
    assert(loadfile(base .. '/source_' .. i .. '.lua'))
end

local function clone(t)
    local c = {}
    for k, v in pairs(t) do
        c[k] = v
    end
    return c
end

local function scenario(detector)
    local calls = {}
    local saved = {}
    local saves = 0
    local opts = {
        video = {
            items = {
                {key = 'fidelity', default = 1},
                {key = 'vsync', default = 1},
            },
        },
    }
    local env = setmetatable({
        options = opts,
        ConTextMatches = detector,
        ConExecute = function(x)
            calls[table.getn(calls) + 1] = x
        end,
    }, {__index = _G})
    assert(loadfile(base .. '/source_0.lua', 't', env))()

    local found
    for _, v in ipairs(opts.video.items) do
        if v.key == 'splat_budget_tier' then
            found = v
        end
    end
    return env, opts, calls, found
end

-- Unsupported or malformed capability responses must hide the option.
for _, detector in ipairs({
    function()
        return {}
    end,
    function()
        return {'ren_SplatBudgetTierOther'}
    end,
    function()
        error('missing')
    end,
    function()
        return 'bad'
    end,
}) do
    local e, o, c, f = scenario(detector)
    assert(not f and table.getn(c) == 0)
end

local e, o, c, f = scenario(nil)
assert(not f and table.getn(c) == 0)
e, o, c, f = scenario(function(command)
    assert(command == 'ren_SplatBudgetTier')
    return {'other', 'ren_SplatBudgetTier'}
end)
assert(f and f.default == 0 and o.video.items[2] == f and table.getn(f.custom.states) == 4)
assert(not f.update and not f.cancel and not f.restart)
for tier = 0, 3 do
    assert(f.custom.states[tier + 1].key == tier)
end

-- Reloading the hook must not add a second splat option.
assert(loadfile(base .. '/source_0.lua', 't', e))()
local count = 0
for _, v in ipairs(o.video.items) do
    if v.key == 'splat_budget_tier' then
        count = count + 1
    end
end
assert(count == 1)

for tier = 0, 3 do
    local n = table.getn(c)
    f.set(f.key, tier, false)
    assert(table.getn(c) == n + 1 and c[n + 1] == 'ren_SplatBudgetTier ' .. tier)
end
for _, v in ipairs({-1, 4, 1.5, '1', '2;quit', {}, true, (1 / 0), 0 / 0}) do
    local n = table.getn(c)
    f.set(f.key, v, false)
    assert(table.getn(c) == n + 1 and c[n + 1] == 'ren_SplatBudgetTier 0')
end
f.set(f.key, nil, true)
assert(c[table.getn(c)] == 'ren_SplatBudgetTier 0')

local n = table.getn(c)
e.ConTextMatches = function()
    return {}
end
f.set(f.key, 3, true)
assert(table.getn(c) == n)
e.ConTextMatches = function()
    return {'ren_SplatBudgetTier'}
end

-- Run the actual options logic with an in-memory preferences backend.
local saved = {}
local saves = 0
local prefs = {
    GetFromCurrentProfile = function()
        return clone(saved)
    end,
    SetToCurrentProfile = function(k, v)
        assert(k == 'options')
        saved = clone(v)
    end,
}
local logicEnv = setmetatable({
    import = function(path)
        if path == '/lua/user/prefs.lua' then
            return prefs
        elseif path == '/lua/options/options.lua' then
            return {options = o}
        end
        error(path)
    end,
    GetPreference = function()
        return nil
    end,
    SavePreferences = function()
        saves = saves + 1
    end,
}, {__index = _G})
assert(loadfile(base .. '/source_2.lua', 't', logicEnv))()
local cur = logicEnv.GetCurrent()
assert(cur.splat_budget_tier == 0 and saves == 1)
logicEnv.Apply(true)
assert(c[table.getn(c)] == 'ren_SplatBudgetTier 0')

local before = table.getn(c)
local pending = clone(cur)
pending.splat_budget_tier = 3
local kills = 0
local exits = 0
local confirmations = 0
local cancelCalls = 0
local cancelProbe = {
    key = 'probe',
    cancel = function()
        cancelCalls = cancelCalls + 1
    end,
}
local dialogEnv = setmetatable({
    dialog = {cancelBtn = {}},
    applyBtn = {},
    resetBtn = {},
    currentOptionsSet = pending,
    currentTabButton = {tabData = {items = {f, cancelProbe}}},
    OptionsLogic = logicEnv,
    KillDialog = function()
        kills = kills + 1
    end,
    exitBehavior = function()
        exits = exits + 1
    end,
    UIUtil = {
        QuickDialog = function(dialog, text, yes, onYes)
            confirmations = confirmations + 1
            onYes()
        end,
    },
}, {__index = _G})
assert(loadfile(base .. '/dialog_handlers.lua', 't', dialogEnv))()

-- Execute the actual Cancel handler with a changed staged value.
dialogEnv.dialog.cancelBtn.OnClick()
assert(saved.splat_budget_tier == 0 and table.getn(c) == before)
assert(kills == 1 and exits == 1 and cancelCalls == 1)

-- Cancel also handles a missing active tab and optional exit callback.
dialogEnv.currentTabButton = nil
dialogEnv.exitBehavior = nil
dialogEnv.dialog.cancelBtn.OnClick()
assert(kills == 2 and exits == 1 and table.getn(c) == before)

pending.splat_budget_tier = 2
dialogEnv.applyBtn.OnClick()
assert(saved.splat_budget_tier == 2 and c[table.getn(c)] == 'ren_SplatBudgetTier 2')
logicEnv.Apply(true)
assert(c[table.getn(c)] == 'ren_SplatBudgetTier 2')
dialogEnv.resetBtn.OnClick()
assert(confirmations == 1 and kills == 3)
assert(saved.splat_budget_tier == 0 and c[table.getn(c)] == 'ren_SplatBudgetTier 0')

saved.splat_budget_tier = '2;quit'
logicEnv.Apply(true)
assert(c[table.getn(c)] == 'ren_SplatBudgetTier 0')
local tipsEnv = setmetatable({Tooltips = {}}, {__index = _G})
assert(loadfile(base .. '/source_1.lua', 't', tipsEnv))()
assert(tipsEnv.Tooltips.options_splat_budget_tier.description:find('2,499', 1, true))
print('PASS UI: parse five sources; capability, unsupported, duplicate, four tiers, invalid values, injection, capability loss, preferences and actual Apply/Reset/Cancel handlers')
