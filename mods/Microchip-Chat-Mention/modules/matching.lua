-- Pure matching logic; use literal searches so punctuation in names is safe.
function Normalize(value)
    value = type(value) == 'table' and value or {}
    local seconds = tonumber(value.seconds) or 10
    if seconds ~= seconds then seconds = 10 end
    local fontSize = tonumber(value.fontSize) or 17
    if fontSize ~= fontSize then fontSize = 17 end
    return {
        enabled = value.enabled ~= false,
        nicknames = type(value.nicknames) == 'string' and string.sub(value.nicknames, 1, 256) or '',
        seconds = math.max(1, math.min(120, math.floor(seconds))),
        simulation = value.simulation == true,
        sound = value.sound == true,
        fontSize = math.max(12, math.min(32, math.floor(fontSize))),
    }
end

local function Word(char)
    return char ~= '' and (string.find(char, '[%w_]') ~= nil or string.byte(char) >= 128)
end

local function Contains(text, name)
    if name == '' then return false end
    local start = 1
    while true do
        local first, last = string.find(text, name, start, true)
        if not first then return false end
        local before, after = string.sub(text, first - 1, first - 1), string.sub(text, last + 1, last + 1)
        if (not Word(string.sub(name, 1, 1)) or not Word(before))
            and (not Word(string.sub(name, -1)) or not Word(after)) then return true end
        start = last + 1
    end
end

function Match(text, playerName, nicknames)
    if type(text) ~= 'string' then return false end
    text = string.lower(text)
    if type(playerName) == 'string' and Contains(text, string.lower(playerName)) then return playerName end
    for name in string.gfind(nicknames or '', '[^,;\n]+') do
        name = string.gsub(string.gsub(name, '^%s+', ''), '%s+$', '')
        if Contains(text, string.lower(name)) then return name end
    end
    return false
end
