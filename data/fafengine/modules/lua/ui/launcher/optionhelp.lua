-- Help for the options FAF has no tooltip for (mostly the engine's own), in the player's language: the game's
-- language code (__language: 'us', 'ru', 'de', 'fr', 'pl', ...) picks the text, English when there is none in it.
-- Kazakh ('kk') is here for when the game can be set to it.

local texts = {
}

--- The help of option `key` in the player's language, or '' when there is none.
function Help(key)
    local entry = texts[key]
    if not entry then
        return ''
    end
    local language = string.lower(tostring(rawget(_G, '__language') or 'us'))
    return entry[language] or entry.us or ''
end
