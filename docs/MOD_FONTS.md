# Fonts and text scale for mods

Two calls for mods, in the user interface's Lua only. Neither exists on the shipped game, so check for them first, and a mod keeps working there. FAF's Lua stops a script that reads a global it doesn't have, so `LoadFont and ...` is an error there: read it with `rawget(_G, 'LoadFont')`.

## Load a font

```lua
-- nil when the engine lacks the call or the file is refused
local LoadFont = rawget(_G, 'LoadFont')
local family = LoadFont and LoadFont('/mods/MyMod/fonts/MyFont.ttf')
if family then
    text:SetFont(family, 14)
end
```

- The file must be a `.ttf` or `.otf` under `/mods/<mod>/fonts/`, inside a folder or a zipped mod.
- The name you get back looks like `mod:3fa9...`. It belongs to that file's bytes, so loading the file twice gives the same name, and a mod can't replace `Arial` or any other family the game uses.
- A font is cooked the first time it's loaded, which takes about a second (1.3 s for Arial with its small sizes), and then read from a cache. Until it's ready, text draws in the default font and `TextAdvance` holds that font's width. It updates when the font arrives, so build your layout from `LazyVar`s and not from a width you read once.
- Characters the font lacks draw from the default font.

**A file is refused**, with one warning in the log and `nil` from `LoadFont`, when:

- its path breaks the rule above, or it's over 32 MB;
- it isn't a plain TrueType or OpenType file: no font collections or WOFF, nothing after the last table, and only tables real fonts use. Variable fonts and bitmap or color fonts are refused;
- the mod has already loaded 16 fonts this session, or the player has turned mod fonts off with `ren_ModFonts 0`.

**A font can also be refused while it cooks**, after `LoadFont` has given its name, when:

- it has over 8,192 edges in a glyph or 262,144 in the characters used, more than 65,535 glyphs, or glyphs whose distance fields would take far more work than any real font's;
- FreeType needs over 64 MB to read it;
- the game closed while it was cooking, on two starts.

Its text then stays in the default font. The refusal is remembered, so on later starts `LoadFont` answers `nil` for that file without another attempt. A cook still running after a minute gives up for that session only, since that depends on the machine.

A mod's font can reach every player in a game, so it cooks with those limits, and with FreeType's hinting programs off, on the game's background font thread.

## Scale text

```lua
if text.SetTextScale then
    text:SetTextScale(1.5)            -- from the control's middle
    text:SetTextScale(1.5, 0, 0.5)    -- from the middle of its left edge
end
```

- `scale` runs from 0, which hides the text, to 64. 1 is normal size, and `GetTextScale` returns the current value.
- It changes only how the text draws, not the layout: `Width`, `TextAdvance` and what the control's parent sees stay the same, and text clipped to its width clips at the same character.
- It's cheap enough to change every frame, for text that pops in or pulses. `SetFont` with each size makes a new font every time, stays in memory, and takes whole pixel sizes only, so use it for a size that stays.
- Text stays sharp at any scale where it draws from a distance field, which is the default. With `ren_MsdfText 0` it stretches its small bitmaps instead.
