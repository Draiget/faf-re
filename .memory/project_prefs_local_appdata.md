---
name: project-prefs-local-appdata
description: FIXED (968fb02) - USER_LoadPreferences resolved CSIDL_APPDATA (Roaming) where the binary pushes 1Ch (CSIDL_LOCAL_APPDATA), so the engine never saw the player's real Game.prefs and started an empty one beside it.
metadata:
  type: project
---

# FIXED: the engine wrote its own empty Game.prefs

Symptom chain: the Profile Manager list came up empty, "Options" answered with
"You must create at least one profile", and a profile created under test
persisted across runs while the player's real one never appeared.

`USER_LoadPreferences` (FUN_008C89D0) built the preference directory from
`SHGetFolderPathW(..., CSIDL_APPDATA, ...)`. The binary pushes `1Ch` at
`0x008C8A2B` - **CSIDL_LOCAL_APPDATA**. Forged Alliance has always kept
`Game.prefs` under Local, and Local is also what `init_faf.lua` mounts as
`/preferences` (`SHGetFolderPath('LOCAL_APPDATA')`).

Two files on disk was the giveaway:

    %LOCALAPPDATA%\Gas Powered Games\Supreme Commander Forged Alliance\Game.prefs   78 KB, the player's
    %APPDATA%\Gas Powered Games\Supreme Commander Forged Alliance\Game.prefs         8 KB, ours

Note the Lua-side `SHGetFolderPath` binding was already correct - its
`kUnsafePaths` table maps `LOCAL_APPDATA -> 28` and looks up with `strcmp`.
Only the C++ preference loader was wrong, so the VFS mount and the loader
disagreed about where preferences live.

Side effect worth remembering: with the real prefs loaded the UI comes up at
the player's saved `ui_scale`, which can overflow a small `/windowed` client -
the main menu's lower buttons fall off the bottom at 1024x768. Not a bug.

## The "language is CN" report was a symptom of this, not a separate bug

Verified by probe: `__language` is `'US'` and `__installedlanguages` holds all
eleven entries (CN CZ DE ES FR IT PL RU TW TZM US), and `DiskFindFiles("/loc/",
"*strings_db.lua")` returns all eleven. What the options dialog shows is
`combo.SetCustomData`'s `default = 1` fallback, taken whenever
`currentOptionsSet['selectedlanguage']` matches no `val.key`. Keys are
upper-cased; a profile created from nothing gets `'us'` **lower**-case, because
`okLanguage` returns the literal `"us"` and userInit writes that back. So a
brand-new profile always displays CN (alphabetically first) - stock behaviour,
and it went away with the player's real profile restored.

**Probe hygiene, learned the hard way**: do not call `lua_tostring` on the key
during a `lua_next` traversal - it converts the key in place and the next step
dies with "invalid key for `next`", which reads exactly like an engine bug in
the table code. Use `lua_tonumber`/`lua_type` on the key instead. And never
write into a table a probe is only supposed to observe: overwriting the
`DiskFindFiles` result corrupted the mod list and killed UI init.

Related: [[project-lua-strlen-pseudo-index]].
