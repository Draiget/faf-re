---
name: reference-decomp-read-helper
description: decomp_read.py prints windows of a FUN_*.c/.asm instead of the whole file; the four token sinks it and the SKILL.md "Token discipline" section exist to kill.
metadata:
  type: reference
---

`python skills/fa-binary-reassembly/scripts/decomp_read.py FUN_XXXXXXXX` —
reads exported decompiles without pulling the whole file into context.

    -p "<regex>" -C 6   windows around each match (the normal mode)
    --meta              callers / callees / size / instruction_count
    -l N -n M           a known line range
    --asm               read FUN_*.asm instead of FUN_*.c
    (no flags)          declaration + every call/string landmark

Measured on `FUN_007C38C0` (CLobby::LaunchGame, 877 lines): reading it whole
cost ~15k tokens; `-p "LaunchFailed" -C 2` answered the same question in 21
lines.

## The four sinks this exists to stop

1. **`ls` on the namespace dir.** Hundreds of thousands of files: the call
   times out at 120s, returns nothing, and leaves a background task behind.
   Hit again on 2026-08-14 despite being known. Use `Glob` with a full
   `FUN_XXXXXXXX*` pattern, or just build the path — the token is always known.
2. **Whole-file `.c` reads.** 100-900 lines each; the useful part is the few
   lines around a named call or a struct displacement.
3. **Header-decl → cpp-definition walks.** One `rg -n "Class::Method" <file>`
   lands it; three calls were being spent on two.
4. **Re-grepping to disprove a redacted grep.** `rg` content output garbles
   symbol text (worst on gamedata Lua). `rg -l`/`-c` to locate, `Read` for
   content, and do not spend a second call confirming the garbling.

Plus one diagnostic habit, not a tool: when shipped FAF Lua raises, the engine
defect is usually *upstream* of the raise. `gameInfo.PlayerOptions:pairs()`
failing was legal - `GameInfo.Flatten` had already replaced the
`WatchedValueArray` with a plain table at lobby.lua:2198 - and the real fault
was whatever made `LaunchFailed` fire. See
[[project_lobby_launch_doscript_substitutes]].

Written into `.claude/skills/continue-recovery/SKILL.md` as "Token discipline"
so it loads on every `/continue-recovery`.
