---
name: project_debugcanvas_screentext_addtext_orphaned
description: FUN_0064CC70/FUN_0064CB90 (builds+appends an SDebugScreenText onto CDebugCanvas::screenText@+0x20) has zero callers anywhere. Traced further than the 2026-08-25 note left it -- CDebugCanvas::AddText itself is ALSO uncalled, so this is a whole debug-overlay feature missing its trigger site(s), not just one leaf function. Low priority (debug-only tooling), documented for a future focused pass.
metadata:
  type: project
---

## Starting point

`FUN_0064CC70` (`src/sdk/moho/sim/Sim.cpp`, status `wip` since 2026-08-25,
worker `claude-db-audit`, stale claim) is a real, structurally-sound
function: calls `sub_64CB90` (builds an `SDebugScreenText` record: 3
`Vec3f` + text + pointSize + color) then the already-recovered
`msvc8::vector<SDebugScreenText>::push_back` (`FUN_0064E120`). Its own DB
note already ruled out `RDebugGrid.cpp`/`RDebugRadar.cpp` as callers and
flagged "likely a third debug-overlay class not yet checked, or a caller
source file whose recovered code needs updating to add a currently-
missing call."

## Traced further this session (2026-09-02)

- `sub_64CC70`'s asm (`0x0064CC70`-`0x0064CCBA`) does `add eax, 0x20` on
  its first stack argument before the push_back call. `CDebugCanvas`
  (`src/sdk/moho/sim/CDebugCanvas.h:200-205`, `sizeof == 0x40`) declares
  `lines@0x00, worldText@0x10, screenText@0x20, decals@0x30` (four
  `msvc8::vector<T>` members, each the 0x10-byte debug-proxy shape) — the
  `+0x20` offset is an EXACT match for `screenText`. So `sub_64CC70`
  takes a `CDebugCanvas*` (or equivalent) as its first argument and
  appends onto ITS `screenText` vector. High confidence this is real.
- Checked the sibling method `CDebugCanvas::AddText` (`0x00652C00`,
  `Sim.cpp:9025`) as the obvious candidate caller — it does NOT call
  `sub_64CC70`/`sub_64CB90` at all; it builds an `SDebugWorldText` (a
  DIFFERENT record type, 3D world-positioned) and appends to `worldText`
  instead. Not the caller.
- **`CDebugCanvas::AddText` itself has ZERO callers anywhere in
  `src/sdk`** (`grep -rn "\.AddText(\|->AddText("` — empty). So the whole
  screen/world debug-text feature looks under-wired, not just the one
  leaf function — this is bigger than a single missing call site.
- Checked `RDebugWeapons.cpp` (the one class whose `OnTick` is cited as
  calling `AddWorldText` on a sibling instantiation, `Sim.cpp:9198`'s own
  doc comment) — it DOES call `debugCanvas->AddWorldText(label)`
  (`RDebugWeapons.cpp:219`) but has no screen-text equivalent call.

## Why not resolved this pass

This is no longer "find one missing call site" (which would have been a
quick, well-scoped fix) — it's "find where in the whole recovered tree a
`CDebugCanvas`-driven screen-text debug overlay is meant to be triggered
from," which could be any debug/dev-console command, any `R*Debug*`-
pattern renderer class not yet checked, or a UI-side toggle. Worth a
dedicated pass with `grep -rn "class R.*Debug\|class.*Debug.*Renderer"`
across `src/sdk` to enumerate every debug-overlay class candidate
systematically, then check each for a `screenText`-shaped record build,
rather than checking classes one at a time by name-guessing (which is
what both this pass and the 2026-08-25 original diagnosis did).

Low priority: this is debug/dev-only overlay tooling (2D on-screen debug
text labels), not gameplay-visible or spawn-path-adjacent — does not
affect the standing "commander spawning" goal or any player-facing
behavior. `sub_64CC70`/`sub_64CB90` stay correctly `wip` (not `blocked`,
per RULE TWO) pending the real trigger site.
