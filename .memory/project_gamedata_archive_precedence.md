---
name: project_gamedata_archive_precedence
description: FAF gamedata archive override order is NOT what the extensions imply - lua.nx2 (2026) is live FAF code, faforever.faf (2022) is stale; three Buff.lua versions ship at once
metadata:
  node_type: memory
  type: reference
---

Game Lua lives in `C:\ProgramData\FAForever\gamedata\*` — all plain zips.
Unpack with `skills/fa-bug-hunt/scripts/unpack_gamedata.py --dst gamedata`
(gamedata/ is gitignored; `_origin.json` records which archive won each file).

**Override order is counter-intuitive.** Measured from mtimes on a live install:

| archive        | date       | status                                    |
|----------------|------------|-------------------------------------------|
| `faforever.faf`| 2022-04-01 | LEGACY / stale — do not read              |
| `*.nx5`        | 2025-03-23 | Forged Alliance baseline                  |
| `*.nx2`        | 2026-04-21 | **CURRENT FAF patch — highest priority**  |

The FAF client rewrites the `.nx2` set on patch, so `.nx2` is newest despite
`.nx2` meaning "SupCom base" in original FA naming.

**Three `lua/sim/Buff.lua` ship simultaneously:** 27782 (lua.nx2, live),
24168 (lua.nx5), 20961 (faforever.faf). They all parse and define the same
symbols, so reading the wrong one yields a confident, wrong analysis. The
stale `faforever.faf` copy contains a **`DoNoFill` typo** (missing 't') that
does NOT exist in live code — if you ever see `vals.DoNoFill`, you are reading
2022 code and must re-extract.

Two extraction orders that are BOTH wrong: plain alphabetical (gives lua.nx5)
and ranking `.faf` last because it "looks like the patch" (gives 2022 code).

**Buff definitions are not confined to `lua/sim/BuffDefinitions.lua`.** Auras
and enhancements are constructed at RUNTIME inside unit scripts
(`units/XSL0001/XSL0001_script.lua` etc.), attaching affects by mutation after
the table literal:

    local buff_bp = { Name = 'SeraphimACURegenAura', Duration = 5, ... }
    buff_bp.Affects.MaxHealth = { Add = 0, Mult = ..., DoNotFill = true }
    BuffBlueprint(buff_bp)

One file can define several. A scanner matching only `BuffBlueprint {` literals
misses them; one that falls back to whole-file parsing collapses them into one
(my first cut reported 1 of the 2 Seraphim auras). `enum_state_producers.py`
segments on `Name = '...'` boundaries to handle both.

Related: [[project_air_staging_detach_exact_compare]]
