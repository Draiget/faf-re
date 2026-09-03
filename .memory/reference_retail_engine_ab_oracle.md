---
name: reference_retail_engine_ab_oracle
description: The retail ForgedAlliance.exe next to our main.exe is a runnable oracle - same switches, same log format. Diffing the two logs on the same map answers "is this behaviour ours or the engine's" in one run, and its Heap line gives an absolute memory budget.
metadata:
  type: reference
---

## The oracle

`C:\ProgramData\FAForever\bin\ForgedAlliance.exe` is the shipped engine, sitting
in the same directory our `main.exe` is staged into. It takes the **same command
line** and writes the **same log format**, so it is a direct control for any
"does the real engine do this?" question:

```powershell
$env:FAF_HANG_TIMEOUT_MS = "240000"
& dbgrun.exe "C:\ProgramData\FAForever\bin\ForgedAlliance.exe" `
             "C:\ProgramData\FAForever\bin" /windowed 1024 768 /map SCMP_009 /log retailheap
```

Run ours the same way with a different `/log` tag, then diff. Two things it gives
you that nothing else does:

**1. An absolute memory budget.** Both print
`Session time / Game time / Heap: <total> / <inUse>`. Retail on SCMP_009 at Game
time 00:00 is **320.0M / 293.3M**. That is the number to hold ourselves to; see
[[project_commander_crash_is_memory_exhaustion]], where ours was 640.0M / 632.4M
and the 2.16x is what drove the allocator off a cliff.

**2. Which log lines are ours and which are the engine's.** Normalise and diff
the message *shapes*:

```bash
norm() { sed -E 's/0x[0-9a-fA-F]+/HEX/g; s/[0-9]+/N/g; s/^[[:space:]]+//' "$1" | cut -c1-110 | sort -u; }
comm -23 <(norm retail.sclog) <(norm ours.sclog)   # retail does, we never do
norm ours.sclog | sort | uniq -c | sort -rn | head -25   # what we spam
```

Findings from the first use of this, all still open unless noted:

- **462 failed module imports we make and retail makes zero of.** We warn
  `Unable to find file /env/evergreen/props/rocks/rockNN_script.lua` +
  `Problems loading module ... Falling back to 'Prop'` 146x *per rock type*.
  Retail emits **none of the four** warnings in
  `ResolveBlueprintScriptFactory` (`Entity.cpp`, `FUN_00677360`) -- not
  "Problems loading module", not "exists but doesn't define", not "Can't find
  module", not "Can't tell the type". The `<id>_script.lua` synthesis itself
  **is** in the binary (verified in `FUN_00677360.c`: `substr(mSource, 1,
  rfind('_')-1)` then `"/" + that + "_script.lua"`), reached only when
  `blueprint->mScriptModule` is empty -- so the likely gap is that
  `mScriptModule` is never populated on our side and every entity silently
  relies on the synthesis. It happens to produce the right path for units, which
  is why only props show it.
- **Retail sends `GpgNetSend JsonStats` at tick 121; we never do.** Retail's dump
  is a per-army ground truth: `"blueprints":{"uel0001":{"built":1}}`,
  `"cdr":{"built":1}`, `currentunits` 1 for the human and 2 for each AI. That is
  the cheapest possible answer to "did the commander spawn".
- Retail plays `/movies/UEF_load.sfd` on this path; we do not.
- Retail emits `MEM: <n> bytes <SUBSYSTEM>` accounting lines (SND, RULE, STIMap,
  LoadTexturing, WaterMask, TERRAIN, LUABP, OGRID); we emit six lines total.
- Retail out-spams *us* on Lua `lazyvar`/`control.lua` tracebacks (2604 vs 462)
  while using half the memory -- so Lua error spam is not a memory driver, and
  those warnings are not a defect on our side.

## Caveats

- Retail writes to the same `game.prefs`; harmless but not zero-side-effect.
- Match how far each run got before comparing counts. Retail reaching Game time
  00:12 and ours 01:52 makes raw counts misleading; compare at the same
  `Session time`/`Game time` checkpoint.

Related: [[reference_dbgrun_crash_harness]],
[[reference_game_log_flag_is_single_slash]].
