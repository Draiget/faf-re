---
name: project_adxm_framework_inversion
description: Movie playback hung in CMovie::OpenMovie's prepare loop because adxmng_DecideFramework's ternary was inverted; fixed e136f85. Includes the affinity interaction and the run harness that hid it.
metadata:
  type: project
---

# The "Preparing movie" infinite loop — root cause and fix (LANDED e136f85)

`CMovie::OpenMovie` spun forever logging `debug: Preparing movie /movies/thqlogo.sfd: 1`
and no movie ever played. Root cause was **one inverted ternary** in
`adxmng_DecideFramework` (0x00B10710, `src/sdk/cri/sofdec/SofdecAdxPlatformRuntime.cpp`).

The binary computes `2 - (ADXM_IsSetupThrd() != 1)`:

```
call _ADXM_IsSetupThrd   ; 1 when the ADXM workers are up, else 0
dec / neg / sbb eax, eax ; up -> 0, down -> -1
add eax, 2               ; up -> 2, DOWN -> 1
```

So **workers up → lane 2, workers down → lane 1**. Lane 1 is the *no-worker
fallback*: `ADXMNG_CallMainServerFunctions` runs `ADXM_ExecSvrAll`, i.e. the
calling thread drives every service lane (vint/vsync/fs/main/idle). Lane 2 runs
only the main lane, which is enough when the workers are alive. We had
`(ADXM_IsSetupThrd() == 1) ? 1 : 2` — backwards.

## Why it only bit on this machine

`adxm_create_thrd` pins all four Sofdec threads to **CPU 0** (`kAdxmThreadAffinity = 1`)
and returns -1 if any pin fails. FAF's `C:\ProgramData\FAForever\bin\init.lua`
does this at startup (log line 4, long before the movie):

```lua
if systemAffinityMask >= 16777215 then
    processAffinityMask = 16777212 -- 0x00FFFFFC, "skip the first two computing units"
```

On any host with 24+ logical CPUs, CPU 0 leaves the process mask, every
`SetThreadAffinityMask(h, 1)` fails with **ERROR_INVALID_PARAMETER (87)**
(Windows requires thread affinity ⊆ process affinity), `adxm_setup_thrd` tears
the workers down and returns *without* `++adxm_init_level`. `ADXM_IsSetupThrd()`
then reports 0 — the exact case the inverted ternary got wrong.

Chain of consequences: no vsync lane → `sftim_UpdateTime` never re-arms the SFPLY
per-tick flag at **+0x44** → `sfply_ExecOne` returns immediately forever →
handle stays in PREP (state 2) → `mwlSfdExecDecSvrPrep` never sees SFD stat 4/6
→ `mwPlyGetStat` keeps returning 1 → prepare loop never exits.

## The harness that hid it for a whole session

Every earlier run went through `scratchpad/runaffchk.ps1`, which sets
`$p.ProcessorAffinity = 0xFFFFFFF` 400 ms after launch — restoring CPU 0 before
Sofdec init. So the workers came up, the inversion was benign, and the movie
played. **The decoder-quality work (commits e02a585…49af891) was all measured
through that workaround.** Do not "verify" engine behaviour with a script that
mutates process state.

## Verified against the shipped binary

`ForgedAlliance.exe` launched with `start "" /affinity FFFFFC` (CPU 0+1 excluded
from process creation, so the pin can never succeed) prepares each movie in
**6 iterations** and plays both `thqlogo.sfd` and `gpglogo.sfd`. Ours now also
prepares in exactly 6 and reaches `Playing movie`. Every other function on the
path was checked byte-for-byte and is faithful: `adxm_create_thrd`,
`adxm_setup_thrd` (including its early `return` on failure), `ADXM_IsSetupThrd`,
`ADXM_ExecMain`, `ADXMNG_CallMainServerFunctions`, `ADXM_WaitVsync`,
`mwPlyGetStat`, `SFD_VbOut` (genuinely one `retn`), `mwsfsvr_CheckSupply`
(genuinely one `retn`), `sfply_ExecOne`.

Frame dump confirms rendering: the THQ prism + light swoosh composited correctly.

## Still open after this fix

- **No sound.** Ours logs **0** `Wavebank prepared` lines; the real engine logs
  **270**. That message comes from the XACT notification callback
  `func_HandleSoundEvent` (type 0x11) in `moho/audio/AudioEngine.cpp` — so our
  sound engine never delivers notifications.
- **Second movie never opens.** Real engine opens `/movies/gpglogo.sfd`
  *immediately* after thqlogo's `Playing` line (it is a queued playlist, not a
  wait-for-completion). Ours stops after the first. Engine is alive and pumping
  (window responds, ~11% of one core), so it is idling, not hung.

## Run harness

`.vscode/run-engine.bat` — build + stage + run with **no debugger**, mirroring the
F5 profile. `run-engine.bat nobuild 30` runs the staged exe for 30 s and kills it.
Notes baked in: `/windowed` must come from cmd/PowerShell (Git Bash rewrites it
into a path and the engine seizes the display); the exe must be invoked by full
path (this machine sets NoDefaultCurrentDirectoryInExePath, so a bare `main.exe`
gives 9009); `timeout /t` dies under redirected stdin, so it uses `ping -n`.
