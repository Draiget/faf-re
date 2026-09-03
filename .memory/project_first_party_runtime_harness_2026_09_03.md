---
name: project_first_party_runtime_harness_2026_09_03
description: dbgrun rebuilt from scratch 2026-09-03 - runtime verification is no longer blocked. Commander spawn CONFIRMED working; terrain overexposure is NOT lighting constants or texture binding.
metadata:
  type: project
---

## The harness is back, and it is cheap to rebuild

`dbgrun` was gone from this machine. It is ~250 lines and took one pass to
rewrite; the source lives in the session scratchpad as `dbgrun.cpp`. Build:

```
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul && cl /nologo /EHsc /O2 /D_CRT_SECURE_NO_WARNINGS dbgrun.cpp /Fe:dbgrun.exe /link dbghelp.lib'
```

Run (PowerShell, NOT Git Bash -- bash mangles `/map` into a path):

```powershell
$env:FAF_HANG_TIMEOUT_MS = "420000"
Start-Process -FilePath dbgrun.exe -ArgumentList `
  '"C:\ProgramData\FAForever\bin\main.exe"','"C:\ProgramData\FAForever\bin"', `
  '/map','SCMP_009','/windowed','1024','768','/log','tag' `
  -RedirectStandardOutput run.log -RedirectStandardError run.err -NoNewWindow
```

**Two gotchas that each cost a rebuild:**

- `SymInitialize(hProcess, path, TRUE)` fails with `0x8000000D` when called
  right after `CreateProcess` -- the debuggee's module list is not walkable
  yet. Use `fInvadeProcess = FALSE` and call `SymLoadModule64` from the
  `CREATE_PROCESS_DEBUG_EVENT` / `LOAD_DLL_DEBUG_EVENT` handlers, using the
  `hFile` and base the event hands you. Then `symbols=1` and stacks resolve.
- Writing C source through a bash heredoc turns `\n` inside a C string
  literal into a real newline (`error C2001: newline in constant`). Use the
  Edit tool for anything containing escape sequences, or build the backslash
  with `chr(92)` in Python.

`msbuild src/sdk/main.vcxproj` stages `main.exe` **and** `main.pdb` straight
into `C:\ProgramData\FAForever\bin`, so there is no copy step. Map load takes
4-8 minutes under the debugger; poll for a probe string rather than guessing.

## What the first runs settled

**The commander spawns.** A 300-second run reached the full in-game state:
`FAF_Draiget: Armored Command Unit`, 11500/11500 +10/s, +1 mass / +20 energy,
veterancy 0/1000, the whole ACU ability list, 650 mass / 4000 energy bars,
command panel, build menu, minimap frame, `[FRAMEDIAG] visited=650 peak=650
ticked=8`. **No fault.** The `ClusterMap::DirtyRect` crash the operator
reported at commander spawn did **not** reproduce on the same map.

**`IWldTerrainRes::Finalize` now runs**, which it never had before (see
[[project_terrain_finalize_had_no_caller]]):

```
[TERRDIAG] Finalize: entering
[TERRDIAG] InitNormalMap field=1025x1025 tile=1024x1024 tiles=1x1=1
[TERRDIAG] Finalize: returned 1
[TERRDIAG] normalMapCount=1
```

## The terrain overexposure is NOT what the old notes assumed

Side-by-side against the retail `ForgedAlliance.exe` on the same map (just run
it with the same args and PrintWindow it -- ground truth is one command away),
the reference renders textured green/brown ground; ours renders a blown-out
pale wash. Ruled out, with evidence:

- **Lighting constants are byte-exact.** `SCMP_009.scmap` carries the lighting
  block at file offset **0x2411CC**: `1.5400 | 0.6161 0.5592 0.5547 | 0.0000
  0.0000 0.0000 | 1.3800 1.2900 1.1400 | 0.5400 0.5400 0.7000 | 0.3100 0 0 0 |
  0.0362 | 0.3700 0.4900 0.4500 | 0 740`. Our `[LIGHTDIAG]` reports exactly
  those. **SunAmbience really is (0,0,0) on this map** -- do not "fix" it.
  (Find the block by scanning for a float in [1.53,1.55] followed by one in
  [0.61,0.62]; the naive header walk desyncs.)
- **Every stratum texture is resident**: `shader='TTerrain' maskA=1 maskB=1
  water=1 lower=1 upper=1 albedo=11110000 normal=11110000` (strata 4-7 unused
  by this map).
- **`SNormalMapInfo` is all floats**, so the `TTerrainBasis` tile loop is not
  feeding integer bit patterns into float shader constants.

So the defect is downstream of constants and binding -- in what the passes
sample or how they compose. Next: the normals target contents and the
`TTerrainNormals` -> `TCreateBasis` -> composite chain.

## Still open

- Operator reports **"crashed on move order"** -- and an unprompted
  worker-thread fault did fire in one run: `ACCESS_VIOLATION reading
  666F7270`, i.e. the ASCII `"prof"` being dereferenced as a pointer. That is
  a pointer field holding string bytes, in a background thread, which fits the
  path-cluster subsystem the operator's own stack implicated
  (`ClusterMap::DirtyRect`). Symbols were still broken on that run; re-run
  with the fixed harness to get a named stack.
- The commander **mesh** does not render even though the unit exists (the
  reference shows it plainly). Minimap content is blank and range rings are
  absent.

Related: [[project_terrain_finalize_had_no_caller]],
[[feedback_orphan_function_means_missing_caller_block]],
[[feedback_gitbash_path_mangling_dbgrun_args]].
