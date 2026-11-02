# Retail call recorder

Records the calls the original `ForgedAlliance.exe` makes to chosen functions while it plays a replay, in faf_math_dump's values format, so `faf_math_dump --values <file>` checks our functions against what the original computed in a real game. It is the way to check sim functions that run on real game state (the inventory of functions the sim checksum depends on is far larger than what hand-built difffuzz inputs reach).

- `recorder_dll.cpp`: x86 DLL loaded into the game. Each hooked entry jumps to a stub that saves every register and the whole FPU/SSE state (pushad, fxsave), records the arguments, runs the function through a trampoline (its first whole instructions, then a jump back) and records the result (`eax`, or `st0` read from the fxsave image) on the way out, then restores everything. The hook table is `kHooks`: entry address, prologue bytes to copy (whole instructions, at least 5, no relative branches), the difffuzz row name, the stack argument words, the result kind, and how many calls to keep (all up to a cap, then one in N).
- `launcher.cpp`: `recorder.exe <out.txt> <timeout-s> <game-log|-> <exe> [args...]` starts the game minimized, loads the DLL once the window is idle (loading it into the process while suspended crashed in the thread pool and the CRT), and ends the game at the parity hook's `over=true` heartbeat or the timeout.
- `build.bat`: builds both with MSVC for x86 into `build\`.

A run, with the init file the replay parity runner generates next to the exe (`init_file_for` in `tools/replay-parity/parity.py`):

```
recorder.exe out.txt 1500 game.log C:\ProgramData\FAForever\bin\ForgedAlliance.exe /init init_parity.lua /nobugreport /replay <id>.scfareplay /replayid <id> /nosound /nomovie /windowed 640 480 /log game.log
faf_math_dump --values out.txt --filter <row>
```

From Git Bash, keep its path conversion off the game's `/flags` (`MSYS2_ARG_CONV_EXCL='/init;/nobugreport;/replay;...'`). Check the game log for `Checksum for beat ... mismatched` lines: none means the recorded game stayed in sync with the replay.

First result: atan2f (0x004E9DF0) during replay 26902315, 21,128 recorded calls, ours identical on every one, and no checksum mismatch in the game.

## Spec mode: every hookable function at once

`spec.py <inventory.tsv> <spec.bin> <report.txt>` derives the hook table from the IDA exports instead of the hand-written `kHooks`: for each inventory address it parses the prologue (whole instructions, no relative branches, no jump into the copied bytes), the `ret N` pop (both `ret 0x58` and `retn 58h` spellings; disagreeing sizes mean an SEH continue path and the function is not hooked), the Hex-Rays prototype's arguments and result, and whether the function writes outside its result and frame (directly or through any callee — the transitive closure). The DLL takes the spec via `RETAIL_RECORDER_SPEC` (`RRS2`; see `SPEC_FORMAT.md`). `spec_slice.py` cuts a spec into halves/subsets for bisecting a crashing set; `run_one.ps1` runs one spec against the replay and classifies the outcome (OK / CRASH / loader stall with retry).

Known limits, from bisecting the all-functions set against replay 26902315:

- MSVC8 SEH functions with several `ret N` sizes must not be hooked (the unwind matcher needs the one pop the taken path uses); the parser rejects them.
- Hook sets of ~1,900 entries run clean for a full replay; the full ~3,850-entry set still stalls the map loader on this machine under multi-session load, flakily — run halves, and use `run_one.ps1 -MaxAttempts` to retry loader stalls.

## Probe mode: edge-value re-calls on the real objects

With `RETAIL_RECORDER_PROBE=1` and `RETAIL_RECORDER_JOURNAL=<path>`, after a real call of a probe-safe function (`writes == 0`, at least one hashed argument) the recorder re-calls it with its own arguments and then with each edge value in place of one argument, and records the real call (`R` lines), the results (`P` lines) and pointer-argument snapshots before/after (`S` lines) to the output file. Probes run only past a 60s grace period on the elected leader (hottest) thread; the journal (`<va> <probesDone> <state> <writes>`) is rewritten around every round so a probe that kills the process is skipped on the next run. Format details: `SPEC_FORMAT.md`.
