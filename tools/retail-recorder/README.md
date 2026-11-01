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
