# Sim profiling harness (original ForgedAlliance.exe)

External sampling profiler for the shipped FAF `ForgedAlliance.exe` (byte-identical to
`bin/2025.7.1/ForgedAlliance.exe`, the binary behind `fa_full_2026_03_26`). It needs no
symbols and no changes to the game: it suspends busy threads about 300 times a second, reads
their WOW64 context and stack, and symbolizes through the repo's own indexes.

Findings and method: `decomp/recovery/reports/perf/sim_multithreading_investigation_2026-09-24.md`.

## Files

| file | what |
|---|---|
| `build_symbols.py` | Builds `symmap.json`, `symnames.json` and `callsites.txt` from `_callgraph_index.sqlite`, `_source_index.sqlite` and the `.asm` export. Run once per index refresh. |
| `sampler.py` | The profiler. Writes one `win_NNN.json` per minute: per-thread CPU, leaf and inclusive counts, call chains, plus `Sim::mCurTick` and an entity census by id family, read from the live `Sim` object. |
| `run_game.py` | Launches the game (replay or `/map` skirmish), starts the sampler, and posts numpad-`+` so the sim runs flat out. |
| `analyze.py` | Two-axis breakdown of the sim thread. **What** is the innermost recognizable subsystem. **Who** is the beat context: stage A/B, army tick, Lua coroutines, forced GC, sync... |
| `convert_replay.py` | `.fafreplay` to `.scfareplay` (zlib and zstd bodies). Optionally rewrites the engine version string or the map folder. |
| `speedkeys.py` | Posts key presses to the game window (used by `run_game.py`). |
| `vault_scan.py` | Finds big team games recorded on a given FAF game version in the replay vault. It reads only the first 4 KB of each replay (the JSON header), about 8 requests a second. |

## Typical run

```bash
python scripts/perf/build_symbols.py                       # once; tables go to %TEMP%/faf_perf
curl -o 26935800.fafreplay https://replay.faforever.com/26935800
python scripts/perf/convert_replay.py 26935800.fafreplay r.scfareplay
MSYS_NO_PATHCONV=1 python scripts/perf/run_game.py out/r 1500 -- /replay C:/full/path/r.scfareplay /replayid 26935800 /nomovie
python scripts/perf/analyze.py out/r/win_010.json out/r/win_011.json
```

26935800 is a 12-player Dual Gap game recorded on game version 3835 (40:53 of game time). On 3835
it plays to `GameEnded` with no checksum mismatch, reaches about 4,400 units and 25,000 entities,
and the sim runs flat out from about the 30-second mark. The whole game takes about 25 minutes of
wall time on a fast desktop.

## Finding a replay that plays clean

Only a replay recorded on the local game version replays without desync (see the caveats). To find
one, look the version up in `lua/version.lua` inside `gamedata/lua.nx2`, then scan the vault range
where that version was current:

```bash
python scripts/perf/vault_scan.py 3835 26800000 27100000 found.jsonl
```

Phase 1 samples the id range coarsely and narrows it to where the version appears. Phase 2 samples
that range and keeps games with 8 or more players that ran 30 minutes or longer. For 3835 the range
is roughly 26.90M to 27.05M; 27079166 is already on 3836.

Seeded AI benchmark with no replay needed, on stock map data. `/noai` + `/noinitialunits` give idle armies for a scripted battle map:

```bash
MSYS_NO_PATHCONV=1 python scripts/perf/run_game.py out/sk 2700 -- /map /maps/dualgap_adaptive.v0014/DualGap_Adaptive_scenario.lua /seed 20260924 /faction 1 /nomovie
```

## How the stack walk stays honest

- x86 frames here are mostly FPO, so there is no EBP chain to follow. The walker scans the stack for return addresses instead.
- A candidate is accepted only if it follows a *real* `call` instruction from the disassembly export, and that call fits the current frame:
  - a direct call must target the current function, directly or through a tail-jump or thunk;
  - an import call is accepted only when the leaf is inside a DLL;
  - other indirect calls are accepted only into functions whose address is taken somewhere.
- Stale return addresses can still derail the root end of a chain. That is why `analyze.py` attributes the **leaf end** ("what") and treats the root end ("who") as best-effort.
- `ntdll` leaves under `CSimDriver`'s condition wait or D3D `Present` are idle time, not work.

## Caveats

- **Replay version.** A replay only plays without desync on the exact FAF game version it was recorded on (`lua/version.lua` in `gamedata/lua.nx2`). Older or newer replays still load if you pass `--as-version`, but they diverge. That is fine for load shape, not for determinism work.
- **Where the Sim object is found.** The `Sim` object is located by scanning the heap for its vtable (`0x00E34714`). Tick is read at `+0x900`, `mEntityDB` at `+0x984`.
