# Performance

The rebuilt engine has to compute exactly what the 2007 engine computes, beat
for beat, so every speed-up here is checked the same way the engine itself is:
replays and live games against the retail `ForgedAlliance.exe`
([retail replay parity](RETAIL_REPLAY_PARITY.md)).

*Snapshot: 20/10/2026.*

## How it is measured

- **Profiler.** `scripts/perf/sampler.py` samples every busy thread of a
  running game. `scripts/perf/build_symbols_pdb.py` builds its symbol tables
  from a rebuilt `main.exe` and its PDB, rebased for ASLR. The same tool
  profiles the retail exe through the IDA export.
- **Metric.** Sim-thread CPU milliseconds per tick, compared at the same tick
  of the same replay. Replay speed alone misleads: the sim and the main thread
  take turns, and the main thread is often the slower of the two.
- **Benchmark.** FAF vault replay 26935800: Dual Gap, 12 players, 41 minutes,
  up to about 4,400 units.

## Results so far

| Change | Sim thread per tick |
|---|---|
| Diagnostic probes removed from hot paths; recon, target and steering scans walk the way the binary does | about −10 to −20 % at 1,500–3,000 units |
| Redundant recon and intel-grid work removed (row-major intel raster, one grid cell per probe, no refcount traffic for unchanged blips); allocator, blueprint-lookup, grid-gather and checksum-hashing fixes | about −9 % on top |
| Recon blip refresh on worker threads (`sim_Workers 8`) | about −7 % overall, up to −13 % at the peak fight |
| **Total since profiling started** | **about −18 %** |

Every row was checked against retail replays before it was committed. The
threaded run plays the whole 41-minute benchmark with every embedded
live-player checksum matching.

## Main thread and replay speed

Profiling the main thread with exact x64 call stacks showed the bigger
problem was turn-taking, not CPU. In a replay the sim issued each beat only
after the main thread had taken the previous one, so at the peak of the
benchmark the main thread was busy only about 60 % of the time. About 40 %
went to waiting on `Present`, and sim and main were both idle 17 % of the
time.

| Change | Console variable (0 = original path) |
|---|---|
| Replays keep up to 10 beats computed ahead of the beat on screen, and the replay clock follows the sim's measured speed instead of the rounded-down rate step. Live games keep the original pacing. | `sim_ReplayLead` (default 10) |
| A user-side worker pool, separate from the sim's. The engine heap is thread-safe. | `user_Workers` (default min(CPUs − 2, 6)) |
| Strategic icons: units are classified on workers, and icons drawn on the main thread in the original order. No reference-count traffic on the textures every unit shares. | `ui_ParallelIcons` |
| Mesh and decal view queries and fog-of-war circles collected on workers, merged in the original walk order | `ren_ParallelCull` |
| Each beat's unit and entity updates: pose and data copies on workers. Spatial relinks, selection and sound stay on the main thread in packet order. An update that can run UI Lua is applied serially, so Lua sees the serial state. | `wld_ParallelSync` |
| Single-player sessions (one local client, no network) keep 2 beats computed ahead. Multiplayer and observers keep the original pacing. | `sim_LocalLead` (default 2) |
| With 20,000+ entities in view, a camera's in-view unit lists refresh every 2 s instead of every 0.5 s (still 0.2 s after a zoom) | `ren_FrustumCacheLodUnits`, `ren_FrustumCacheLodInterval` |

Results, x64:

| | Before | After |
|---|---|---|
| Benchmark replay, wall time for the whole game | 37:33 | 20:31 (about 1.8× faster) |
| Main thread ms per tick at 3,900 / 4,370 units | 95 / 108 | 43 / 57 before parallel sync apply, which took about 12 % more off |
| Stress map, ticks per second at 30,000 / 60,000 units | 1.75 / 0.9 | 2.8 / 1.4 |
| Stress map, main thread ms per tick at 30,000 / 60,000 units | 570 / 860 | 255 / 494 |

The full benchmark replay matches every recorded checksum on x64 and x86, and
screenshots of the serial and parallel paths show the same picture. In
replays the sim is now the limit, busy about 90 % of the time.
`/con name=value;name2=value2` sets console variables from the command line.

## Threads without breaking determinism

The original sim is single-threaded, and the checksum covers its results
bit for bit. A sim phase runs in parallel only when it can produce exactly
what the serial code produces:

- **Reads.** A job reads only state that nothing writes during the phase.
- **Writes.** A job writes only storage that belongs to its own item.
- **Serial commits.** Anything order-sensitive is applied on the sim thread
  in the original order after the join: container inserts, Lua, the random
  stream, entity creation, the last release of a shared object.
- **Same arithmetic.** Workers run under the sim thread's x87 and SSE control
  state, and chunk boundaries never depend on the worker count.

**Controls.** `sim_Workers` is a process-local console variable, seeded from
`/simworkers N`. Its default, 0, runs the original serial code. Each threaded
phase also has its own switch (for example `sim_ParallelRecon`), so any phase
can be forced back to serial.

**Determinism check.** The same replay runs at `/simworkers 0` and
`/simworkers 8` with a per-beat checksum log, and every beat must be
byte-identical. The recon phase passed on 6,814 consecutive beats of the
benchmark.

## Scale: x86 against x64

A single-player stress map spawns idle units in waves until the engine gives
out:

| | x86 (large-address-aware, 4 GB) | x64 |
|---|---|---|
| Units when the run ended | **59,969**: the sim stopped with `bad allocation` | **89,957**, still running when the test was stopped |
| Private memory | 1.9 GB | 3.8 GB |
| Address space | 3.7 of 4 GB, largest free block 29 MB | 8.2 GB, no limit in practice |

x86 runs out of contiguous address space well before it runs out of memory.
x64 has no such ceiling. At these unit counts the game crawls on both builds,
because the main thread applies and draws every unit every frame. That is the
next target.

## Where the time goes next

Main-thread work never feeds back into the simulation, so it can be
multi-threaded and rewritten freely; the checksum cannot move. The plan, in
order:

1. **Fog of war.** At 60,000 units, the serial walk of the vision tree costs
   about 17 % of the main thread.
2. **Bulk strategic-icon drawing.** The serial quad emit costs about 10 % when
   zoomed out at 60,000 units.
3. **Observer pacing for live games**, after a live multiplayer test.
4. **New renderer backends** behind the existing `gpg::gal` layer, which
   already has a full D3D9 and a partial D3D10 backend:
   - Direct3D 11 first, with instancing, lower per-draw overhead and
     multi-threaded command recording;
   - then D3D12 and Vulkan, compiled from one shader pipeline. The game's
     `.fx` effects are translated automatically from your installed copy,
     never shipped.
5. **More sim phases on workers:** sync packet serialization, intel rasters,
   then pose and animation (about 14 % of sim time), which needs speculative
   computation published in serial order.
