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

The biggest remaining costs are on the main thread, not the sim:

- applying each beat's sync packet to the user-side unit copies;
- visibility culling and mesh batching;
- strategic icons;
- D3D9 draw-call overhead.

None of this feeds back into the simulation, so it can be multi-threaded and
rewritten freely; the checksum cannot move. The plan, in order:

1. **Main-thread parallelism:** sync apply per entity, culling and batching,
   strategic icons, and letting the sim run several beats ahead of the
   renderer during replays.
2. **A Direct3D 11 backend** behind the existing `gpg::gal` layer, which
   already has a full D3D9 and a partial D3D10 backend. It brings instancing,
   lower per-draw overhead and multi-threaded command recording. Its main cost
   is porting the game's effect files to Shader Model 5.
3. **More sim phases on workers:** sync packet serialization, intel rasters,
   then pose and animation (about 14 % of sim time), which needs speculative
   computation published in serial order.
4. **D3D12 or Vulkan** only if profiling then shows rendering is GPU- or
   submission-bound. For the planned Linux and macOS builds, Vulkan is the
   more useful of the two.
