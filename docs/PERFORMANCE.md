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
| Lua collector mark and sweep on worker threads (`lua_ParallelMark`, `lua_ParallelSweep`); see [Lua](#lua) | about −2 % at the peak (collector 2.2 → 0.5 ms per tick) |
| **Total since profiling started** | **about −18 %** (before the Lua collector row) |

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

The sim is now the limit, both in replays and on the stress map at
30,000–60,000 units. The latest main-thread savings, fog of war walked from
arrays on workers and strategic icons drawn in bulk, give more frames per
second, not more ticks. The plan, in order:

1. **More sim phases on workers:** sync packet serialization, intel rasters,
   then pose and animation (about 14 % of sim time). Pose and animation need
   speculative computation published in serial order.
2. **Observer pacing for live games**, after a live multiplayer test.
3. **New renderer backends** behind the existing `gpg::gal` layer, which
   already has a full D3D9 and a partial D3D10 backend:
   - Direct3D 11 first, with instancing, lower per-draw overhead and
     multi-threaded command recording;
   - then D3D12 and Vulkan, compiled from one shader pipeline. The game's
     `.fx` effects are translated automatically from your installed copy,
     never shipped.

## Lua

The sim runs LuaPlus Build 1081 (Lua 5.0). Its collector is stop-the-world,
and a collection has to happen on the same beat, free objects in the same
order and run finalizers in the same order as the original, so the
accounting that triggers it (`nblocks`, `GCthreshold`) is untouched.
`FAF_LUAGC_TIMING=1` logs the phases of every sim collection.

**Collector on the sim workers** (`lua_ParallelMark`, `lua_ParallelSweep`):

- **Mark.** Objects are claimed by an atomic test-and-set of the same mark bit
  the serial code tests, so each is traversed once and the marked set is the
  serial one. Thread stacks, the LuaPlus root objects, weak-table clearing and
  the separation of userdata awaiting finalization run on workers too. Stack
  shrinks (allocations) and the GC hook stay on the sim thread.
- **Sweep.** Workers walk the GC lists, sort live from dead objects and reset
  the live objects' mark bits. The sim thread then frees the dead objects in
  the original list order. The lists are split at objects known to be on
  them: every 4,096th survivor of the previous sweep, and every 4,096th object
  linked at a list head since.

Everything a collection gathers belongs to that collection. The weak tables
the workers find used to go into one process-wide set, which every Lua VM's
collection emptied when it began. The UI VM collects on the main thread, so
when it started during a sim mark it dropped the sim's weak tables: they were
never cleared, kept entries for objects the sweep then freed, and later
lookups found new objects at the old addresses. The `sizes` table that
`table.insert` and `unpack` use is weak-keyed, so a fresh table could inherit
a dead table's length, and `unpack` of an orientation came back short. It
happened about once in five replays at `/simworkers 8` and desynced the game.

With both switches on, the per-beat checksum log of the benchmark replay is
identical to the serial run (`/simworkers 0`) at 8 and at 3 workers, on all
24,565 beats, and the full replay matches every embedded checksum on x64 and
x86 at `/simworkers 8`.

Benchmark replay, x64, `/simworkers 8`, both runs matching every embedded
checksum:

| | Switches off | Switches on |
|---|---|---|
| Collector time, whole game (356 collections) | 35.9 s (mark 24.3, sweep 11.6) | 9.3 s (mark 6.0, sweep 3.2) |
| Lua collector, sim ms per tick at the peak (ticks 19,000–22,500) | 2.18 (2.5 % of the sim) | 0.48 (0.6 %) |
| Lua in total (interpreter, bindings, collector) at the peak | 6.1 % of the sim | 4.5 % |

In the 2,000 v 2,000 air fight a heavy collection drops from 75 ms mark and
66 ms sweep to 22 ms and 34 ms. What is left of the sweep is the frees, which
stay serial.

**Single-thread interpreter.** Measured in-process with random A/B assignment
of interpreter entries, the interpreter costs about 140 cycles per Lua
instruction excluding the C functions it calls. It is bound by memory latency
on table lookups, not by dispatch. Two exact fast paths were built and dropped:

| Idea | Why it was dropped |
|---|---|
| String-key `__index` chains followed inline in OP_GETTABLE, OP_SELF and OP_GETGLOBAL, skipping `luaV_index` / `luaT_gettm` / `luaH_get` (about 2.5 million chain lookups per 20 million instructions) | 146 against 148 cycles per lookup: both read the same table nodes, and those cache misses are the cost |
| Interpreter loop with its program counter in a register (no live-pc publication for crash reports) | 140 cycles per instruction either way |

A per-instruction inline cache was not attempted for the same reason: a hit
still has to read the cached node to validate it, which is the read the
lookup itself makes.

## Switches

Every performance change has a switch that brings back the original path, and
both paths give the same sim checksums. Console variables can be set in game
(`name value` in the console) or at startup with
`/con name=value;name2=value2`, which runs on the first frame. "Live" means a
change applies from the next use; "next game" means the value is read when a
thread or session starts.

| Switch | Default | At startup | Applies | What it does |
|---|---|---|---|---|
| `sim_Workers` | 0 | `/simworkers N` or `/con sim_Workers=N` | live (next dispatch) | Sim worker threads; 0 runs every phase serially |
| `sim_ParallelRecon` | 1 | `/con` | live | Recon blip refresh per army on sim workers (needs `sim_Workers` > 0) |
| `sim_ParallelSync` | 1 | `/con` | live | Sync packet unit updates filled on sim workers (needs `sim_Workers` > 0) |
| `lua_ParallelMark` | 1 | `/con` | live (next collection) | Lua GC mark on sim workers (needs `sim_Workers` > 0): propagation, thread stacks, the LuaPlus root objects, weak-table clearing and the userdata separation; stack shrinks, the GC hook and finalizers stay serial |
| `lua_ParallelSweep` | 1 | `/con` | live (next collection) | Lua GC sweep: live/dead classification and mark reset on sim workers (needs `sim_Workers` > 0); every free stays on the sim thread, in the original list order |
| `sim_DeferBlipUnlinks` | 1 | `/con` | live | Dropped blips-in-range lists leave their weak chains in one bulk pass instead of one chain walk per blip |
| `sim_DeferBlipUnlinksTicks` | 4 | `/con` | live | Ticks between those bulk passes |
| `sim_ExemptCheckInPlace` | 1 | `/con` | live | Target exemption reads the command queue instead of copying it |
| `sim_CacheScriptModuleLookups` | 1 | `/con` | live | Remembers whether each blueprint script module exists (cleared by disk-watch events and a new sim) |
| `sim_BlueprintLookupFast` | 1 | `/con` | live | Blueprint lookups without a copy of the id, and without a retry that cannot match |
| `sim_GatherLargeBuffers` | 1 | `/con` | live | Grid gathers use large stack buffers, so dense queries stay off the heap |
| `sim_GatherReserve` | 1 | `/con` | live | Area queries size their result list once |
| `sim_ChecksumBatching` | 1 | `/con` | live | Each entity's checksum bytes go to MD5 in one run |
| `sim_MD5Unrolled` | 1 | `/con` | live | MD5 blocks unrolled instead of the table-driven loop |
| `sim_ReconProbeCellCache` | 1 | `/con` | live | A recon point probe computes each intel-grid cell once per grid size |
| `sim_ReconSkipSelfAlly` | 1 | `/con` | live | Recon merges skip the army's own database on its repeat ally-loop visit |
| `sim_ReconBlipHandleAssign` | 1 | `/con` | live | Blip refresh copies mesh and pose handles without temporaries (no refcount traffic when unchanged) |
| `sim_IntelRasterRows` | 1 | `/con` | live | Intel circles rastered row by row instead of column by column |
| `sim_IntelSameCellMove` | 1 | `/con` | live | An intel source moving inside its grid cell skips the two rasters that would cancel |
| `sim_BlueprintNameCache` | 1 | `/con` | live | Emitter, trail and projectile blueprint lookups by name remembered per game rules (positive results only) |
| `sim_SquadUnitSearch` | 1 | `/con` | live | Squad membership test by binary search of the id-sorted unit set |
| `sim_ParallelCoords` | 1 | `/con` | live | Per-entity half of the coordinate advance (transforms, history, collision shape) on sim workers; grid relinks, intel updates and list links stay serial in list order (needs `sim_Workers` > 0) |
| `sim_ReconBlipIndex` | 1 | `/con` | live | Recon blip lookup by entity id through a hash index instead of the blip map walk |
| `sim_ParallelBlipFlush` | 1 | `/con` | live | The bulk blip-unlink pass splices separate weak chains on sim workers (needs `sim_Workers` > 0) |
| `sim_ParallelSyncHeap` | 1 | `/con` | live | With `sim_ParallelSync`, the allocating members of unit-update records are copied on workers too |
| `sim_ParallelEntitySync` | 1 | `/con` | live | With `sim_ParallelSync`, entity-update records are copied on workers |
| `sim_ReplayLead` | 10 | `/con` | live | Beats a replay may compute ahead of the screen |
| `sim_LocalLead` | 2 | `/con` | live | Beats a single-player session may compute ahead |
| `sim_LeadOnSchedule` | 1 | `/con` | live | With a lead, beats are still issued on the original rate schedule, with the lead on top (0: only the fixed lead, which caps the session at about lead × frame rate) |
| `mem_SmallBlockIndexTable` | 1 | `/con` | live | x86 allocator: size class by table instead of a binary search |
| `mem_InlineTransformCopy` | 1 | `/con` | live | Transform copies inline instead of through Wm3's out-of-line `memcpy_s` |
| small-block pool (x64) | on | `/smallpool 0` or `FAF_SMALLPOOL=0` | startup only | Size-class pool for blocks up to 4 KB in front of the system heap; the log says `mem: small-block pool on/off` |
| `res_CacheFileLookups` | 1 | `/con` | live | Remembers where the mounted file system found each file (cleared on disk-watch events, mount changes and the engine's own deletes and moves; "not found" kept only for archive-only lookups) |
| `user_Workers` | −1 (auto: min(CPUs − 2, 6)) | `/con` | live | User-side worker threads; 0 runs everything on the main thread |
| `ren_ParallelCull` | 1 | `/con` | live | Mesh and decal view queries and fog-of-war circles collected on user workers |
| `ui_ParallelIcons` | 1 | `/con` | live | Strategic icons classified on user workers and drawn in bulk |
| `wld_ParallelSync` | 1 | `/con` | live | Beat sync apply: pose and data copies on user workers |
| `wld_FrameClock` | 1 | `/con` | live | Replays and single player: game clock from the mean frame time (0: the original median, 2: each frame's own time) |
| `wld_VisionChainHints` | 1 | `/con` | live | Vision-tree chain tails and predecessors from checked hints instead of chain walks |
| `wld_VisionRepeatInsert` | 1 | `/con` | live | A vision entry identical to the previous one goes where the tree walk would put it, without the walk |
| `ren_ParticleKeyShortcut` | 1 | `/con` | live | Particles reuse the cached render bucket when their key would match, without building the key |
| `ren_FrustumCacheLodUnits` | 20000 | `/con` | live | From this many entities in view, a camera's unit lists refresh every `ren_FrustumCacheLodInterval` s |
| `ren_FrustumCacheLodInterval` | 2.0 | `/con` | live | That refresh interval, in seconds |
| `ren_GpuIcons` | −1 (auto) | `/con` | live | Strategic icons drawn by the GPU (1 on, 0 off, −1 when the device verified the path) |
| `ren_GpuIconClassify` | −1 (auto) | `/con` | live | Icon classification in a compute pass |
| `ren_GpuFog` | −1 (auto) | `/con` | live | Fog of war drawn by the GPU |
| `ren_GpuSelectBrackets` | −1 (auto) | `/con` | live | Selection brackets drawn by the GPU |
| `ren_GpuProjectileIcons` | −1 (auto) | `/con` | live | Projectile icons drawn by the GPU |
| `ren_ParticleBatch` | −1 (auto) | `/con` | live | Each particle bucket drawn as one instanced draw |
| `ren_CacheFogFootprint` | 1 | `/con` | live | The fog pass keeps each camera's terrain footprint until the camera or terrain changes |
| `ui_IconRecords` | 1 | `/con` | live | Strategic icons classified from per-unit records refreshed only after a sync beat or a view-list rebuild |
| `sys_ThreadPlacement` | 0 | `/threadplacement N` | next thread start | Thread placement on cores (0 leaves it to Windows) |

## Tried and dropped

| Idea | Why it was dropped |
|---|---|
| Reusing a unit's retired pose object each tick instead of allocating a new one | It can never apply: every enemy army that sees the unit holds its prior and current poses through its recon blip (refreshed every tick), and sync and the user side hold copies too, so the two-frame-old pose always has other owners. Measured: the pose copy constructor's cost was unchanged with the switch on. |
| Keeping a unit's blips-in-range list when a refresh finds the same blips | In a moving fight the list order changes almost every refresh (0.3 % identical, 0.7 % of entries in place), so it never paid off. The deferred bulk unlink (`sim_DeferBlipUnlinks`) took its place. |
| Running independent per-unit Lua callbacks speculatively in parallel | Measured on 400,000 callbacks in a 2,000 v 2,000 air fight: 77 % allocate (moving the GC trigger), 32 % write tables they did not create, 16 % draw from the sim random stream, 98 % call engine bindings. Only 1.6–6.5 % could run independently. |
