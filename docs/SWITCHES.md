# Switches

Reference for the console variables and startup flags behind the
[performance work](PERFORMANCE.md).

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
| `lua_GcVerify` | 0 | `/con` | live (next collection) | Debug only: check each parallel sim collection against a serial one, see [Debugging aids](#debugging-aids) |
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


## Debugging aids

Off by default.

- `FAF_LUAGC_TIMING=1` (environment) logs the phases of every sim Lua collection.
  and weak-table lists after both propagations and the sweep's live/dead
  classification. After the mark it checks that no marked weak table refers to
  an unmarked object, that no live closure keeps an open upvalue into a dead
  thread, and that the LuaObject root list is intact. Findings are `[GCVERIFY]`
  warnings, and every 100th clean collection logs `[GCVERIFY-OK]`. It roughly
  doubles collector time and stretches each sim mark, which also widens the
  window for races between the sim and other threads.
- `FAF_DUMP_ON_SIM_LUA_ERROR=<n>` (environment): the first n sim Lua script
  errors each write a full-memory minidump and the error text beside the exe
  (`faf_luaerr_*.dmp/.txt`), then the game continues.
  `FAF_DUMP_ON_SIM_LUA_ERROR_IGNORE` lists `;`-separated substrings of errors
  to skip, for errors a replay always logs (benchmark replay: `SetSpinDown;Failed
  to attach entity`).

