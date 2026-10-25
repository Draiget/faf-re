# Switches

Reference for the console variables and startup flags behind the [performance work](PERFORMANCE.md).

Every performance change has a switch that brings back the original path, and both paths give the same sim checksums. So does every ported FAF FA-Binary-Patches change a player can notice (rows that name a patch number). Console variables can be set in game (`name value` in the console) or at startup with `/con name=value;name2=value2`, which runs on the first frame. "Live" means a change applies from the next use; "next game" means the value is read when a thread or session starts.

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
| `ren_GpuShapes` | −1 (auto) | `/con` | live | FAF's `UI_DrawLine`/`UI_DrawRect`/`UI_DrawCircle` world shapes drawn by the GPU, one instanced draw per run of same-kind shapes (0: the prim batcher, as FA-Binary-Patches draws them) |
| `ren_ParticleBatch` | −1 (auto) | `/con` | live | Each particle bucket drawn as one instanced draw |
| `ren_CacheFogFootprint` | 1 | `/con` | live | The fog pass keeps each camera's terrain footprint until the camera or terrain changes |
| `ui_IconRecords` | 1 | `/con` | live | Strategic icons classified from per-unit records refreshed only after a sync beat or a view-list rebuild |
| `cam_FreeClampFocus` | 0 | `/con` | live | With `cam_Free` on, 1 snaps the camera focus onto the terrain under the view ray again, as before FAF FA-Binary-Patches #170 (the free camera jumped behind hills) |
| `ren_LargeParticlePools` | 1 | `/con` | first world particle (startup) | Particle and trail-segment render-buffer pools of 4096 and 400 buffers (FAF FA-Binary-Patches #165); 0 keeps the original 400 and 100, which run out in big fights and drop particles ("Particle cap exceeded") and trail segments |
| `ren_MinimapRanges` | 1 | `/con` | live | Range rings on the minimap; 0 skips that pass (FAF FA-Binary-Patches #158, FAF's own name) |
| `ren_MinimapDebugOverlays` | 0 | `/con` | live | 1 draws the debug overlays (`ren_ShowFrameTimes`, `ren_ShowNetworkStats`, `ren_ShowBandwidthUsage`, `UI_ShowControlUnderMouse`) into the minimap again, as before FAF FA-Binary-Patches #158 |
| `ui_StrategicIconScale`, `ui_DepositIconScale`, `ui_ProjectileIconScale` | 1.0 | `/con` | live | Size multipliers of unit strategic icons (with their paused, stunned and underlay overlays), deposit icons and projectile icons (FAF FA-Binary-Patches #147; 1.0 is the original size) |
| `sys_ThreadPlacement` | 0 | `/threadplacement N` | next thread start | Thread placement on cores (0 leaves it to Windows) |
| XACT process clock | on | `/realtickcount` turns it off | startup only | XACT 2.9 times itself from process start instead of Windows boot, so sound keeps working after 24.8 days of uptime without UptimeFaker; the log says `SND: xactengine2_9.dll clock imports patched` (`FAF_TEST_TICK_OFFSET_DAYS=N` in the environment fakes N more days of uptime, for testing) |


## FAF game version

FAF ships its engine fixes ([FA-Binary-Patches](https://github.com/FAForever/FA-Binary-Patches)) as a new exe with a game release, and the FAF client stamps the game version into that exe, so one game version means one set of engine patches. This engine carries those patches up to game version 3840 and applies them per session: a replay plays with the patches of the version in its header (`Supreme Commander v1.50.<version>`, accepted from 3835 to 3840), every other session uses 3840, and the replay it records names the version it ran as. The log says `FAF game version <n> (replay|session), sim fixes 0x..` when a session begins. `GetEngineVersion` reports 1.5.3840.

The switches below are read when a session begins. In a multiplayer game every client must use the same values, so leave them at their defaults there; they are for replays and tests.

| Switch | Default | At startup | Applies | What it does |
|---|---|---|---|---|
| `sim_FafGameVersion` | 0 | `/con sim_FafGameVersion=N` | next game | Game version the session runs as; 0 takes the replay's recorded version, or 3840 |
| `sim_FixAimLeadOncePerTick` | −1 | `/con` | next game | FA-Binary-Patches #143 (from 3836): no one-tick velocity lead on a target that already moved this tick; −1 follows the game version, 0 off, 1 on |
| `sim_FixTargetPointCollisionCentre` | −1 | `/con` | next game | #145/#157 (from 3836): a unit without target bones is aimed at its collision-box centre |
| `sim_FixProjectileImpactBelowZero` | −1 | `/con` | next game | #154 (from 3840): a projectile below height 0 impacts |
| `sim_FixRefuelUndockAboveMaxHealth` | −1 | `/con` | next game | #169 (from 3840): refuelled aircraft undock once health is at least max health |
| `sim_FixShieldRepair` | −1 | `/con` | next game | #175 (from 3840): shield repair scales with the builder's resources, and a switched-off shield is not repaired |

## Server mode

Server-authoritative sessions are being built: one server runs the only sim, and each player receives only what their army can see. The code is behind the CMake option `FAF_SERVER_MODE` (off by default; the presets `clang-x64-release-server` and `clang-x86-release-server` turn it on). A client built with it is the same lockstep client for every normal game, replay and lobby: the server-mode path runs only when `/connectserver` is on the command line, and it never falls back to a lockstep session.

| Switch | Default | At startup | Applies | What it does |
|---|---|---|---|---|
| `/connectserver host:port` | — | command line | startup only | Join the game server at that address (needs `/servertoken`); refused together with `/hostgame`, `/joingame`, `/gpgnet`, `/replay`, `/load`, `/scenario`, `/map` or `/perf`. Not working yet: the client says "This build cannot join server games yet." and exits |
| `/servertoken token` | — | command line | startup only | The admission token the launcher was given for this match (1 to 1024 printable characters, no spaces) |

### faf-replay

The server-mode build also produces `faf-replay.exe`, a console program that plays one replay with no window, render device or audio engine and reports whether every checksum the players recorded matches. It runs the game's sim, sim driver and replay client; it does not build the world session the game's UI runs on. Put it in a folder of its own next to the game's `bin` folder (it reads `../Installed.Prefs` and mounts the `fafengine` folder next to itself, as the game does) and give it the game's init file:

```
faf-replay.exe --replay C:\full\path\26902315.scfareplay /init C:\ProgramData\FAForever\bin_x64\init.lua /nosound /log replay.log
```

The last line it prints is `VERDICT ended=<True|False> mismatches=<n> crash=<True|False>`, the same verdict `tools/runs/replay_20261013/run_replay.py` prints for the game. `ended` is the sim's Lua `Sync.GameEnded`, which the game reports to FAF; the run itself stops at the sim's game-over beat (a victory, or the end of the recorded commands).

| Switch | Default | What it does |
|---|---|---|
| `--replay file` | — | The `.scfareplay` to play (required) |
| `--focus army` | −1 | The army whose view the sim builds, 0-based; −1 is an observer, as when watching a replay. The sim starts with that focus, as a player's game does with the player's own army |
| `--digests file` | — | Writes `beat md5` for every beat the sim checksums |
| `--sync-keys file` | — | Writes every top-level key of the sim's Lua `Sync` table seen during the replay, with the number of beats it was present and its first and last beat |
| `--wire-stats file` | — | Runs the server-mode wire format's entities lane on every beat: the entities the sim published to this run's focus become a view frame, encoded against the previous beat's, decoded and compared; writes one CSV line per beat (entities, created, removed, changed, delta bytes, full-frame bytes every 100 beats) and prints a summary |
| `--checksum-period n` | the game's (50) | `sim_ChecksumPeriod` for this run. With 1 every beat has a digest. Other code feeds the checksum between checksum beats, so a period other than the recorded 50 digests different spans of data: the verdict then says "recorded-checksum check skipped" and mismatches do not count. The period changes only the checksum, never the sim (plan §12, 2026-10-25) |
| `--state-digests file` | — | Writes `beat digest` of what the sim published each beat (creations, entity and unit updates, deletions, army economy, the Lua `Sync` bytes). Independent of `sim_ChecksumPeriod` and of the sim's checksum, so runs with different periods can be compared |
| `--lead n` | 10 | Beats the sim may compute ahead (`sim_ReplayLead`); faf-replay issues beats without the rate clock (`sim_LeadOnSchedule 0`), so the sim runs flat out |
| `--timeout minutes` | 180 | Gives up after this long |
| `--label text` | `faf-replay` | Prefix of every printed line |

Engine switches work as in the game: `/init`, `/log`, `/synclog`, `/simworkers`, `/con`, `/prefs`, `/sse2`, `/noversioncheck`. Exit code: 0 every recorded checksum matched and the replay reached its end; 1 a mismatch; 2 the end was not reached in time; 3 a crash or fatal error; 4 bad arguments or a replay that could not be loaded.

## Debugging aids

Off by default.

- `FAF_LUAGC_TIMING=1` (environment) logs the phases of every sim Lua collection.
- `lua_GcVerify` (console variable, `/con lua_GcVerify=1`): every parallel sim collection is checked against a serial mark and sweep. It compares mark bytes and weak-table lists after both propagations and the sweep's live/dead classification. After the mark it checks that no marked weak table refers to an unmarked object, that no live closure keeps an open upvalue into a dead thread, and that the LuaObject root list is intact. Findings are `[GCVERIFY]` warnings, and every 100th clean collection logs `[GCVERIFY-OK]`. It roughly doubles collector time and stretches each sim mark, which also widens the window for races between the sim and other threads.
- `FAF_DUMP_ON_SIM_LUA_ERROR=<n>` (environment): the first n sim Lua script errors each write a full-memory minidump and the error text beside the exe (`faf_luaerr_*.dmp/.txt`), then the game continues. `FAF_DUMP_ON_SIM_LUA_ERROR_IGNORE` lists `;`-separated substrings of errors to skip, for errors a replay always logs (benchmark replay: `SetSpinDown;Failed to attach entity`).
