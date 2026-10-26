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
| `d3d_PipelineCache` | 1 | `/nopipelinecache` turns it off before the device is created | live | Direct3D 12 pipeline states kept on disk (`pipelines-d3d12.bin` in the shader cache directory), so a later session loads them instead of compiling each one in the frame that first draws it (10–40 ms per mesh pipeline, several at once when new units come into view); 0 creates every one in that frame |
| `ren_DdsDirectLoad` | 1 | `/con` | live | Direct3D 12 and Vulkan read DXT1/3/5 DDS textures (2D and cube, with a full mip chain) straight from the file instead of decoding every texture through D3DX11 on a software device (25–45 ms per 1024×1024 unit texture, behind one lock); same format, shape and bytes, except the levels under 4×4, where D3DX11's round trip changes a few bytes and the direct load keeps the file's (`FAF_IMAGECODEC_VERIFY=1` decodes both ways and logs any other difference) |
| `ren_TextureDecodeCache` | 1 | `/con` | live | Direct3D 12 and Vulkan keep each texture that took D3DX11 more than 8 ms to decode (mostly the original game's textures without mip levels, whose chain D3DX11 builds and BC-compresses again on the CPU, 30–40 ms each) in `textures\` under the shader cache directory, keyed by a hash of the file's bytes, and read it back in later sessions; the texels are D3DX11's own output |
| `ren_BackgroundShaders` | 1 | `/con` | when an effect is created | Direct3D 12 and Vulkan prepare every shader of an effect on low-priority background threads (a quarter of the cores, 1 to 4) when the effect is created: the cached ones are read first, then the rest are compiled and added to the cache. Without it a draw opened the cache file (several ms each; half of a 330 ms zoom frame) or ran the compiler (15–300 ms each; a 383 ms zoom frame with an empty cache, as after every update that changes the shaders) in the frame that first used the shader; a draw that needs a shader a worker is still preparing waits for it |
| `ren_GlyphBitmapRead` | 1 | `/con` | live | A new character's glyph is read from the font's scratch bitmap in one call instead of one `GetPixel` per pixel as the original did (tens of ms when a frame meets many new characters); the session's first glyph is read both ways and any difference turns it off |
| `sys_ThreadPlacement` | 0 | `/threadplacement N` | next thread start | Thread placement on cores (0 leaves it to Windows) |
| XACT process clock | on | `/realtickcount` turns it off | startup only | XACT 2.9 times itself from process start instead of Windows boot, so sound keeps working after 24.8 days of uptime without UptimeFaker; the log says `SND: xactengine2_9.dll clock imports patched` (`FAF_TEST_TICK_OFFSET_DAYS=N` in the environment fakes N more days of uptime, for testing) |


## FAF game version

FAF ships its engine fixes ([FA-Binary-Patches](https://github.com/FAForever/FA-Binary-Patches)) as a new exe with a game release, and the FAF client stamps the game version into that exe, so one game version means one set of engine patches. This engine carries those patches up to game version 3840 and applies them per session: a replay plays with the patches of the version in its header (`Supreme Commander v1.50.<version>`, accepted from 3835 to 3840), and every other session with those of the game data in use, `Version` in `/lua/version.lua` (FAF's `GetVersion()`). The FAF client gives every player of a game the same game data, with the exe of that version, so a game with players on the FAF exe needs no setting; data without that file counts as 3835. The replay a session records names the version it ran as. The log says `FAF game version <n> (replay|game data|sim_FafGameVersion), sim fixes 0x..` when a session begins. `GetEngineVersion` reports 1.5.3840, the newest version whose patches the engine carries.

The switches below are read when a session begins. In a multiplayer game every client must use the same values, so leave them at their defaults there; they are for replays and tests.

| Switch | Default | At startup | Applies | What it does |
|---|---|---|---|---|
| `sim_FafGameVersion` | 0 | `/con sim_FafGameVersion=N` | next game | Game version the session runs as; 0 takes the replay's recorded version, or the game data's |
| `sim_FixAimLeadOncePerTick` | −1 | `/con` | next game | FA-Binary-Patches #143 (from 3836): no one-tick velocity lead on a target that already moved this tick; −1 follows the game version, 0 off, 1 on |
| `sim_FixTargetPointCollisionCentre` | −1 | `/con` | next game | #145/#157 (from 3836): a unit without target bones is aimed at its collision-box centre |
| `sim_FixProjectileImpactBelowZero` | −1 | `/con` | next game | #154 (from 3840): a projectile below height 0 impacts |
| `sim_FixRefuelUndockAboveMaxHealth` | −1 | `/con` | next game | #169 (from 3840): refuelled aircraft undock once health is at least max health |
| `sim_FixShieldRepair` | −1 | `/con` | next game | #175 (from 3840): shield repair scales with the builder's resources, and a switched-off shield is not repaired |

## Protection against other players

Not performance switches: these guard a game against players who send crafted traffic or host crafted maps and mods. The defaults are the protected ones.

| Switch | Default | At startup | Applies | What it does |
|---|---|---|---|---|
| `net_CheckOrderStreams` | 1 | `/con` | next game | Compares every player's orders as each client received them (a hash in the acknowledgements the engine already sends; the shipped exe ignores it). 1 logs and shows in chat who sent players different orders; desyncs against a player whose own acknowledgement contradicts what reached this client are logged instead of reported to FAF. 2 also stops the game; 0 turns the check off |
| `lua_AllowPrecompiledChunks` | 0 | `/con` | live | 1 lets Lua load compiled chunks as well as source. Off, a map or mod cannot run crafted bytecode, which can get past the loader's checks |
| `net_DebugAlterOrdersTo` | −1 | `/con` | live | Test only: alters this client's checksum reports to the player with that client index, for `tools/scenarios/3p-retail-orders-cheat.yaml` |

Game Lua states (sim, user interface, blueprints, session) read files through the mounted game folders only: `dofile` and `loadfile` look paths up like `doscript` and `import`, a path that climbs above a mount with `..` is not found, and `LuaDumpBinary` is gone. The start-up state that runs the init file keeps real paths.

## Debugging aids

Off by default.

- `FAF_LUAGC_TIMING=1` (environment) logs the phases of every sim Lua collection.
- `lua_GcVerify` (console variable, `/con lua_GcVerify=1`): every parallel sim collection is checked against a serial mark and sweep. It compares mark bytes and weak-table lists after both propagations and the sweep's live/dead classification. After the mark it checks that no marked weak table refers to an unmarked object, that no live closure keeps an open upvalue into a dead thread, and that the LuaObject root list is intact. Findings are `[GCVERIFY]` warnings, and every 100th clean collection logs `[GCVERIFY-OK]`. It roughly doubles collector time and stretches each sim mark, which also widens the window for races between the sim and other threads.
- `FAF_DUMP_ON_SIM_LUA_ERROR=<n>` (environment): the first n sim Lua script errors each write a full-memory minidump and the error text beside the exe (`faf_luaerr_*.dmp/.txt`), then the game continues. `FAF_DUMP_ON_SIM_LUA_ERROR_IGNORE` lists `;`-separated substrings of errors to skip, for errors a replay always logs (benchmark replay: `SetSpinDown;Failed to attach entity`).
