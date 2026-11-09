# Simulation bottlenecks

Where a sim tick's time went in October 2026, and what four speed-up experiments found, so that nobody has to repeat them blind. GodFuper ran the profile and the experiments and wrote them up in PR #27, which was closed without merging.

*Measured: 28/10/2026, before PR #30. The runs have not been repeated. Code references checked on master: 03/11/2026.*

## Outcome

| Experiment | Result | On master |
|---|---|---|
| Reusing the pose object in place (`sim_RecyclePose`) | Same checksums, 5.3 MB lower peak memory, no clear speed change | Yes, on by default (PR #30), not for 11-bone poses |
| Pose updates on sim workers (`sim_ParallelPose`) | Crash in Lua | Yes, on by default, in a narrower form that keeps Lua on the sim thread |
| Army ticks on sim workers (`sim_ParallelArmies`) | Desync at beat 500 | No |
| Packed spatial grid cells and SIMD overlap tests (`sim_PackedOgrid`, `sim_SimdAABB`) | Under 0.1 % change in match time | No |

The army and grid switches existed only in the author's experiments. The switches do not exist today, and their code is not in this repository, on any of the 14 branches of the author's fork, or in the heads of the author's 9 PRs (checked 03/11/2026).

## Setup

- **Build**: x64 Release, clang-cl, 8 sim workers, D3D12, Windows 11.
- **Replay**: `28007941`, 4 players, 17,936 beats (30 minutes of game time), with late-game armies of thousands of entities. PR #30 gives 24,565 beats for it, which does not match the file.
- **Parity**: a run must match all 359 checksums recorded in the replay, one every 50 beats ([PR replay check](PR_REPLAY_CHECK.md)).
- **Profile**: Tracy, about 466 ticks in a mid-to-late game fight. PR #30 reports the same baseline as a 15-second capture at game time 17:11.
- **Mean `SimTick`**: 32.45 ms, about 30.8 ticks per second with no speed limit.

Terms used below: a beat is one sim tick; headless is the engine with no renderer; a recon blip is an army's record of a unit it can see; a pose handle is a shared pointer to a unit's pose; task stage A runs the entities' task and motion ticks.

## Where sim time goes

| Zone | Mean time | Share | What it does |
|---|---|---|---|
| `Sim::TaskStages` | 14.74 ms | 45.4 % | Unit tasks (`CTaskStage::UserFrame`): command threads, motion, weapons, builders, and Lua coroutines and callbacks |
| `Sim::ArmiesTick` | 8.11 ms | 25.0 % | Each army's `CArmyImpl::OnTick`: AI brains, army plans, platoons, economy |
| `Sim::Recon` | 2.82 ms | 8.7 % | Blip refresh, line of sight, and radar and sonar grids |
| `Sim::AdvanceCoords` | 1.04 ms | 3.2 % | Coordinate advances and spatial grid (`COGrid`) updates |
| Rest of `SimTick` | 5.74 ms | 17.7 % | Not split in this capture. From the source at that commit, it includes the `Sim::RulesUpdate` and `Sim::LuaGC` zones, `Sim::PathUpdate` when `path_BackgroundUpdate` is on, the `Sim::Sync` call and work in no zone. PR #27 labelled this row collision, physics and sync; those first two have no zone of their own, so the capture can't show them |

PR #30 later measured the same replay at 27.99 ms per tick, with `Sim::ArmiesTick` at 4.18 ms. That PR puts the drop down to economy stats no longer looking up their names every tick; there was no separate on/off comparison for that one switch.

## The experiments

The crash and the desync below were not reproduced for this page. Their causes are the author's analysis. The code paths they name are still there, and were checked by reading the source.

### Reusing the pose object in place (`sim_RecyclePose`)

- **Idea**: retail runs `mPose.swap(mPriorPose)` and then allocates a new `CAniPose` every time `CAniActor::UpdateManipulators` runs (`FUN_0063AA80`: allocation at `0x0063AAB8`, copy constructor at `0x0063AAD4`). At 1,000 moving units and 10 ticks per second, that is 10,000 allocations per second. When nothing else holds the retired pose (`mPose.unique()`), `CAniPose::OverwritePose` (retail `FUN_0054B330`, which the copy constructor already calls) can reuse it, copying bones and transforms without reallocating the vector buffers. If another system, such as rendering or weapon tracking, still holds it, a new pose is allocated as before.
- **Result in PR #27 (D3D12)**: every checksum matched over the whole replay. Peak working set went from 1767.94 MB to 1762.60 MB. Time went from 334.1 s to 338.9 s, which the author put down to measurement noise of about 1 %, and they suggested CPU caches and fast small-block allocators as the reason for no gain (not measured). They rolled the change back to keep the code minimal and kept it as a candidate for later memory work.
- **Result in PR #30 (D3D9, on a later base)**: same replay, 308.01 s to 300.12 s (2.6 % less). The renderer and base differ, and the two results point in opposite directions, so neither settles the speed effect.
- **How often it applies**: not measured since. An earlier trial (documented in `99a471490`) argued that the reuse "can never apply" in a real game, because every enemy army that sees a unit holds its poses through a recon blip, and sync and the user side hold them too. Its pose copy cost did not change. PR #27 instead describes the allocations as eliminated. The two accounts conflict for the game, and only a hit count would settle it. Headless now drops those handles, so poses stay unique there (`7bab2c935`). The game keeps them.
- **Status**: on by default. Poses of exactly 11 bones are still allocated new (the `kBinaryLaneBones` check in `CAniActor::UpdateManipulators`), because when one is freed decides which memory block the next formation gets, and the sim can observe that (see Reused addresses in [Retail replay parity](RETAIL_REPLAY_PARITY.md)).

### Pose updates on sim workers (`sim_ParallelPose`)

- **Idea**: pose and animation updates were on the roadmap at about 14 % of sim time. Queue moving units during `Unit::MotionTick` and run `CAniActor::UpdateManipulators` across `CSimWorkerPool`.
- **Result**: the game froze and crashed at game time 3:14 with an access violation (`0xC0000005`). Line numbers are from the author's experiment build:

  ```
  luaV_index
  lua_gettable
  moho::CScriptObject::FindScript
  moho::CScriptObject::RunScript
  moho::CBuilderArmManipulator::TrackAimDirection (CBuilderArmManipulator.cpp:566)
  moho::CBuilderArmManipulator::ManipulatorUpdate (CBuilderArmManipulator.cpp:599)
  moho::CAniActor::UpdateManipulators (CAniActor.cpp:568)
  moho::CSimWorkerPool::ParallelFor
  ```

- **Cause**: engineers and factories had started building. When a builder arm starts tracking, `TrackAimDirection` calls `unit->RunScript("OnStartBuilderTracking")`, and the Lua VM is single-threaded. A second problem: running the updates as a batch at the end of task stage A lets weapons and attached entities that tick later in that stage read old bone transforms.
- **Status**: the trial was dropped. A later implementation (`4e71b4325`) is built to avoid both problems. Only units whose enabled manipulators are all Rotate, Slide, Slave, Animation or Storage, with no Lua waiter, are queued, so units with builder arm or aim manipulators stay on the sim thread. When last counted on 26954789, before 11-bone poses were also kept on the sim thread, 37.4M of 92.3M pose updates ran there, from these and any other units the filter keeps back. A trial that queues these units on ticks with no target cut that to 13.4M, but has not shown a wall-time gain and is not merged. `GetBoneWorldTransform` and the pose accessors wait for that unit's job, and any engine call from Lua waits for all of them; not every direct read of `mPose` was audited for this page. When it landed, the x64 core and extended replay sets matched every checksum with it on, headless, as did one x86 replay. Replay 26954789 took 7.8 % less wall time in one off/on/on/off test (1307, 1152, 1134, 1173 s), and the two off runs differ by more than that gain. [Switches](SWITCHES.md) has the details.

### Army ticks on sim workers (`sim_ParallelArmies`)

- **Idea**: run `CArmyImpl::OnTick` for each army on its own worker. `Sim::ArmiesTick` was 25 % of a tick, and each army looked self-contained, with its own economy, AI brain and path queue.
- **Result**: desync at beat 500 (`Checksum for beat 500 mismatched`).
- **Cause**: three things in an army's tick are not independent of the other armies or of the Lua thread.
  - With resource sharing on, `ProcessArmyEconomy` writes an army's excess straight into its allies' `mResources` and `mPendingResources`, so allies running at once race on those values. The available resources and consumption ratios then differ, and the sim state desyncs. The author's reference was `CEconomy.cpp:508-527`; the code has since moved within the file.
  - `CArmyImpl::CleanUpPlatoons` runs Lua when it destroys idle or empty platoons: `RunPlatoonOnDestroyAndDelete` calls `platoon->RunScript("OnDestroy")`.
  - `OnTick` advances the AI brain's thread stages (`mAiThreadStage->UserFrame()` and the others), which run Lua coroutines.
- **Status**: dropped. `Sim::ArmiesTick` still ticks the armies one at a time, in order.

### Packed spatial grid and SIMD overlap tests (`sim_PackedOgrid`, `sim_SimdAABB`)

- **Idea**: pack `COGrid` cell bounds into 16 bytes and test 3D box overlaps with SSE (`_mm_min_ps`, `_mm_max_ps`), on the guess that entity queries lose time to cache misses and branch mispredictions.
- **Result**: 334.13 s to 333.91 s, under 0.1 % and inside measurement noise.
- **Cause**: the author's explanation is that `Sim::AdvanceCoords`, which holds the grid updates, is 3.2 % of a tick, so making all of it twice as fast would save about 1.6 %. That limit covers grid updates only. Grid queries also run outside that zone, for example from `CDamage.cpp`, `CAiBrain.cpp` and `CUnitMotion.cpp`, and their share of the tick was not measured.
- **Status**: dropped.
