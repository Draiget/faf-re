# Simulation bottlenecks

Detailed Tracy profiling of the sim tick and the context, failure mechanisms, and results of four evaluated optimizations on the x64 engine.

*Snapshot: 28/10/2026.*

## Profiling & benchmark context

- **Test setup:** x64 Release (`clang-cl`), 8 sim worker threads, Direct3D 12 backend, running on Windows 11.
- **Workload:** 30-minute 4-player competitive vault replay `28007941.scfareplay` (late-game army sizes reaching thousands of active entities).
- **Parity verification:** Replay was verified bit-for-bit against retail `ForgedAlliance.exe` checksums recorded every 10 and 50 beats. Any differing bit in the simulation state fails the beat.
- **Profiling capture:** Tracy profiler attached during late-game combat stretches (466 ticks analyzed). Mean `SimTick` is **32.45 ms** (~30.8 ticks/second at unthrottled maximum speed).

## Where sim time goes

| Phase | Mean time | Share | What it does |
|---|---|---|---|
| `Sim::TaskStages` | **14.74 ms** | **45.4 %** | Unit tasks (`CTaskStage::UserFrame`): command threads, unit motion, weapons, builder tasks, and **Lua coroutines and callbacks** |
| `Sim::ArmiesTick` | **8.11 ms** | **25.1 %** | Per-army simulation (`CArmyImpl::OnTick`): AI brains (`AiBrain`), army plans, platoons, and economy |
| `Sim::Recon` | **2.82 ms** | **8.7 %** | Blip refresh, line of sight, and radar/sonar grids |
| `Sim::AdvanceCoords` | **1.04 ms** | **3.2 %** | Coordinate advances and spatial grid (`COGrid`) updates |
| Other / untracked | **5.74 ms** | **17.6 %** | Collision checks, physics integration, and sync packet filling |

---

## Evaluated optimizations

### In-place pose recycling (`sim_RecyclePose`)

- **Context & motivation:** In retail `CAniActor::UpdateManipulators()`, every moving unit each frame executes `mPose.swap(mPriorPose)` followed by `mPose.reset(new CAniPose(*mPriorPose))`. For 1,000 active units ticking 10 times a second, this creates 10,000 dynamic heap allocations and frees per second.
- **Implementation:** Added `CAniPose::OverwritePose(const CAniPose&)` which copies bone vectors and transforms in place without reallocating underlying `std::vector` buffers. When `mPose.unique()` is true, the existing allocated pose object is recycled; if an external system (such as rendering or weapon tracking) still holds a reference, it safely falls back to allocating a fresh pose.
- **Determinism:** 100 % bit-for-bit replay parity across all 30 minutes of `28007941.scfareplay`: every checksum matches retail (`OK (All checksums match)`).
- **Memory impact:** Peak working set dropped from **1767.94 MB** to **1762.60 MB** (~5.3 MB reduction), completely eliminating pose allocation churn in the system heap.
- **Wall-clock time:** 338.9 s against 334.1 s baseline (within normal 1 % measurement variance; no measurable wall-clock speedup due to modern CPU cache and fast small-block allocators).
- **Status:** Fully validated and deterministic, but rolled back to keep the codebase minimal. Preserved as a candidate for future memory/GC passes.

### Parallel pose updates (`sim_ParallelPose`)

- **Context & motivation:** Pose updates and animation hierarchy transforms were previously considered a potential parallelization target (~14 % of sim time). The idea was to queue moving units during `Unit::MotionTick` and batch-execute `AniActor->UpdateManipulators()` across worker threads in `CSimWorkerPool`.
- **Result:** Game froze and crashed at game time `00:03:14` with an access violation (`0xC0000005`) in `luaV_index` / `lua_gettable`.
- **Crash analysis & failure mechanism:**
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
  At `00:03:14`, engineers and factories began building units. When a builder arm acquires an aim direction, `CBuilderArmManipulator::TrackAimDirection` triggers `unit->RunScript("OnStartBuilderTracking")`.
  - **Lua is strictly single-threaded:** Executing Lua bytecode concurrently from secondary worker threads causes data races and memory corruption in the Lua VM state.
  - **Intra-stage data hazards:** Deferring pose updates to a batch at the end of Task Stage A causes weapons and attached entities that tick later in the same stage to read stale bone transforms.
- **Status:** Dropped.

### Parallel army ticks (`sim_ParallelArmies`)

- **Context & motivation:** `Sim::ArmiesTick` accounts for 8.11 ms (25.1 % of `SimTick`). Because each army owns its own economy info, AI brain, and pathfinding queue, running each army on a separate worker thread seemed like an attractive coarse-grained parallelization candidate.
- **Result:** Desynced at beat 500 (`Checksum for beat 500 mismatched`).
- **Failure mechanism:**
  1. **Allied resource sharing race:** In `CEconomy.cpp:508-527`, when resource sharing is active, an army with excess mass or energy overflows it directly into its allies' bank balances during its tick (`recipient.mResources += share`). When allied armies run their economy passes concurrently, concurrent reads and writes to `recipient.mResources` race. This alters available resources, grants different consumption ratios, and desyncs simulation state.
  2. **Platoon cleanup invokes Lua:** In `CArmyImpl::CleanUpPlatoons()`, destroying idle or empty platoons calls `RunPlatoonOnDestroyAndDelete()`, which dispatches the Lua callback `platoon->RunScript(kOnDestroyScriptName)`.
  3. **AI brain stages:** `AiBrain->mAiThreadStage->UserFrame()` advances coroutines that execute Lua scripts, violating the single-threaded Lua requirement.
- **Status:** Dropped.

### Spatial grid packing and SIMD (`sim_PackedOgrid`, `sim_SimdAABB`)

- **Context & motivation:** The unit spatial grid (`COGrid`) was hypothesized to suffer from cache misses and high branch misprediction during entity queries. The experiment packed cell bounds to 16 bytes and vectorized 3D AABB overlap tests using SSE intrinsics (`_mm_min_ps` / `_mm_max_ps`).
- **Result:** Total match time changed from 334.13 s to 333.91 s (< 0.1 % difference, indistinguishable from measurement noise).
- **Why it failed (Amdahl's Law):** The Tracy profiling data showed that `Sim::AdvanceCoords` (which contains spatial grid indexing) accounts for only **1.04 ms (3.2 %)** of the 32.45 ms sim tick. Even an unrealistically high 2× speedup of grid queries would only reduce total match time by ~1.5 %.
- **Status:** Dropped.
