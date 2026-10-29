# UI Parallel Lua Garbage Collection (ui_ParallelMark & ui_PeriodicGC)

## Problem Statement

In retail *Forged Alliance*, `moho::CUIManager::UpdateFrameRate` unconditionally forces a full stop-the-world Lua garbage collection on the UI Lua VM every 5.0 seconds via `lua_setgcthreshold(mLuaState->m_state, 0)`.

Profiling shows that this 5-second forced collection causes a **42 ms to 60 ms pause** on the main thread, resulting in visible frame drops / hitches in the rendering loop. 

An initial attempt to disable the forced 5-second timer (`ui_PeriodicGC=0`) failed because Lua 5.0 lacks an incremental garbage collector: the dynamic threshold allowed the UI Lua heap to grow from ~38 MB to 93 MB before triggering, doubling the collection pause to an average of **80 ms** and peak of **123 ms** (increasing frames > 100 ms from 14 to 23).

## Proposed Architecture

To eliminate UI hitches without allowing the heap to grow uncontrollably:
1. **Accelerate the collection**: Adapt the parallel stop-the-world mark phase (`lua_ParallelMark`) from the Sim thread to the UI thread using the existing `CUserWorkerPool` (which manages 4–8 user worker threads).
2. **Retain runtime switch controls**:
   - `ui_PeriodicGC` (default `true`): controls whether `CUIManager::UpdateFrameRate` triggers the 5-second forced collection reset or allows dynamic Lua thresholding.
   - `ui_ParallelMark` (default `true`): controls whether `PropagateMarksForCollection` and `parallel_weak::Clear` run across `CUserWorkerPool` worker threads instead of single-threaded on the main thread.
3. **Comprehensive Profiling Matrix**:
   - Add a Tracy zone inside `luaC_collectgarbage` (`UI::LuaGC` on the main thread) and Tracy heap memory plot so all UI collections are measured regardless of trigger mechanism.
   - Benchmark all 4 switch combinations on full-speed windowed replay with UI active.

---

## Detailed Design

### 1. Worker Pool Abstraction in `src/lua/LuaObject.cpp`

Currently, `parallel_mark` and `parallel_weak::Clear` directly call `moho::CSimWorkerPool::Get()`.

We define an internal helper to determine the active pool and worker capabilities:

```cpp
namespace
{
  enum class EGcPoolKind
  {
    None,
    Sim,
    User
  };

  struct GcWorkerPoolInfo
  {
    EGcPoolKind kind{EGcPoolKind::None};
    unsigned int workerCount{0};

    [[nodiscard]] bool IsParallel() const noexcept {
      return kind != EGcPoolKind::None && workerCount > 0u;
    }

    template <class Body>
    void ParallelFor(std::size_t count, std::size_t grain, Body&& body) const
    {
      if (kind == EGcPoolKind::Sim) {
        moho::CSimWorkerPool::Get().ParallelFor(count, grain, std::forward<Body>(body));
      } else if (kind == EGcPoolKind::User) {
        moho::CUserWorkerPool::Get().ParallelFor(count, grain, std::forward<Body>(body));
      } else {
        body(0u, count);
      }
    }
  };

  [[nodiscard]] GcWorkerPoolInfo GetActiveGcPool() noexcept
  {
    if (moho::IsSimThread()) {
      if (!moho::IsSimWorkerThread() && moho::lua_ParallelMark &&
          moho::CSimWorkerPool::ParallelEnabled() && moho::CSimWorkerPool::Get().WorkerCount() > 0u) {
        return {EGcPoolKind::Sim, moho::CSimWorkerPool::Get().WorkerCount()};
      }
    } else {
      // Main / UI thread:
      if (moho::ui_ParallelMark && moho::CUserWorkerPool::ConfiguredWorkerCount() > 0u) {
        return {EGcPoolKind::User, moho::CUserWorkerPool::ConfiguredWorkerCount()};
      }
    }
    return {EGcPoolKind::None, 0u};
  }
}
```

### 2. Parallel Mark & Weak Table Dispatch

- In `parallel_mark::Enabled()`:
  - Check `GetActiveGcPool().IsParallel()`.
- In `PropagateMarksForCollection`:
  - `const GcWorkerPoolInfo pool = GetActiveGcPool();`
  - `round.workers.resize(pool.workerCount + 1u);`
  - `pool.ParallelFor(round.workers.size(), 1u, ...);`
- In `parallel_weak::Clear`:
  - `const GcWorkerPoolInfo pool = GetActiveGcPool();`
  - `pool.ParallelFor(jobs.size(), 8u, ...);`

### 3. Tracy Profiling of all UI Collections

In `luaC_collectgarbage(lua_State* const state)`:
```cpp
const bool isSim = moho::IsSimThread();
FAF_PROFILE_ZONE_NAMED(isSim ? "Sim::LuaGC" : "UI::LuaGC");
```
This ensures every full collection (whether triggered from `CUIManager::UpdateFrameRate`, `luaC_checkGC`, or elsewhere) is recorded and timed with its exact duration in Tracy.

### 4. Convars and Switches

1. **`ui_PeriodicGC`** (in `src/moho/ui/CUIManager.cpp`):
   - Type: `bool`
   - Default: `true` (retail behavior)
   - Description: "Enable forced periodic 5-second UI Lua GC reset (retail behaviour). When false, Lua manages GC threshold dynamically."
2. **`ui_ParallelMark`** (in `src/moho/ui/CUIManager.cpp` or `src/lua/LuaObject.cpp`):
   - Type: `bool`
   - Default: `true`
   - Description: "Mark UI Lua objects on CUserWorkerPool worker threads during garbage collection."

Both documented in `docs/SWITCHES.md`.

---

## Benchmark & Verification Plan

### Test Matrix

Run 4 runs of replay `26915859` (49:44 game time, heavy 8-player replay) at full speed on `main_x64_profile.exe` with `/simworkers 8` and active UI window:

| Config | `ui_PeriodicGC` | `ui_ParallelMark` | Expected Behavior |
|---|---|---|---|
| **1. Retail Baseline** | `1` | `0` | Collections every 5s, pause ~42–60 ms, heap ~53 MB |
| **2. Dynamic Serial** | `0` | `0` | Collections every ~42s, pause ~80–123 ms, heap ~93 MB |
| **3. Dynamic Parallel**| `0` | `1` | Collections every ~42s, parallel mark on 6-8 workers |
| **4. Periodic Parallel**| `1` | `1` | Collections every 5s, parallel mark, target pause ~8–15 ms |

### Key Metrics to Collect:
- Number of full UI collections
- Average pause duration (ms)
- Maximum pause duration (ms)
- Total UI GC time across replay
- Frame distribution: Frames > 33 ms, > 50 ms, > 100 ms
- 99.9th percentile frame duration
- Peak UI Lua heap (MB)

### Determinism & Multiplayer Parity
- UI Lua state is completely isolated from the simulation state.
- Sim checksum and multiplayer replay verification are unaffected.
