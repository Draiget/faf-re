# UI Parallel Lua Garbage Collection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accelerate the UI Lua garbage collection stop-the-world pause from 42–60 ms down to ~8–15 ms by dispatching the mark and weak-table clearing phases to `CUserWorkerPool` worker threads, while preserving runtime switches for retail behavior and benchmarking.

**Architecture:** Introduce a unified worker pool dispatch helper in `src/lua/LuaObject.cpp` that selects `CSimWorkerPool` on the Sim thread and `CUserWorkerPool` on the main/UI thread. Gate UI parallelism behind `ui_ParallelMark` (default `true`) and retail 5-second periodic resets behind `ui_PeriodicGC` (default `true`). Add a Tracy profiling zone in `luaC_collectgarbage` to capture all collections, and benchmark the 4 switch combinations in a windowed replay with UI active.

**Tech Stack:** C++20, Lua 5.0 (LuaPlus), Moho engine threading (`CSimWorkerPool`, `CUserWorkerPool`), Tracy Profiler.

**Spec:** [docs/superpowers/specs/2026-10-29-ui-parallel-gc-design.md](file:///i:/ProjectsFaf/faf-re/docs/superpowers/specs/2026-10-29-ui-parallel-gc-design.md)

## Global Constraints

- Never break simulation checksum determinism: UI Lua state must remain strictly decoupled from the Sim Lua state.
- All performance switches must be documented in [docs/SWITCHES.md](file:///i:/ProjectsFaf/faf-re/docs/SWITCHES.md) immediately alongside code changes.
- Every switch must support runtime `/con <switch>=<value>` toggling and startup `/con` syntax without crashing.
- Preserved comments and docstrings must remain intact.

## Review Focus

1. **Deadlock on User Worker**: If a Lua GC is somehow triggered from within a worker thread running a job, calling `ParallelFor` on the same pool will deadlock or throw. The pool dispatcher must return `None` (serial fallback) when called from a worker thread.
2. **Zero Workers Configured**: If `user_Workers` is set to `0`, `CUserWorkerPool::ConfiguredWorkerCount()` is `0`. The dispatcher must safely fall back to serial execution without crashing or dividing by zero.
3. **Concurrent Mark Race**: Sim GC and UI GC running at the exact same moment must not share any mutable static state. All work structures in `parallel_mark` must be strictly thread-local or stack-allocated.
4. **Tracy Zone Mismatch**: Tracy zones inside `luaC_collectgarbage` must properly differentiate `Sim::LuaGC` vs `UI::LuaGC` so UI collections aren't conflated with Sim collections.
5. **Replay Checksum Parity**: Toggling `ui_ParallelMark` or `ui_PeriodicGC` must result in 0 checksum mismatches against retail replays.

---

### Task 1: Declare `ui_ParallelMark` and set `ui_PeriodicGC` default to `true`

**Files:**
- Modify: `src/moho/ui/CUIManager.cpp`
- Modify: `docs/SWITCHES.md`

**Interfaces:**
- Produces: `extern bool ui_ParallelMark;` in `moho` namespace.
- Produces: `gTConVar_ui_ParallelMark` console command.

- [ ] **Step 1: Update `CUIManager.cpp` convar definitions**

Update `ui_PeriodicGC` default value from `false` to `true` (retail behavior).
Add `ui_ParallelMark` convar defaulting to `true`:

```cpp
namespace moho
{
  bool ui_PeriodicGC = true;
  TConVar<bool> gTConVar_ui_PeriodicGC(
    "ui_PeriodicGC",
    "Enable forced periodic 5-second UI Lua GC reset (retail behaviour). When false, Lua manages GC threshold dynamically.",
    &ui_PeriodicGC
  );

  bool ui_ParallelMark = true;
  TConVar<bool> gTConVar_ui_ParallelMark(
    "ui_ParallelMark",
    "Mark UI Lua objects on CUserWorkerPool worker threads during garbage collection.",
    &ui_ParallelMark
  );
}
```

- [ ] **Step 2: Update `docs/SWITCHES.md`**

Update the table row for `ui_PeriodicGC` to default `1` and add `ui_ParallelMark`:

```markdown
| `ui_PeriodicGC` | 1 | `/con` | live | Enable forced periodic 5-second UI Lua GC reset (retail behavior); 0 leaves GC threshold dynamic |
| `ui_ParallelMark` | 1 | `/con` | live (next collection) | Mark UI Lua objects across CUserWorkerPool worker threads; 0 runs mark serially on main thread |
```

- [ ] **Step 3: Build and test compilation**

Run: `powershell -ExecutionPolicy Bypass -File ./build.ps1 -Config Release`
Expected: Build succeeds.

- [ ] **Step 4: Commit**

```bash
git add src/moho/ui/CUIManager.cpp docs/SWITCHES.md
git commit -m "feat(ui): add ui_ParallelMark and default ui_PeriodicGC to 1"
```

---

### Task 2: Dispatch `parallel_mark` and `parallel_weak` to `CUserWorkerPool`

**Files:**
- Modify: `src/lua/LuaObject.cpp`
- Include: `"moho/app/UserWorkerPool.h"`

**Interfaces:**
- Consumes: `moho::ui_ParallelMark`, `moho::CUserWorkerPool::Get()`, `moho::CSimWorkerPool::Get()`
- Produces: `GetActiveGcPool()` returning thread-appropriate pool info for `parallel_mark::Enabled`, `PropagateMarksForCollection`, and `parallel_weak::Clear`.

- [ ] **Step 1: Include `UserWorkerPool.h` and declare external convar in `LuaObject.cpp`**

In `src/lua/LuaObject.cpp`, include `moho/app/UserWorkerPool.h` and declare `extern bool ui_ParallelMark;`.

- [ ] **Step 2: Implement `GetActiveGcPool()` helper in `LuaObject.cpp`**

Implement pool dispatch logic:
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
      // Main / UI thread (not running inside a user worker job):
      if (moho::ui_ParallelMark && moho::CUserWorkerPool::ConfiguredWorkerCount() > 0u) {
        return {EGcPoolKind::User, moho::CUserWorkerPool::ConfiguredWorkerCount()};
      }
    }
    return {EGcPoolKind::None, 0u};
  }
}
```

- [ ] **Step 3: Update `parallel_mark::Enabled()`**

Replace hardcoded sim check with `GetActiveGcPool().IsParallel()`:
```cpp
[[nodiscard]] bool Enabled() noexcept
{
  return GetActiveGcPool().IsParallel();
}
```

- [ ] **Step 4: Update `PropagateMarksForCollection` and `parallel_weak::Clear`**

In `PropagateMarksForCollection`:
```cpp
const GcWorkerPoolInfo pool = GetActiveGcPool();
Round round;
round.g = st->g;
round.workers.resize(pool.workerCount + 1u);
...
pool.ParallelFor(round.workers.size(), 1u, [&round](const std::size_t begin, const std::size_t end) {
...
```

In `parallel_weak::Clear`:
```cpp
const GcWorkerPoolInfo pool = GetActiveGcPool();
pool.ParallelFor(jobs.size(), 8u, [&jobs](const std::size_t begin, const std::size_t end) {
...
```

- [ ] **Step 5: Build and verify compilation**

Run: `powershell -ExecutionPolicy Bypass -File ./build.ps1 -Config Release`
Expected: Clean compilation, 0 errors.

- [ ] **Step 6: Commit**

```bash
git add src/lua/LuaObject.cpp
git commit -m "feat(lua): enable parallel mark and weak table clear on CUserWorkerPool for UI state"
```

---

### Task 3: Add Tracy Zone to `luaC_collectgarbage`

**Files:**
- Modify: `src/lua/LuaObject.cpp:18390`

**Interfaces:**
- Produces: Tracy zone `UI::LuaGC` when called on UI thread, `Sim::LuaGC` when called on Sim thread.

- [ ] **Step 1: Add profile zone to `luaC_collectgarbage`**

In `src/lua/LuaObject.cpp`, inside `luaC_collectgarbage(lua_State* const state)`:
```cpp
void luaC_collectgarbage(lua_State* const state)
{
  const bool isSim = moho::IsSimThread();
  FAF_PROFILE_ZONE_NAMED(isSim ? "Sim::LuaGC" : "UI::LuaGC");
  ...
```

- [ ] **Step 2: Build profile configuration**

Run: `powershell -ExecutionPolicy Bypass -File ./build.ps1 -Config Profile`
Expected: Build succeeds.

- [ ] **Step 3: Commit**

```bash
git add src/lua/LuaObject.cpp
git commit -m "perf(profiling): add Tracy zone for UI::LuaGC inside luaC_collectgarbage"
```

---

### Task 4: Author Benchmark Script & Execute 4-Configuration Matrix

**Files:**
- Create: `scripts/perf/benchmark_ui_gc.py`

**Interfaces:**
- Consumes: `build/x64-Profile/main_x64_profile.exe`, replay `26915859.scfareplay` (or vault benchmark replay).
- Produces: Comparative summary table with GC pause stats (min, avg, max, count, total time) and frame percentiles across the 4 configurations.

- [ ] **Step 1: Write `benchmark_ui_gc.py` script**

The script runs the game with windowed display and UI active for each configuration:
1. `ui_PeriodicGC=1`, `ui_ParallelMark=0` (Retail baseline)
2. `ui_PeriodicGC=0`, `ui_ParallelMark=0` (Dynamic single-thread)
3. `ui_PeriodicGC=0`, `ui_ParallelMark=1` (Dynamic parallel)
4. `ui_PeriodicGC=1`, `ui_ParallelMark=1` (Periodic parallel target)

Captures Tracy traces and extracts `UI::LuaGC` zone execution metrics.

- [ ] **Step 2: Run benchmarks and record Tracy data**

Execute the 4 runs with windowed playback and UI active.
Extract metrics:
- GC Collection count
- Min pause
- Average pause
- Max pause
- Total GC time
- Frame count > 33 ms, > 50 ms, > 100 ms

- [ ] **Step 3: Verify simulation checksum parity**

Run replay validation to ensure 0 checksum desyncs:
`build/x64-Release/main_x64.exe /replay <replay_path> /simworkers 8`
Verify all recorded checksums match 100%.

- [ ] **Step 4: Commit benchmark script and results**

```bash
git add scripts/perf/benchmark_ui_gc.py
git commit -m "test(perf): add comparative benchmark runner for UI GC combinations"
```
