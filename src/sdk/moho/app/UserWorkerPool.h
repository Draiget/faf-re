#pragma once

#include <cstddef>
#include <memory>
#include <type_traits>

namespace moho
{
  /**
   * Engine addition, not recovered from the binary: `user_Workers`, a process-local console
   * variable giving the worker threads CUserWorkerPool may use for main-thread (user-side) jobs:
   * -1 (the default) picks min(usable CPUs - 2, 6), 0 runs every job inline on the main thread.
   * Nothing a user-side job computes reaches the simulation, so this never affects a checksum.
   */
  extern int user_Workers;

  /**
   * Engine addition: `ren_ParallelCull`, user-side. Run large view queries (visible meshes and
   * decals, fog-of-war circles) on CUserWorkerPool. The results and their order are exactly the
   * serial ones.
   */
  extern bool ren_ParallelCull;

  /**
   * Engine addition, not recovered from the binary: fork-join pool for data-parallel work on the
   * main (render/UI) thread, separate from CSimWorkerPool so neither side ever waits on the other's
   * jobs.
   *
   * The contract matches CSimWorkerPool's: a job body reads shared state that nothing writes during
   * the job and writes only storage owned by its own items; the caller merges per-chunk results in
   * chunk order afterwards, so the result is the serial result whatever the worker count. Job
   * bodies must not run Lua, touch D3D, create or copy `WeakPtr`s / `LuaObject`s, or change any
   * container the main thread shares. Allocation is allowed (the engine heap is thread-safe and
   * user-side addresses never reach the sim).
   *
   * Chunks run under the dispatching thread's x87/SSE control state, so floating-point results are
   * bit-identical to the serial path.
   */
  class CUserWorkerPool
  {
  public:
    using RangeFunction = void (*)(void* context, std::size_t begin, std::size_t end);

    [[nodiscard]] static CUserWorkerPool& Get();

    CUserWorkerPool(const CUserWorkerPool&) = delete;
    CUserWorkerPool& operator=(const CUserWorkerPool&) = delete;
    ~CUserWorkerPool();

    /// Worker threads the next dispatch will use (0 = serial), after resolving `user_Workers`.
    [[nodiscard]] static unsigned int ConfiguredWorkerCount();

    /**
     * Runs `fn(context, begin, end)` over [0, count) in chunks of `grain` items; the calling
     * thread helps. Returns once every chunk has finished; the first exception a chunk threw is
     * rethrown here. Nested calls and calls from a worker run serially.
     */
    void Run(std::size_t count, std::size_t grain, RangeFunction fn, void* context);

    /// `Run` over a callable taking `(std::size_t begin, std::size_t end)`.
    template <class Body>
    void ParallelFor(const std::size_t count, const std::size_t grain, Body&& body)
    {
      using BodyType = std::remove_reference_t<Body>;
      Run(
        count,
        grain,
        [](void* const context, const std::size_t begin, const std::size_t end) {
          (*static_cast<BodyType*>(context))(begin, end);
        },
        const_cast<void*>(static_cast<const void*>(std::addressof(body)))
      );
    }

  private:
    CUserWorkerPool();

    struct Impl;
    std::unique_ptr<Impl> mImpl;
  };
} // namespace moho
