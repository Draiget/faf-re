#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>

#include "moho/sim/SimThreadRole.h"

namespace moho
{
  /**
   * Engine addition, not recovered from the binary: the floating-point control state that sim
   * arithmetic runs under.
   *
   * The Sim thread sets 24-bit x87 precision (`_controlfp(_PC_24, _MCW_PC)` in
   * `CSimDriver::ThreadCreateSim`) and inherits the default SSE MXCSR. A new thread starts with
   * the CRT defaults instead, so a sim job run there could round differently from the serial path.
   * That is a desync. Every CSimWorkerPool job therefore runs under the dispatching thread's state,
   * captured at dispatch.
   */
  struct SFpuControlState
  {
    std::uint32_t mX87ControlWord; // FNSTCW: precision, rounding, exception masks (0 on non-x86 targets)
    std::uint32_t mMxcsr;          // SSE control bits only; the sticky exception flags are dropped

    /// Reads the calling thread's x87 control word and MXCSR.
    [[nodiscard]] static SFpuControlState Capture() noexcept;

    /// Loads this state into the calling thread's FPU and SSE control registers.
    void Apply() const noexcept;

    [[nodiscard]] friend bool operator==(const SFpuControlState&, const SFpuControlState&) noexcept = default;
  };

  /**
   * Engine addition, not recovered from the binary: fixed worker pool for data-parallel sim phases.
   *
   * The contract is "execution order may vary, commit order may not":
   * - A job body may read shared sim state but writes only to storage owned by its own items.
   * - It must not draw from the sim RNG, create or destroy entities, call Lua, or create or copy
   *   `WeakPtr`s / `LuaObject`s. `MOHO_ASSERT_NOT_SIM_WORKER` enforces the last two in Debug.
   * - The caller then commits the per-item results serially, in item order.
   *
   * Determinism guarantees:
   * - Chunk boundaries depend only on `count` and `grain`, never on the worker count.
   * - Every chunk runs under the dispatcher's floating-point state (SFpuControlState).
   * - The same job with 0 workers (fully serial) and with N workers produces identical results.
   *   Checking exactly that is the determinism test for any parallel phase.
   *
   * Worker count: the `sim_Workers` console variable, seeded from `/simworkers N` on the command
   * line. 0, the default, runs every job inline on the caller, which is the original serial path.
   * A changed value takes effect at the next dispatch. Threads are created on first use.
   */
  /**
   * Engine addition: `sim_Workers`, a user-side (process-local) console variable. It is never sent
   * to the sim, so clients may differ; parallel phases produce the serial result either way.
   * -1 until first use, then the `/simworkers` value (0 when absent).
   */
  extern int sim_Workers;

  /**
   * Engine addition: per-phase switches, user-side like `sim_Workers`, so any parallel phase can
   * be forced back to its serial path for bisection. They only matter while `sim_Workers > 0`.
   */
  extern bool sim_ParallelRecon;
  extern bool sim_ParallelSync;
  extern bool sim_ParallelCoords; // Sim.cpp: the coordinate pass on workers
  extern bool sim_ParallelUnitSyncRefresh; // Sim.cpp: units' own sync blocks refreshed on workers

  /**
   * Engine addition, debug only: microseconds a worker thread waits before each chunk it takes
   * (0, the default, waits nothing). The dispatching thread takes the first chunks itself and the
   * workers come in late, so chunks overlap in other combinations than they do without it: a chunk
   * that touches state another chunk owns shows up as a checksum mismatch instead of passing by
   * luck. Results must not change with any value.
   */
  extern int sim_WorkerJobDelayUs;

  class CSimWorkerPool
  {
  public:
    using RangeFunction = void (*)(void* context, std::size_t begin, std::size_t end);

    [[nodiscard]] static CSimWorkerPool& Get();

    /**
     * True when parallel phases should run: `sim_Workers`, resolved from `/simworkers` on first
     * call, is above 0. Callers test this before taking a phase's parallel path.
     */
    [[nodiscard]] static bool ParallelEnabled();

    CSimWorkerPool(const CSimWorkerPool&) = delete;
    CSimWorkerPool& operator=(const CSimWorkerPool&) = delete;
    ~CSimWorkerPool();

    /// Worker threads this pool will use (0 = every job runs serially on the calling thread).
    [[nodiscard]] unsigned int WorkerCount() const noexcept;

    /**
     * Runs `fn(context, begin, end)` over [0, count) in chunks of `grain` items. The calling
     * thread helps, and the call returns once every chunk has finished.
     * - If a chunk throws, the first exception is rethrown here after all chunks are done.
     * - A nested call, or a call from a worker, runs serially on the calling thread.
     * - Concurrent dispatchers are serialized.
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
    CSimWorkerPool();

    struct Impl;
    std::unique_ptr<Impl> mImpl;
  };
} // namespace moho
