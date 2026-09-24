#pragma once

#include <atomic>

namespace moho
{
  /**
   * Engine addition, not recovered from the binary: a race-free counter for rate-limited diagnostic
   * probes.
   *
   * Probes throttle their logging with a function-local counter ("log the first N calls", "log every
   * 50th beat"). A plain `static int` there is a data race as soon as the same code can run on more
   * than one thread (CSimWorkerPool jobs), so the count lives in an atomic and each call takes one
   * ticket. Relaxed ordering is enough: the tickets only need to be unique.
   */
  class DiagnosticBudget
  {
  public:
    /// Takes one ticket and returns its zero-based ordinal (0 for the first call, then 1, 2, ...).
    int Next() noexcept
    {
      return mCount.fetch_add(1, std::memory_order_relaxed);
    }

    /// True for the first `limit` calls.
    [[nodiscard]] bool Take(const int limit) noexcept
    {
      return Next() < limit;
    }

    /// Tickets taken so far.
    [[nodiscard]] int Count() const noexcept
    {
      return mCount.load(std::memory_order_relaxed);
    }

  private:
    std::atomic<int> mCount{0};
  };
} // namespace moho
