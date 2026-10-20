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

    /// True for the first `limit` calls. Once the budget is spent this is one relaxed load: no
    /// further tickets are taken, so a hot-path probe stops paying for the atomic increment and the
    /// counter can never wrap.
    [[nodiscard]] bool Take(const int limit) noexcept
    {
      if (Count() >= limit) {
        return false;
      }
      return Next() < limit;
    }

    /// Tickets taken so far (at most a few past the largest `limit` passed to `Take`, from racing
    /// callers; `Next` callers take one ticket each).
    [[nodiscard]] int Count() const noexcept
    {
      return mCount.load(std::memory_order_relaxed);
    }

  private:
    std::atomic<int> mCount{0};
  };
} // namespace moho
