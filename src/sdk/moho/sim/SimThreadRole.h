#pragma once

// Engine addition, not recovered from the binary: which kind of thread is running, so code that
// only its owning thread may touch can refuse to run on a CSimWorkerPool worker.
//
// Several "reads" in the sim mutate shared state: copying a WeakPtr links a node into the target's
// owner chain, every LuaPlus::LuaObject links into its root state's used-object list, and so on.
// None of that is synchronized (the binary was single-threaded there), so parallel sim code must
// not do it. MOHO_ASSERT_NOT_SIM_WORKER turns a violation into an immediate assert instead of a
// rare heap corruption. It is on in Debug builds; define MOHO_SIM_AFFINITY_CHECKS=1 to keep it in
// Release. The header is kept dependency-free because WeakPtr.h includes it.

namespace gpg
{
  void HandleAssertFailure(const char* msg, int lineNum, const char* file);
}

namespace moho
{
  /// Set to true for the lifetime of every CSimWorkerPool worker thread.
  inline thread_local bool tIsSimWorkerThread = false;

  /// True while the calling thread is a CSimWorkerPool worker.
  [[nodiscard]] inline bool IsSimWorkerThread() noexcept
  {
    return tIsSimWorkerThread;
  }
} // namespace moho

#if !defined(MOHO_SIM_AFFINITY_CHECKS)
#if defined(_DEBUG)
#define MOHO_SIM_AFFINITY_CHECKS 1
#else
#define MOHO_SIM_AFFINITY_CHECKS 0
#endif
#endif

#if MOHO_SIM_AFFINITY_CHECKS
#define MOHO_ASSERT_NOT_SIM_WORKER(what)                                                                           \
  do {                                                                                                             \
    if (::moho::IsSimWorkerThread()) {                                                                             \
      ::gpg::HandleAssertFailure("sim worker thread touched owner-thread-only state: " what, __LINE__, __FILE__); \
    }                                                                                                              \
  } while (false)
#else
#define MOHO_ASSERT_NOT_SIM_WORKER(what) ((void)0)
#endif
