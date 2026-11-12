#pragma once

#include "legacy/thread/Mutex.h"
#include "platform/PlatformDefines.h"

#include <mutex>

#if !FAFRE_PLATFORM_WINDOWS
#include <pthread.h>
#endif

namespace fa
{
  /**
   * The 2007 binary's `boost::condition` (boost 1.34.1), with its layout and behaviour.
   *
   * On Windows it is boost's own algorithm (libs/thread/src/condition.cpp, "8a"): a gate semaphore, a queue semaphore
   * and a mutex handle, with three counters. Unlike a Win32 CONDITION_VARIABLE it never wakes a waiter without a
   * notify, and two waits in `CWaitHandleSet.cpp` don't re-check their condition after waking. 24 bytes on x86, which
   * recovered layouts pin (`FileWaitHandleSet.h`, `ResourceManager.h`, `SimDriver.h`). On POSIX it is the
   * `pthread_cond_t` boost used there.
   *
   * Only what the engine calls is here: `wait` (on an `fa::mutex` or `fa::recursive_mutex` lock) and `notify_all`.
   */
  class condition
  {
  public:
    condition();
    ~condition();

    condition(const condition&) = delete;
    condition& operator=(const condition&) = delete;

    /** Wakes every thread waiting now. */
    void notify_all();

    /**
     * Releases `lock`, sleeps until notified, takes `lock` back. As boost: the waiter registers before it releases
     * the lock, so a notify after the release reaches it.
     */
    template <class Mutex>
    void wait(
      std::unique_lock<Mutex>& lock
    )
    {
      Mutex& mutex = *lock.mutex();
      typename Mutex::cv_state state{};
#if FAFRE_PLATFORM_WINDOWS
      EnterWait();
      mutex.begin_wait(state);
      DoWait();
      mutex.end_wait(state);
#else
      mutex.begin_wait(state);
      pthread_cond_wait(&mCondition, mutex.native_handle());
      mutex.end_wait(state);
#endif
    }

  private:
#if FAFRE_PLATFORM_WINDOWS
    void EnterWait();
    void DoWait();

    void* mGate;            // boost's m_gate: semaphore, 1 when waiters may register
    void* mQueue;           // boost's m_queue: semaphore the waiters sleep on
    void* mMutex;           // boost's m_mutex: guards the counters
    unsigned mGone;         // boost's m_gone: waiters that left without a signal
    unsigned long mBlocked; // boost's m_blocked: waiters registered, not yet signalled
    unsigned mWaiting;      // boost's m_waiting: waiters signalled, not yet woken
#else
    pthread_cond_t mCondition;
#endif
  };

#if FAFRE_PLATFORM_WINDOWS
  static_assert(sizeof(void*) != 4 || sizeof(condition) == 0x18, "fa::condition keeps boost::condition's x86 size");
#endif
} // namespace fa
