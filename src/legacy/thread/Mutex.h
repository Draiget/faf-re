#pragma once

#include "platform/PlatformDefines.h"

#include <mutex>

#if !FAFRE_PLATFORM_WINDOWS
#include <pthread.h>
#endif

namespace fa
{
  /**
   * The 2007 binary's `boost::mutex` (boost 1.34.1), with its layout and behaviour.
   *
   * On Windows it is boost's critical-section mutex: the constructor allocates a `CRITICAL_SECTION` on the heap
   * (boost's `new_critical_section`), so the engine makes the same allocation at the same moment, and the thread
   * holding it may take it again (`STAT_GetLuaTable` relies on that). 8 bytes on x86, which recovered layouts pin
   * (`FileWaitHandleSet.h`, `Stats.h`, `SimDriver.h`). On POSIX it is the recursive pthread mutex boost's file was
   * built with there (formerly `platform/posix/BoostMutexPosix.cpp`).
   *
   * `scoped_lock` is `std::unique_lock`; `fa::condition` waits on it.
   */
  class mutex
  {
  public:
    using scoped_lock = std::unique_lock<mutex>;

    /** What a condition wait keeps of the lock while it sleeps: nothing for a plain mutex. */
    struct cv_state
    {};

    mutex();
    ~mutex();

    mutex(const mutex&) = delete;
    mutex& operator=(const mutex&) = delete;

    void lock();
    void unlock();

    /** Before a condition wait: on Windows the lock is released here; on POSIX pthread_cond_wait releases it. */
    void begin_wait(cv_state& state);
    /** After a condition wait: takes the lock back where begin_wait released it. */
    void end_wait(cv_state& state);

#if !FAFRE_PLATFORM_WINDOWS
    [[nodiscard]] pthread_mutex_t* native_handle() noexcept
    {
      return &mMutex;
    }
#endif

  private:
#if FAFRE_PLATFORM_WINDOWS
    void* mCriticalSection;    // CRITICAL_SECTION*, boost's m_mutex
    bool mUsesCriticalSection; // boost's m_critical_section, always true in its Win32 build
#else
    pthread_mutex_t mMutex;
#endif
  };

  /**
   * The 2007 binary's `boost::recursive_mutex` (boost 1.34.1): one critical section held once by its owner, and a
   * count of how often the owner took it. 12 bytes on x86 (`ResourceManager.h`, `CNetUDPConnector.h`).
   *
   * A condition wait releases every level and restores the count afterwards, as boost's `do_unlock(cv_state&)` does.
   * POSIX keeps the same scheme over a recursive pthread mutex, so the OS lock is held once while the count is above
   * zero and pthread_cond_wait can release it.
   */
  class recursive_mutex
  {
  public:
    using scoped_lock = std::unique_lock<recursive_mutex>;

    /** The owner's lock count, kept across a condition wait. */
    struct cv_state
    {
      unsigned long count = 0;
    };

    recursive_mutex();
    ~recursive_mutex();

    recursive_mutex(const recursive_mutex&) = delete;
    recursive_mutex& operator=(const recursive_mutex&) = delete;

    void lock();
    void unlock();

    void begin_wait(cv_state& state);
    void end_wait(cv_state& state);

#if !FAFRE_PLATFORM_WINDOWS
    [[nodiscard]] pthread_mutex_t* native_handle() noexcept
    {
      return &mMutex;
    }
#endif

  private:
#if FAFRE_PLATFORM_WINDOWS
    void* mCriticalSection;    // CRITICAL_SECTION*, boost's m_mutex
    bool mUsesCriticalSection; // boost's m_critical_section
#else
    pthread_mutex_t mMutex;
#endif
    unsigned long mCount; // boost's m_count: how often the owner holds it
  };

#if FAFRE_PLATFORM_WINDOWS
  static_assert(sizeof(void*) != 4 || sizeof(mutex) == 0x08, "fa::mutex keeps boost::mutex's x86 size");
  static_assert(
    sizeof(void*) != 4 || sizeof(recursive_mutex) == 0x0C,
    "fa::recursive_mutex keeps boost::recursive_mutex's x86 size"
  );
#endif
} // namespace fa
