#include "legacy/thread/Mutex.h"

#include <new>
#include <system_error>

#if FAFRE_PLATFORM_WINDOWS
#include "platform/Platform.h"
#endif

namespace fa
{
  namespace
  {
#if FAFRE_PLATFORM_WINDOWS
    /** boost's new_critical_section (mutex.inl): a heap CRITICAL_SECTION, initialized. */
    void* NewCriticalSection()
    {
      auto* const criticalSection = new CRITICAL_SECTION;
      ::InitializeCriticalSection(criticalSection);
      return criticalSection;
    }

    void FreeCriticalSection(
      void* const criticalSection
    ) noexcept
    {
      auto* const section = static_cast<CRITICAL_SECTION*>(criticalSection);
      ::DeleteCriticalSection(section);
      delete section;
    }

    void Enter(
      void* const criticalSection
    ) noexcept
    {
      ::EnterCriticalSection(static_cast<CRITICAL_SECTION*>(criticalSection));
    }

    void Leave(
      void* const criticalSection
    ) noexcept
    {
      ::LeaveCriticalSection(static_cast<CRITICAL_SECTION*>(criticalSection));
    }
#else
    /** A recursive pthread mutex, as the Windows critical section is. */
    void InitRecursive(
      pthread_mutex_t* const mutex
    )
    {
      pthread_mutexattr_t attributes;
      pthread_mutexattr_init(&attributes);
      pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
      const int result = pthread_mutex_init(mutex, &attributes);
      pthread_mutexattr_destroy(&attributes);
      if (result != 0) {
        throw std::system_error(result, std::generic_category(), "fa::mutex");
      }
    }
#endif
  } // namespace

  // ---------------------------------------------------------------- mutex

  mutex::mutex()
#if FAFRE_PLATFORM_WINDOWS
    : mCriticalSection(NewCriticalSection())
    , mUsesCriticalSection(true)
#endif
  {
#if !FAFRE_PLATFORM_WINDOWS
    InitRecursive(&mMutex);
#endif
  }

  mutex::~mutex()
  {
#if FAFRE_PLATFORM_WINDOWS
    FreeCriticalSection(mCriticalSection);
#else
    pthread_mutex_destroy(&mMutex);
#endif
  }

  void mutex::lock()
  {
#if FAFRE_PLATFORM_WINDOWS
    Enter(mCriticalSection);
#else
    pthread_mutex_lock(&mMutex);
#endif
  }

  void mutex::unlock()
  {
#if FAFRE_PLATFORM_WINDOWS
    Leave(mCriticalSection);
#else
    pthread_mutex_unlock(&mMutex);
#endif
  }

  void mutex::begin_wait(
    cv_state&
  )
  {
#if FAFRE_PLATFORM_WINDOWS
    Leave(mCriticalSection);
#endif
  }

  void mutex::end_wait(
    cv_state&
  )
  {
#if FAFRE_PLATFORM_WINDOWS
    Enter(mCriticalSection);
#endif
  }

  // ---------------------------------------------------------------- recursive_mutex

  recursive_mutex::recursive_mutex()
#if FAFRE_PLATFORM_WINDOWS
    : mCriticalSection(NewCriticalSection())
    , mUsesCriticalSection(true)
    , mCount(0)
#else
    : mCount(0)
#endif
  {
#if !FAFRE_PLATFORM_WINDOWS
    InitRecursive(&mMutex);
#endif
  }

  recursive_mutex::~recursive_mutex()
  {
#if FAFRE_PLATFORM_WINDOWS
    FreeCriticalSection(mCriticalSection);
#else
    pthread_mutex_destroy(&mMutex);
#endif
  }

  // boost's do_lock: take the OS lock, count, and give back the extra level so the OS lock is held once.
  void recursive_mutex::lock()
  {
#if FAFRE_PLATFORM_WINDOWS
    Enter(mCriticalSection);
    if (++mCount > 1) {
      Leave(mCriticalSection);
    }
#else
    pthread_mutex_lock(&mMutex);
    if (++mCount > 1) {
      pthread_mutex_unlock(&mMutex);
    }
#endif
  }

  // boost's do_unlock: the OS lock goes when the count reaches zero.
  void recursive_mutex::unlock()
  {
    if (--mCount == 0) {
#if FAFRE_PLATFORM_WINDOWS
      Leave(mCriticalSection);
#else
      pthread_mutex_unlock(&mMutex);
#endif
    }
  }

  // boost's do_unlock(cv_state&): keep the count, release every level.
  void recursive_mutex::begin_wait(
    cv_state& state
  )
  {
    state.count = mCount;
    mCount = 0;
#if FAFRE_PLATFORM_WINDOWS
    Leave(mCriticalSection);
#endif
  }

  // boost's do_lock(cv_state&): take the lock back and restore the count.
  void recursive_mutex::end_wait(
    cv_state& state
  )
  {
#if FAFRE_PLATFORM_WINDOWS
    Enter(mCriticalSection);
#endif
    mCount = state.count;
  }
} // namespace fa
