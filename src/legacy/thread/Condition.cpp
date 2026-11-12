#include "legacy/thread/Condition.h"

#include <limits>
#include <system_error>

#if FAFRE_PLATFORM_WINDOWS
#include "platform/Platform.h"
#endif

namespace fa
{
#if FAFRE_PLATFORM_WINDOWS
  namespace
  {
    HANDLE AsHandle(
      void* const handle
    ) noexcept
    {
      return static_cast<HANDLE>(handle);
    }

    void Acquire(
      void* const handle
    ) noexcept
    {
      (void)::WaitForSingleObject(AsHandle(handle), INFINITE);
    }

    void ReleaseOne(
      void* const semaphore
    ) noexcept
    {
      (void)::ReleaseSemaphore(AsHandle(semaphore), 1, nullptr);
    }
  } // namespace

  /**
   * Address: 0x00AC2190 (FUN_00AC2190, boost::detail::condition_impl::condition_impl)
   *
   * The counters at +0x0C..+0x14 are zeroed, then the gate semaphore (initial 1, max 1), the queue semaphore
   * (initial 0, max 0x7FFFFFFF) and the counter mutex are created, all unnamed, so which of the A/W entry points
   * makes them doesn't matter. A failed create throws (boost: thread_resource_error).
   */
  condition::condition()
    : mGate(::CreateSemaphoreW(nullptr, 1, 1, nullptr))
    , mQueue(::CreateSemaphoreW(nullptr, 0, (std::numeric_limits<long>::max)(), nullptr))
    , mMutex(::CreateMutexW(nullptr, FALSE, nullptr))
    , mGone(0)
    , mBlocked(0)
    , mWaiting(0)
  {
    if (mGate == nullptr || mQueue == nullptr || mMutex == nullptr) {
      const DWORD error = ::GetLastError();
      for (void* const handle : {mGate, mQueue, mMutex}) {
        if (handle != nullptr) {
          ::CloseHandle(AsHandle(handle));
        }
      }
      throw std::system_error(static_cast<int>(error), std::system_category(), "fa::condition");
    }
  }

  condition::~condition()
  {
    ::CloseHandle(AsHandle(mGate));
    ::CloseHandle(AsHandle(mQueue));
    ::CloseHandle(AsHandle(mMutex));
  }

  // boost's condition_impl::notify_all (Win32).
  void condition::notify_all()
  {
    unsigned signals = 0;

    Acquire(mMutex);
    if (mWaiting != 0) { // the gate is already closed
      if (mBlocked == 0) {
        (void)::ReleaseMutex(AsHandle(mMutex));
        return;
      }
      mWaiting += (signals = mBlocked);
      mBlocked = 0;
    } else {
      Acquire(mGate);
      if (mBlocked > mGone) {
        if (mGone != 0) {
          mBlocked -= mGone;
          mGone = 0;
        }
        signals = mWaiting = mBlocked;
        mBlocked = 0;
      } else {
        ReleaseOne(mGate);
      }
    }
    (void)::ReleaseMutex(AsHandle(mMutex));

    if (signals != 0) {
      (void)::ReleaseSemaphore(AsHandle(mQueue), static_cast<LONG>(signals), nullptr);
    }
  }

  // boost's condition_impl::enter_wait (Win32): register as blocked while the gate is open.
  void condition::EnterWait()
  {
    Acquire(mGate);
    ++mBlocked;
    ReleaseOne(mGate);
  }

  // boost's condition_impl::do_wait (Win32).
  void condition::DoWait()
  {
    Acquire(mQueue);

    unsigned wasWaiting = 0;
    unsigned wasGone = 0;

    Acquire(mMutex);
    wasWaiting = mWaiting;
    wasGone = mGone;
    if (wasWaiting != 0) {
      if (--mWaiting == 0) {
        if (mBlocked != 0) {
          ReleaseOne(mGate); // open the gate
          wasWaiting = 0;
        } else if (mGone != 0) {
          mGone = 0;
        }
      }
    } else if (++mGone == ((std::numeric_limits<unsigned>::max)() / 2)) {
      // Normalize the gone count, as boost does after many waits that ended without a notify.
      Acquire(mGate);
      mBlocked -= mGone;
      ReleaseOne(mGate);
      mGone = 0;
    }
    (void)::ReleaseMutex(AsHandle(mMutex));

    if (wasWaiting == 1) {
      for (; wasGone != 0; --wasGone) {
        Acquire(mQueue); // better now than spurious later (boost)
      }
      ReleaseOne(mGate);
    }
  }
#else
  condition::condition()
  {
    const int result = pthread_cond_init(&mCondition, nullptr);
    if (result != 0) {
      throw std::system_error(result, std::generic_category(), "fa::condition");
    }
  }

  condition::~condition()
  {
    pthread_cond_destroy(&mCondition);
  }

  void condition::notify_all()
  {
    pthread_cond_broadcast(&mCondition);
  }
#endif
} // namespace fa
