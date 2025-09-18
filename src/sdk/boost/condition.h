#pragma once

/**
 * Boost.Thread 1.34-compatible condition variable:
 * - API: wait(lock), timed_wait(lock, xtime const&), notify_one(), notify_all()
 * - Windows: emulation via Semaphore + Manual-Reset Event + waiter accounting
 * - POSIX: pthread_cond_t
 * - Works with our boost::mutex wrapper (in-place CRITICAL_SECTION on Win32)
 *
 * Spurious wakeups are possible: use predicate loop around wait/timed_wait.
 */

#include "platform/Platform.h"
#include <limits>

#include "mutex.h"
#include "xtime.h"

namespace boost
{
    class condition
	{
    public:
        /** Construct empty condition variable. */
        condition() noexcept {
#if defined(_WIN32)
            InitializeCriticalSection(&waiters_lock_);
            waiters_ = 0;
            was_broadcast_ = 0;
            sema_ = CreateSemaphoreW(nullptr, 0, std::numeric_limits<LONG>::max(), nullptr);
            done_ = CreateEventW(nullptr, TRUE /*manual reset*/, FALSE /*nonsignaled*/, nullptr);
#else
            pthread_mutexattr_t ma{}; pthread_mutexattr_init(&ma);
            pthread_mutex_init(&guard_, &ma);
            pthread_mutexattr_destroy(&ma);

            pthread_condattr_t ca{}; pthread_condattr_init(&ca);
            pthread_cond_init(&cv_, &ca);
            pthread_condattr_destroy(&ca);
#endif
        }

        /**
         * Destroy condition variable. Undefined behavior if waiters exist.
         */
        ~condition() {
#if defined(_WIN32)
            CloseHandle(sema_);
            CloseHandle(done_);
            DeleteCriticalSection(&waiters_lock_);
#else
            pthread_cond_destroy(&cv_);
            pthread_mutex_destroy(&guard_);
#endif
        }

        /**
         * Wait indefinitely until notified.
         * The lock must own a boost::mutex at entry; it is atomically released
         * during wait and reacquired before return.
         */
        void wait(mutex::scoped_lock& lock) noexcept {
#if defined(_WIN32)
            EnterCriticalSection(&waiters_lock_);
            ++waiters_;
            LeaveCriticalSection(&waiters_lock_);

            lock.unlock();
            WaitForSingleObject(sema_, INFINITE);

            bool last = false;
            EnterCriticalSection(&waiters_lock_);
            if (was_broadcast_) {
                last = (--waiters_ == 0);
            } else {
                --waiters_;
            }
            LeaveCriticalSection(&waiters_lock_);

            if (last) {
                SetEvent(done_); // last waiter leaving broadcast
            }

            lock.lock();
#else
            pthread_cond_wait(&cv_, __boost_mutex_native__(lock));
#endif
        }

        /**
         * Timed wait until absolute deadline `xt`. Returns true if signaled, false on timeout.
         * The lock is atomically released and reacquired across the wait.
         */
        bool timed_wait(mutex::scoped_lock& lock, const xtime& xt) noexcept {
#if defined(_WIN32)
            // Compute timeout in milliseconds relative to now (TIME_UTC)
            xtime now{};
            if (xtime_get(&now, kTimeUtc) != kTimeUtc) {
                // Unable to get time: fall back to immediate timeout behavior
                return false;
            }
            long long now_ms = 1000LL * static_cast<long long>(now.sec) + now.nsec / 1000000LL;
            long long tgt_ms = 1000LL * static_cast<long long>(xt.sec) + xt.nsec / 1000000LL;

            DWORD timeout = 0;
            if (tgt_ms <= now_ms) {
                timeout = 0;
            } else {
                long long diff = tgt_ms - now_ms;
                if (diff > static_cast<long long>(std::numeric_limits<DWORD>::max()))
                    timeout = std::numeric_limits<DWORD>::max();
                else
                    timeout = static_cast<DWORD>(diff);
            }

            EnterCriticalSection(&waiters_lock_);
            ++waiters_;
            LeaveCriticalSection(&waiters_lock_);

            lock.unlock();
            DWORD wr = WaitForSingleObject(sema_, timeout);
            bool signaled = (wr == WAIT_OBJECT_0);

            bool last = false;
            EnterCriticalSection(&waiters_lock_);
            if (was_broadcast_) {
                last = (--waiters_ == 0);
            } else {
                --waiters_;
            }
            LeaveCriticalSection(&waiters_lock_);

            if (last) {
                SetEvent(done_);
            }

            lock.lock();
            return signaled;
#else
            timespec abs{};
            abs.tv_sec = static_cast<time_t>(xt.sec);
            abs.tv_nsec = static_cast<long>(xt.nsec);
            int r = pthread_cond_timedwait(&cv_, __boost_mutex_native__(lock), &abs);
            return r == 0;
#endif
        }

        /**
         * Wake one waiting thread (if any).
         */
        void notify_one() noexcept {
#if defined(_WIN32)
            EnterCriticalSection(&waiters_lock_);
            bool have_waiters = (waiters_ > 0);
            LeaveCriticalSection(&waiters_lock_);
            if (have_waiters) {
                ReleaseSemaphore(sema_, 1, nullptr);
            }
#else
            pthread_cond_signal(&cv_);
#endif
        }

        /**
         * Wake all waiting threads (if any).
         */
        void notify_all() noexcept {
#if defined(_WIN32)
            EnterCriticalSection(&waiters_lock_);
            if (waiters_ > 0) {
                was_broadcast_ = 1;
                ReleaseSemaphore(sema_, waiters_, nullptr);
                LeaveCriticalSection(&waiters_lock_);

                // Wait until all waiters drain the semaphore and exit wait()
                WaitForSingleObject(done_, INFINITE);
                ResetEvent(done_);

                EnterCriticalSection(&waiters_lock_);
                was_broadcast_ = 0;
            }
            LeaveCriticalSection(&waiters_lock_);
#else
            pthread_cond_broadcast(&cv_);
#endif
        }

        // non-copyable
        condition(const condition&) = delete;
        condition& operator=(const condition&) = delete;

    private:
#if defined(_WIN32)
        CRITICAL_SECTION waiters_lock_;
        long             waiters_;
        int              was_broadcast_;
        HANDLE           sema_;
        HANDLE           done_;
#else
        pthread_mutex_t  guard_;
        pthread_cond_t   cv_;
#endif
    };

}
