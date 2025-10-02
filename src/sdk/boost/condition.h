#pragma once
#include "platform/Platform.h"
#include <limits>
#include <cstdint>
#include "mutex.h"
#include "xtime.h"

namespace boost
{
#pragma pack(push, 4)
    /**
     * Legacy Boost.Thread-like condition variable for Win32 (VC8 era) with 24-byte layout.
     * Fields mirror the classic emulation: gate event + queue semaphore + internal mutex + counters.
     * Spurious wakeups are possible; always wait in a predicate loop.
     */
    class condition
    {
    public:
        /** Default ctor: create kernel primitives and zero counters. */
        condition() noexcept {
#if defined(_WIN32)
            m_gate = ::CreateEventW(nullptr, /*manual*/FALSE, /*signaled*/FALSE, nullptr);   // auto-reset
            m_queue = ::CreateSemaphoreW(nullptr, 0, std::numeric_limits<LONG>::max(), nullptr);
            m_mutex = ::CreateMutexW(nullptr, FALSE, nullptr); // protects counters below
            m_gone = 0;
            m_blocked = 0;
            m_waiting = 0;
#else
            pthread_condattr_t ca{}; pthread_condattr_init(&ca);
            ::pthread_cond_init(&cv_, &ca);
            pthread_condattr_destroy(&ca);
#endif
        }

        /** Dtor: destroy primitives. Undefined if waiters still exist. */
        ~condition() {
#if defined(_WIN32)
            if (m_gate)  ::CloseHandle(reinterpret_cast<HANDLE>(m_gate));
            if (m_queue) ::CloseHandle(reinterpret_cast<HANDLE>(m_queue));
            if (m_mutex) ::CloseHandle(reinterpret_cast<HANDLE>(m_mutex));
#else
            ::pthread_cond_destroy(&cv_);
#endif
        }

        /**
         * Block until notified. Releases the associated mutex while waiting and re-acquires it before return.
         */
        void wait(mutex::scoped_lock& lock) noexcept {
#if defined(_WIN32)
            HANDLE gate = reinterpret_cast<HANDLE>(m_gate);
            HANDLE queue = reinterpret_cast<HANDLE>(m_queue);
            HANDLE mtx = reinterpret_cast<HANDLE>(m_mutex);

            // Enter: register as blocked
            ::WaitForSingleObject(mtx, INFINITE);
            ++m_blocked;
            ::ReleaseMutex(mtx);

            // Release external lock and wait on queue
            lock.unlock();
            ::WaitForSingleObject(queue, INFINITE);

            // Post-wake bookkeeping (single or broadcast path)
            ::WaitForSingleObject(mtx, INFINITE);
            if (m_waiting != 0) {
                // Broadcast in progress: we are one of the broadcasted waiters leaving
                if (--m_waiting == 0) {
                    // Last waiter releases the gate so notifier can continue
                    ::SetEvent(gate);
                }
            } else {
                // Single notify: just consumed one ticket from queue
                --m_blocked;
            }
            ::ReleaseMutex(mtx);

            // Re-acquire external lock before returning
            lock.lock();
#else
            ::pthread_cond_wait(&cv_, __boost_mutex_native__(lock));
#endif
        }

        /**
         * Timed wait until absolute deadline `xt` (TIME_UTC). Returns true if notified, false on timeout.
         */
        bool timed_wait(mutex::scoped_lock& lock, const xtime& xt) noexcept {
#if defined(_WIN32)
            // Compute milliseconds until deadline
            xtime now{};
            if (xtime_get(&now, kTimeUtc) != kTimeUtc) return false;
            long long now_ms = 1000LL * static_cast<long long>(now.sec) + now.nsec / 1000000LL;
            long long tgt_ms = 1000LL * static_cast<long long>(xt.sec) + xt.nsec / 1000000LL;
            DWORD timeout = (tgt_ms <= now_ms) ? 0u :
                (static_cast<unsigned long long>(tgt_ms - now_ms) > std::numeric_limits<DWORD>::max()
                    ? std::numeric_limits<DWORD>::max()
                    : static_cast<DWORD>(tgt_ms - now_ms));

            HANDLE gate = reinterpret_cast<HANDLE>(m_gate);
            HANDLE queue = reinterpret_cast<HANDLE>(m_queue);
            HANDLE mtx = reinterpret_cast<HANDLE>(m_mutex);

            // Enter: register as blocked
            ::WaitForSingleObject(mtx, INFINITE);
            ++m_blocked;
            ::ReleaseMutex(mtx);

            // Release external lock and wait with timeout
            lock.unlock();
            DWORD wr = ::WaitForSingleObject(queue, timeout);
            bool signaled = (wr == WAIT_OBJECT_0);

            // Bookkeeping
            ::WaitForSingleObject(mtx, INFINITE);
            if (!signaled) {
                // Timed out: mark as 'gone' (missed ticket) and adjust blocked
                ++m_gone;
                if (m_waiting != 0 && m_waiting == m_blocked) {
                    // If we time out while a broadcast is trying to drain, unblock the notifier
                    ::SetEvent(gate);
                }
                --m_blocked;
                ::ReleaseMutex(mtx);
                lock.lock();
                return false;
            }

            if (m_waiting != 0) {
                // In broadcast: one more waiter left the queue
                if (--m_waiting == 0) {
                    ::SetEvent(gate);
                }
            } else {
                // Single notify
                --m_blocked;
            }
            ::ReleaseMutex(mtx);

            lock.lock();
            return true;
#else
            timespec abs{}; abs.tv_sec = static_cast<time_t>(xt.sec); abs.tv_nsec = static_cast<long>(xt.nsec);
            int r = ::pthread_cond_timedwait(&cv_, __boost_mutex_native__(lock), &abs);
            return r == 0;
#endif
        }

        /**
         * Wake one waiting thread (if any).
         */
        void notify_one() noexcept {
#if defined(_WIN32)
            HANDLE queue = reinterpret_cast<HANDLE>(m_queue);
            HANDLE mtx = reinterpret_cast<HANDLE>(m_mutex);

            ::WaitForSingleObject(mtx, INFINITE);
            unsigned has_waiters = m_blocked - m_gone;
            if (has_waiters != 0) {
                // Consume one blocked and issue one ticket
                if (m_waiting != 0) {
                    // If a broadcast is in progress, it already owns the release path; prefer it
                    ::ReleaseMutex(mtx);
                    return;
                }
                --m_blocked;
                ::ReleaseSemaphore(queue, 1, nullptr);
            }
            ::ReleaseMutex(mtx);
#else
            ::pthread_cond_signal(&cv_);
#endif
        }

        /**
         * Wake all waiting threads (if any).
         */
        void notify_all() noexcept {
#if defined(_WIN32)
            HANDLE gate = reinterpret_cast<HANDLE>(m_gate);
            HANDLE queue = reinterpret_cast<HANDLE>(m_queue);
            HANDLE mtx = reinterpret_cast<HANDLE>(m_mutex);

            ::WaitForSingleObject(mtx, INFINITE);
            unsigned nrelease = m_blocked - m_gone;
            if (nrelease != 0) {
                // Start broadcast: transfer blocked->waiting and release that many tickets
                m_waiting = nrelease;
                m_blocked -= nrelease;
                ::ReleaseSemaphore(queue, static_cast<LONG>(nrelease), nullptr);
                ::ReleaseMutex(mtx);

                // Wait for the last waiter to signal the gate
                ::WaitForSingleObject(gate, INFINITE);
                ::ResetEvent(gate);

                // Cleanup 'gone' accumulation to avoid overflow
                ::WaitForSingleObject(mtx, INFINITE);
                m_gone = 0;
            }
            ::ReleaseMutex(mtx);
#else
            ::pthread_cond_broadcast(&cv_);
#endif
        }

        condition(const condition&) = delete;
        condition& operator=(const condition&) = delete;

    private:
#if defined(_WIN32)
        // Keep legacy 24-byte layout (3 pointers + 3 uints)
        void* m_gate;    // HANDLE (auto-reset event)
        void* m_queue;   // HANDLE (semaphore)
        void* m_mutex;   // HANDLE (mutex protecting counters)
        unsigned  m_gone;    // timeouts / cancellations
        unsigned  m_blocked; // total threads blocked (not yet released)
        unsigned  m_waiting; // threads to drain during broadcast
#else
        pthread_cond_t cv_{};
#endif
    };
#pragma pack(pop)

#if defined(_WIN32)
    static_assert(sizeof(condition) == 0x18, "boost::condition size must be 0x18 bytes on Win32");
#endif
} // namespace boost
