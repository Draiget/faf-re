#pragma once

/* Minimal drop-in replacement for boost::recursive_mutex and scoped_lock
 * Cross-platform (Win32 CRITICAL_SECTION / POSIX pthread recursive mutex)
 * No dependency on <mutex> to avoid mixing with std::mutex in legacy code.
 */

#include <cassert>

#include "platform/Platform.h"

namespace boost
{

    /** Tag type for deferred locking. */
    struct defer_lock_t { explicit defer_lock_t() = default; };
    /** Tag object for deferred locking. */
    inline constexpr defer_lock_t defer_lock{};

    /** Tag type for adopt-lock. */
    struct adopt_lock_t { explicit adopt_lock_t() = default; };
    /** Tag object for adopt-lock. */
    inline constexpr adopt_lock_t adopt_lock{};

    /** Tag type for try-to-lock. */
    struct try_to_lock_t { explicit try_to_lock_t() = default; };
    /** Tag object for try-to-lock. */
    inline constexpr try_to_lock_t try_to_lock{};

    /**
     * Recursive mutex compatible with old Boost.Thread expectations.
     */
    class recursive_mutex {
    public:
        /** Default constructor: initializes native recursive mutex. */
        recursive_mutex() noexcept {
#if defined(_WIN32)
            // InitializeCriticalSectionEx is Vista+; fall back if unavailable.
            // Size is fixed; no spin count tuning here to keep behaviour stable.
            ::InitializeCriticalSection(&cs_);
#else
            pthread_mutexattr_t attr;
            ::pthread_mutexattr_init(&attr);
            ::pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            ::pthread_mutex_init(&mtx_, &attr);
            ::pthread_mutexattr_destroy(&attr);
#endif
        }

        /** Destructor: destroys native mutex. */
        ~recursive_mutex() {
#if defined(_WIN32)
            ::DeleteCriticalSection(&cs_);
#else
            ::pthread_mutex_destroy(&mtx_);
#endif
        }

        recursive_mutex(const recursive_mutex&) = delete;
        recursive_mutex& operator=(const recursive_mutex&) = delete;

        /**
         * Acquire the mutex, blocking until success.
         */
        void lock() noexcept {
#if defined(_WIN32)
            ::EnterCriticalSection(&cs_);
#else
            ::pthread_mutex_lock(&mtx_);
#endif
        }

        /**
         * Try to acquire the mutex without blocking.
         * @returns true if lock was acquired, false otherwise.
         */
        bool try_lock() noexcept {
#if defined(_WIN32)
            return ::TryEnterCriticalSection(&cs_) != 0;
#else
            const int rc = ::pthread_mutex_trylock(&mtx_);
            return rc == 0;
#endif
        }

        /**
         * Release one level of ownership.
         */
        void unlock() noexcept {
#if defined(_WIN32)
            ::LeaveCriticalSection(&cs_);
#else
            ::pthread_mutex_unlock(&mtx_);
#endif
        }

        /**
         * RAII scoped lock compatible with old boost::recursive_mutex::scoped_lock.
         */
        class scoped_lock {
        public:
            /** Construct and lock. */
            explicit scoped_lock(recursive_mutex& m) noexcept
                : m_(&m), owns_(false) {
                m_->lock();
                owns_ = true;
            }

            /** Construct but do not lock (deferred). */
            scoped_lock(recursive_mutex& m, defer_lock_t) noexcept
                : m_(&m), owns_(false) {
            }

            /** Construct and try to lock (non-blocking). */
            scoped_lock(recursive_mutex& m, try_to_lock_t) noexcept
                : m_(&m), owns_(m.try_lock()) {
            }

            /** Construct assuming mutex is already locked by this thread. */
            scoped_lock(recursive_mutex& m, adopt_lock_t) noexcept
                : m_(&m), owns_(true) {
            }

            /** Destructor: unlock if owning. */
            ~scoped_lock() {
                if (owns_ && m_) {
                    m_->unlock();
                }
            }

            scoped_lock(const scoped_lock&) = delete;
            scoped_lock& operator=(const scoped_lock&) = delete;

            /**
             * Lock now (if not already locked).
             */
            void lock() noexcept {
                assert(m_ && "null mutex");
                assert(!owns_ && "lock already owned");
                m_->lock();
                owns_ = true;
            }

            /**
             * Try to lock now (if not already locked).
             * @returns true on success, false otherwise.
             */
            bool try_lock() noexcept {
                assert(m_ && "null mutex");
                assert(!owns_ && "lock already owned");
                owns_ = m_->try_lock();
                return owns_;
            }

            /**
             * Unlock one recursion level.
             */
            void unlock() noexcept {
                assert(m_ && "null mutex");
                assert(owns_ && "unlock without ownership");
                m_->unlock();
                owns_ = false;
            }

            /**
             * Check ownership.
             * @returns true if this guard currently owns the lock.
             */
            [[nodiscard]] bool owns_lock() const noexcept { return owns_; }

            /**
             * Get associated mutex pointer.
             * @returns pointer to the wrapped mutex or nullptr.
             */
            [[nodiscard]] recursive_mutex* mutex() const noexcept { return m_; }

            /**
             * Release ownership without unlocking (rarely needed).
             * @returns mutex pointer and sets internal state to non-owning.
             */
            recursive_mutex* release() noexcept {
                auto* tmp = m_;
                m_ = nullptr;
                owns_ = false;
                return tmp;
            }

        private:
            recursive_mutex* m_;
            bool             owns_;
        };

    private:
#if defined(_WIN32)
        CRITICAL_SECTION cs_{};
#else
        pthread_mutex_t  mtx_{};
#endif
    };

} // namespace boost
