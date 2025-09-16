#pragma once

/**
 * Minimal Boost.Thread 1.34-style mutex:
 * - Stores CRITICAL_SECTION in-place on Windows (ABI: 24 bytes on x86)
 * - No timed locking APIs (those belonged to timed_mutex in 1.34)
 * - Provides nested scoped_lock guard
 * - Non-copyable
 */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <pthread.h>
#  include <errno.h>
#endif

namespace boost
{
    class mutex
	{
    public:
        /**
         * Construct unlocked mutex.
         */
        mutex() noexcept {
#if defined(_WIN32)
            InitializeCriticalSection(&cs_);
#else
            pthread_mutexattr_t attr{};
            pthread_mutexattr_init(&attr);
            // Non-recursive default mutex mirrors boost::mutex semantics.
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
            pthread_mutex_init(&mtx_, &attr);
            pthread_mutexattr_destroy(&attr);
#endif
        }

        /**
         * Destroy mutex. Undefined behavior if still locked by any thread.
         */
        ~mutex() {
#if defined(_WIN32)
            DeleteCriticalSection(&cs_);
#else
            pthread_mutex_destroy(&mtx_);
#endif
        }

        /**
         * Acquire the mutex, blocking until it becomes available.
         */
        void lock() noexcept {
#if defined(_WIN32)
            EnterCriticalSection(&cs_);
#else
            // Block until acquired.
            (void)pthread_mutex_lock(&mtx_);
#endif
        }

        /**
         * Try to acquire the mutex without blocking. Returns true on success.
         */
        bool try_lock() noexcept {
#if defined(_WIN32)
            return !!TryEnterCriticalSection(&cs_);
#else
            const int r = pthread_mutex_trylock(&mtx_);
            return r == 0;
#endif
        }

        /**
         * Release the mutex. Must be held by the current thread.
         */
        void unlock() noexcept {
#if defined(_WIN32)
            LeaveCriticalSection(&cs_);
#else
            (void)pthread_mutex_unlock(&mtx_);
#endif
        }

        /**
         * RAII guard that locks on construction and unlocks on destruction.
         */
        class scoped_lock
    	{
        public:
            /** Lock the given mutex. */
            explicit scoped_lock(mutex& m) noexcept : m_(&m), owns_(false) {
                m_->lock();
                owns_ = true;
            }

            /** Unlock on destruction if still owning. */
            ~scoped_lock() {
                if (owns_) m_->unlock();
            }

            /** Manually unlock early (idempotent). */
            void unlock() noexcept {
                if (owns_) {
                    m_->unlock();
                    owns_ = false;
                }
            }

            /** Manually (re)lock if not owning. */
            void lock() noexcept {
                if (!owns_) {
                    m_->lock();
                    owns_ = true;
                }
            }

            /** Return true if this guard currently owns the mutex. */
            bool locked() const noexcept { return owns_; }

            // Non-copyable (mirrors historical behavior)
            scoped_lock(const scoped_lock&) = delete;
            scoped_lock& operator=(const scoped_lock&) = delete;

        private:
            mutex* m_;
            bool   owns_;
        };

        // Non-copyable (same as historical boost::mutex)
        mutex(const mutex&) = delete;
        mutex& operator=(const mutex&) = delete;

    private:
#if defined(_WIN32)
        // In-place native storage: ABI matches Boost.Thread 1.34 on Win32.
        CRITICAL_SECTION cs_;
#else
        pthread_mutex_t  mtx_;
#endif
    };

} // namespace boost

#if defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
static_assert(sizeof(boost::mutex) == sizeof(CRITICAL_SECTION),
    "boost::mutex must be an in-place CRITICAL_SECTION on Win32 x86");
#endif
