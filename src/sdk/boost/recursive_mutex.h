#pragma once

// Legacy-size boost::recursive_mutex shim.
// Important for SDK ABI/layout recovery: this wrapper must stay compact on x86.

#include <cassert>
#include <cstdint>
#include <exception>
#include <new>

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
     * Recursive mutex compatible with old Boost.Thread calling style and
     * compact legacy layout requirements.
     */
    class recursive_mutex
    {
    public:
        recursive_mutex() noexcept
            : m_mutex(nullptr)
            , m_critical_section(true)
            , m_pad0(0)
            , m_pad1(0)
            , m_pad2(0)
        {
#if defined(_WIN32)
            auto* cs = static_cast<LPCRITICAL_SECTION>(::operator new(sizeof(CRITICAL_SECTION), std::nothrow));
            if (!cs) {
                std::terminate();
            }
            ::InitializeCriticalSection(cs);
            m_mutex = cs;
#else
            auto* pm = static_cast<pthread_mutex_t*>(::operator new(sizeof(pthread_mutex_t), std::nothrow));
            if (!pm) {
                std::terminate();
            }
            pthread_mutexattr_t attr{};
            ::pthread_mutexattr_init(&attr);
            ::pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            ::pthread_mutex_init(pm, &attr);
            ::pthread_mutexattr_destroy(&attr);
            m_mutex = pm;
#endif
        }

        ~recursive_mutex()
        {
#if defined(_WIN32)
            if (m_critical_section) {
                auto* cs = static_cast<LPCRITICAL_SECTION>(m_mutex);
                if (cs) {
                    ::DeleteCriticalSection(cs);
                    ::operator delete(cs);
                }
            } else if (m_mutex) {
                ::CloseHandle(static_cast<HANDLE>(m_mutex));
            }
#else
            auto* pm = static_cast<pthread_mutex_t*>(m_mutex);
            if (pm) {
                ::pthread_mutex_destroy(pm);
                ::operator delete(pm);
            }
#endif
            m_mutex = nullptr;
            m_critical_section = false;
            m_pad0 = 0;
            m_pad1 = 0;
            m_pad2 = 0;
        }

        recursive_mutex(const recursive_mutex&) = delete;
        recursive_mutex& operator=(const recursive_mutex&) = delete;

        void lock() noexcept
        {
#if defined(_WIN32)
            if (m_critical_section) {
                ::EnterCriticalSection(static_cast<LPCRITICAL_SECTION>(m_mutex));
            } else {
                ::WaitForSingleObject(static_cast<HANDLE>(m_mutex), INFINITE);
            }
#else
            ::pthread_mutex_lock(static_cast<pthread_mutex_t*>(m_mutex));
#endif
        }

        bool try_lock() noexcept
        {
#if defined(_WIN32)
            if (m_critical_section) {
                return ::TryEnterCriticalSection(static_cast<LPCRITICAL_SECTION>(m_mutex)) != 0;
            }
            const DWORD result = ::WaitForSingleObject(static_cast<HANDLE>(m_mutex), 0);
            return result == WAIT_OBJECT_0;
#else
            const int result = ::pthread_mutex_trylock(static_cast<pthread_mutex_t*>(m_mutex));
            return result == 0;
#endif
        }

        void unlock() noexcept
        {
#if defined(_WIN32)
            if (m_critical_section) {
                ::LeaveCriticalSection(static_cast<LPCRITICAL_SECTION>(m_mutex));
            } else {
                ::ReleaseMutex(static_cast<HANDLE>(m_mutex));
            }
#else
            ::pthread_mutex_unlock(static_cast<pthread_mutex_t*>(m_mutex));
#endif
        }

        /**
         * RAII scoped lock compatible with boost::recursive_mutex::scoped_lock.
         */
        class scoped_lock
        {
        public:
            explicit scoped_lock(recursive_mutex& m) noexcept
                : m_(&m)
                , owns_(false)
            {
                m_->lock();
                owns_ = true;
            }

            scoped_lock(recursive_mutex& m, defer_lock_t) noexcept
                : m_(&m)
                , owns_(false)
            {}

            scoped_lock(recursive_mutex& m, try_to_lock_t) noexcept
                : m_(&m)
                , owns_(m.try_lock())
            {}

            scoped_lock(recursive_mutex& m, adopt_lock_t) noexcept
                : m_(&m)
                , owns_(true)
            {}

            ~scoped_lock()
            {
                if (owns_ && m_) {
                    m_->unlock();
                }
            }

            scoped_lock(const scoped_lock&) = delete;
            scoped_lock& operator=(const scoped_lock&) = delete;

            void lock() noexcept
            {
                assert(m_ && "null mutex");
                assert(!owns_ && "lock already owned");
                m_->lock();
                owns_ = true;
            }

            bool try_lock() noexcept
            {
                assert(m_ && "null mutex");
                assert(!owns_ && "lock already owned");
                owns_ = m_->try_lock();
                return owns_;
            }

            void unlock() noexcept
            {
                assert(m_ && "null mutex");
                assert(owns_ && "unlock without ownership");
                m_->unlock();
                owns_ = false;
            }

            [[nodiscard]] bool owns_lock() const noexcept { return owns_; }
            [[nodiscard]] recursive_mutex* mutex() const noexcept { return m_; }

            recursive_mutex* release() noexcept
            {
                auto* tmp = m_;
                m_ = nullptr;
                owns_ = false;
                return tmp;
            }

        private:
            recursive_mutex* m_;
            bool owns_;
        };

        /**
         * Construct as kernel mutex handle (rare legacy branch).
         */
        struct use_kernel_handle_t
        {
            explicit use_kernel_handle_t() = default;
        };

        static constexpr use_kernel_handle_t use_kernel_handle{};

        explicit recursive_mutex(use_kernel_handle_t) noexcept
            : m_mutex(nullptr)
            , m_critical_section(false)
            , m_pad0(0)
            , m_pad1(0)
            , m_pad2(0)
        {
#if defined(_WIN32)
            m_mutex = ::CreateMutexA(nullptr, FALSE, nullptr);
#else
            new (this) recursive_mutex();
#endif
        }

    private:
        // 8-byte legacy wrapper on x86: pointer + flag + padding.
        void* m_mutex;
        bool m_critical_section;
        std::uint8_t m_pad0;
        std::uint8_t m_pad1;
        std::uint8_t m_pad2;
    };

#if defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
    static_assert(sizeof(recursive_mutex) == 0x8, "boost::recursive_mutex size must be 0x8 on Win32 x86");
#endif
} // namespace boost
