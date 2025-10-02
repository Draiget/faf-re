#pragma once

// Exact-size 8-byte mutex wrapper matching old Boost.Thread behavior on Win32.
// - Stores a pointer to heap-allocated CRITICAL_SECTION (+ optional flag).
// - Default ctor uses CriticalSection (flag = 1).
// - Dtor: if flag==1 -> DeleteCriticalSection + delete; else -> CloseHandle.
// - API: lock(), try_lock(), unlock(), scoped_lock.

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <new>
#else
#  include <pthread.h>
#  include <errno.h>
#endif

namespace boost
{
#pragma pack(push, 1)
    class mutex
    {
    public:
        /** Construct unlocked mutex backed by a CRITICAL_SECTION (flag = 1). */
        mutex() noexcept
            : m_mutex(nullptr)
            , m_critical_section(1)
        {
#if defined(_WIN32)
            // Allocate CS on heap and initialize
            auto* cs = static_cast<LPCRITICAL_SECTION>(operator new(sizeof(CRITICAL_SECTION), std::nothrow));
            if (!cs) { std::terminate(); }
            InitializeCriticalSection(cs);
            m_mutex = cs;
#else
            // POSIX fallback (heap-allocated pthread_mutex_t to keep 8B wrapper semantics)
            auto* pm = static_cast<pthread_mutex_t*>(::operator new(sizeof(pthread_mutex_t), std::nothrow));
            if (!pm) { std::terminate(); }
            pthread_mutexattr_t attr{};
            pthread_mutexattr_init(&attr);
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
            pthread_mutex_init(pm, &attr);
            pthread_mutexattr_destroy(&attr);
            m_mutex = pm;
            m_critical_section = 1; // treat as "cs-like" branch for unified code path
#endif
        }

        /** Destroy the mutex; undefined behavior if still locked. */
        ~mutex() noexcept
        {
#if defined(_WIN32)
            if (m_critical_section) {
                auto* cs = static_cast<LPCRITICAL_SECTION>(m_mutex);
                if (cs) { DeleteCriticalSection(cs); operator delete(cs); }
            } else {
                if (m_mutex) { CloseHandle(static_cast<HANDLE>(m_mutex)); }
            }
            m_mutex = nullptr; m_critical_section = 0;
#else
            auto* pm = static_cast<pthread_mutex_t*>(m_mutex);
            if (pm) { pthread_mutex_destroy(pm); ::operator delete(pm); }
            m_mutex = nullptr; m_critical_section = 0;
#endif
        }

        // Non-copyable
        mutex(const mutex&) = delete;
        mutex& operator=(const mutex&) = delete;

        /** Acquire the mutex, blocking until it becomes available. */
        void lock() noexcept {
#if defined(_WIN32)
            if (m_critical_section) {
                EnterCriticalSection(static_cast<LPCRITICAL_SECTION>(m_mutex));
            } else {
                // Kernel HANDLE branch (not used by default ctor, kept for completeness)
                WaitForSingleObject(static_cast<HANDLE>(m_mutex), INFINITE);
            }
#else
            (void)pthread_mutex_lock(static_cast<pthread_mutex_t*>(m_mutex));
#endif
        }

        /** Try to acquire the mutex without blocking. Returns true on success. */
        bool try_lock() noexcept {
#if defined(_WIN32)
            if (m_critical_section) {
                return !!TryEnterCriticalSection(static_cast<LPCRITICAL_SECTION>(m_mutex));
            } else {
                DWORD r = WaitForSingleObject(static_cast<HANDLE>(m_mutex), 0);
                return r == WAIT_OBJECT_0;
            }
#else
            const int r = pthread_mutex_trylock(static_cast<pthread_mutex_t*>(m_mutex));
            return r == 0;
#endif
        }

        /** Release the mutex. Must be held by the current thread. */
        void unlock() noexcept {
#if defined(_WIN32)
            if (m_critical_section) {
                LeaveCriticalSection(static_cast<LPCRITICAL_SECTION>(m_mutex));
            } else {
                ReleaseMutex(static_cast<HANDLE>(m_mutex));
            }
#else
            (void)pthread_mutex_unlock(static_cast<pthread_mutex_t*>(m_mutex));
#endif
        }

        /** RAII guard that locks on construction and unlocks on destruction. */
        class scoped_lock
        {
        public:
            explicit scoped_lock(mutex& m) noexcept : m_(&m), owns_(false) { m_->lock(); owns_ = true; }
            ~scoped_lock() { if (owns_) m_->unlock(); }
            void unlock() noexcept { if (owns_) { m_->unlock(); owns_ = false; } }
            void lock()   noexcept { if (!owns_) { m_->lock(); owns_ = true; } }
            bool locked() const noexcept { return owns_; }
            scoped_lock(const scoped_lock&) = delete;
            scoped_lock& operator=(const scoped_lock&) = delete;
        private:
            mutex* m_;
            bool   owns_;
        };

        /** Create a kernel mutex (HANDLE) instead of CS, to match dtor's else branch */
        struct use_kernel_handle_t { explicit use_kernel_handle_t() = default; };
        static constexpr use_kernel_handle_t use_kernel_handle{};

        /** Construct mutex as a kernel HANDLE (CloseHandle in dtor). */
        explicit mutex(use_kernel_handle_t) noexcept
            : m_mutex(nullptr)
            , m_critical_section(0)
        {
#if defined(_WIN32)
            HANDLE h = CreateMutexA(nullptr, FALSE, nullptr);
            m_mutex = h;
#else
            // POSIX: fallback to default ctor semantics
            new (this) mutex();
#endif
        }

    private:
        // Layout must match: pointer + int == 8 bytes on Win32 x86.
        void* m_mutex;           // CRITICAL_SECTION* or HANDLE
        bool  m_critical_section; // 1 = CRITICAL_SECTION branch; 0 = HANDLE branch
    };
#pragma pack(pop)

#if defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
    static_assert(sizeof(mutex) == 5, "boost::mutex size must be 5 bytes");
#endif
} // namespace boost

