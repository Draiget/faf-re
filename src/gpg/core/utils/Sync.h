#pragma once
#include <cstdint>
#include <chrono>
#include <limits>

#include "platform/Platform.h"

namespace gpg::core
{
    /**
     * Cross-platform mutex wrapper compatible with legacy MSVC8-era layout.
     * On Windows uses CRITICAL_SECTION or kernel HANDLE; on POSIX uses pthreads.
     */

    enum class LockKind : uint8_t {
        kKernelWaitable = 0,  // HANDLE on Win32, pthread_mutex_t* on POSIX
        kCriticalSection = 1, // CRITICAL_SECTION* (Win32 only)
    };

    namespace detail {
        constexpr uint8_t kOwnedBit = 0x80;
        constexpr uint8_t kKindMask = 0x01;
    }

#if !defined(_WIN32)
    // Some platforms (older macOS) miss pthread_mutex_timedlock; emulate if needed.
#if defined(__APPLE__) || defined(__MACH__)
#define GPG_NO_PTHREAD_MUTEX_TIMEDLOCK 1
#else
#define GPG_NO_PTHREAD_MUTEX_TIMEDLOCK 0
#endif

/**
 * Convert relative duration to absolute timespec for CLOCK_REALTIME.
 */
    inline timespec gpg_timespec_abs_after(std::chrono::nanoseconds delta) noexcept {
        timespec ts{};
        clock_gettime(CLOCK_REALTIME, &ts);
        // add delta
        auto ns = static_cast<long long>(delta.count());
        ts.tv_sec += ns / 1000000000LL;
        long long nsec = static_cast<long long>(ts.tv_nsec) + (ns % 1000000000LL);
        if (nsec >= 1000000000LL) { ts.tv_sec += 1; nsec -= 1000000000LL; }
        if (nsec < 0) { ts.tv_sec -= 1; nsec += 1000000000LL; }
        ts.tv_nsec = static_cast<long>(nsec);
        return ts;
    }
#endif

#pragma pack(push, 4)
    struct Mutex {
        void* native_ = nullptr; // HANDLE / CRITICAL_SECTION* / pthread_mutex_t*
        uint8_t lockMode_ = 0;       // bit0=kind, bit7=owned (same packed flags)

        /**
         * Query lock kind flag.
         */
        LockKind kind() const noexcept {
            return (static_cast<uint8_t>(lockMode_) & detail::kKindMask)
                ? LockKind::kCriticalSection
                : LockKind::kKernelWaitable;
        }

        /**
         * Query ownership flag.
         */
        bool owned() const noexcept {
            return (static_cast<uint8_t>(lockMode_) & detail::kOwnedBit) != 0;
        }

        /**
         * Set lock kind flag.
         */
        void set_kind(LockKind k) noexcept {
            uint8_t b = static_cast<uint8_t>(lockMode_) & ~detail::kKindMask;
            b |= (k == LockKind::kCriticalSection) ? 1u : 0u;
            lockMode_ = b;
        }

        /**
         * Set ownership flag.
         */
        void set_owned(bool v) noexcept {
            uint8_t b = static_cast<uint8_t>(lockMode_);
            b = v ? (b | detail::kOwnedBit) : (b & ~detail::kOwnedBit);
            lockMode_ = b;
        }

#if defined(_WIN32)
        /**
         * Initialize owned CRITICAL_SECTION.
         */
        void init_critical_section() noexcept {
            destroy();
            auto* cs = new CRITICAL_SECTION{};
            InitializeCriticalSection(cs);
            native_ = cs;
            set_kind(LockKind::kCriticalSection);
            set_owned(true);
        }

        /**
         * Initialize owned kernel mutex HANDLE.
         */
        void init_kernel_mutex(bool initiallyOwned = false, const wchar_t* nameW = nullptr) noexcept {
            destroy();
            const HANDLE h = CreateMutexW(nullptr, initiallyOwned ? TRUE : FALSE, nameW);
            native_ = h;
            set_kind(LockKind::kKernelWaitable);
            set_owned(true);
        }

        /**
         * Attach non-owned external native mutex.
         */
        void attach(void* native, LockKind k) noexcept {
            destroy();
            native_ = native;
            set_kind(k);
            set_owned(false);
        }
#else
        /**
         * Initialize owned portable recursive pthread mutex.
         */
        void init_portable() noexcept {
            destroy();
            auto* pm = new pthread_mutex_t{};
            pthread_mutexattr_t attr{};
            pthread_mutexattr_init(&attr);
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            pthread_mutex_init(pm, &attr);
            pthread_mutexattr_destroy(&attr);
            native_ = pm;
            set_kind(LockKind::kKernelWaitable);
            set_owned(true);
        }

        /**
         * Attach non-owned portable pthread mutex.
         */
        void attach_portable(pthread_mutex_t* m) noexcept {
            destroy();
            native_ = m;
            set_kind(LockKind::kKernelWaitable);
            set_owned(false);
        }
#endif

        /**
         * Release resources if owned().
         */
        void destroy() noexcept {
#if defined(_WIN32)
            if (!native_ || !owned()) { native_ = nullptr; set_owned(false); return; }
            if (kind() == LockKind::kCriticalSection) {
                auto* cs = static_cast<CRITICAL_SECTION*>(native_);
                DeleteCriticalSection(cs);
                delete cs;
            } else {
                CloseHandle(static_cast<HANDLE>(native_));
            }
            native_ = nullptr;
            set_owned(false);
#else
            if (!native_ || !owned()) { native_ = nullptr; set_owned(false); return; }
            auto* pm = static_cast<pthread_mutex_t*>(native_);
            pthread_mutex_destroy(pm);
            delete pm;
            native_ = nullptr;
            set_owned(false);
#endif
        }

        /**
         * Destructor releases owned native handle.
         */
        ~Mutex() { destroy(); }

        /**
         * Blocking lock.
         */
        void lock() const noexcept {
#if defined(_WIN32)
            if (!native_) return;
            if (kind() == LockKind::kCriticalSection) {
                EnterCriticalSection(static_cast<CRITICAL_SECTION*>(native_));
            } else {
                (void)WaitForSingleObject(static_cast<HANDLE>(native_), INFINITE);
            }
#else
            if (!native_) return;
            pthread_mutex_lock(static_cast<pthread_mutex_t*>(native_));
#endif
        }

        /**
         * Non-blocking try_lock.
         */
        [[nodiscard]] bool try_lock() const noexcept {
#if defined(_WIN32)
            if (!native_) return false;
            if (kind() == LockKind::kCriticalSection) {
                return !!TryEnterCriticalSection(static_cast<CRITICAL_SECTION*>(native_));
            }
            const DWORD r = WaitForSingleObject(static_cast<HANDLE>(native_), 0);
            return r == WAIT_OBJECT_0;
#else
            if (!native_) return false;
            return pthread_mutex_trylock(static_cast<pthread_mutex_t*>(native_)) == 0;
#endif
        }

        /**
         * Timed try_lock with platform-specific backend.
         */
        template<class Rep, class Period>
        [[nodiscard]] bool try_lock_for(const std::chrono::duration<Rep, Period>& d) noexcept {
#if defined(_WIN32)
            if (!native_) return false;

            if (kind() == LockKind::kCriticalSection) {
                const auto deadline = std::chrono::steady_clock::now() + d;
                do {
                    if (TryEnterCriticalSection(static_cast<CRITICAL_SECTION*>(native_)))
                        return true;
                    Sleep(0);
                } while (std::chrono::steady_clock::now() < deadline);
                return false;
            }

            using namespace std::chrono;
            DWORD to = 0u;
            if (d > milliseconds::zero()) {
                const unsigned long long ms64 =
                    static_cast<unsigned long long>(duration_cast<milliseconds>(d).count());
                to = (ms64 >= 0xFFFFFFFFull) ? 0xFFFFFFFFu : static_cast<DWORD>(ms64);
            }
            const DWORD r = WaitForSingleObject(static_cast<HANDLE>(native_), to);
            return r == WAIT_OBJECT_0;
#else
            if (!native_) return false;

#if !GPG_NO_PTHREAD_MUTEX_TIMEDLOCK
            if (d <= std::chrono::nanoseconds::zero()) {
                return pthread_mutex_trylock(static_cast<pthread_mutex_t*>(native_)) == 0;
            }
            const timespec abs_ts = gpg_timespec_abs_after(std::chrono::duration_cast<std::chrono::nanoseconds>(d));
            const int rc = pthread_mutex_timedlock(static_cast<pthread_mutex_t*>(native_), &abs_ts);
            return rc == 0;
#else
            const auto deadline = std::chrono::steady_clock::now() + d;
            do {
                if (pthread_mutex_trylock(static_cast<pthread_mutex_t*>(native_)) == 0)
                    return true;
                timespec req{ 0, 1000 * 1000 }; // ~1ms
                nanosleep(&req, nullptr);
            } while (std::chrono::steady_clock::now() < deadline);
            return false;
#endif
#endif
        }

        /**
         * Unlock.
         */
        void unlock() const noexcept {
#if defined(_WIN32)
            if (!native_) return;
            if (kind() == LockKind::kCriticalSection) {
                LeaveCriticalSection(static_cast<CRITICAL_SECTION*>(native_));
            } else {
                (void)ReleaseMutex(static_cast<HANDLE>(native_));
            }
#else
            if (!native_) return;
            pthread_mutex_unlock(static_cast<pthread_mutex_t*>(native_));
#endif
        }
    };
#pragma pack(pop)

    /**
     * Simple RAII guard.
     */
    struct MutexGuard {
        explicit MutexGuard(Mutex& m) noexcept : m_(m) { m_.lock(); }
        ~MutexGuard() { m_.unlock(); }
        MutexGuard(const MutexGuard&) = delete;
        MutexGuard& operator=(const MutexGuard&) = delete;
    private:
        Mutex& m_;
    };

    static_assert(sizeof(Mutex) == 8, "Mutex must be 8 bytes on x86");
#if defined(_WIN64)
    static_assert(sizeof(void*) == 8, "Audit layout for x64 sites.");
#endif

    /**
     * Lightweight fast mutex (no std::mutex).
     */
    struct FastMutex {
#if defined(_WIN32)
        CRITICAL_SECTION cs{};
        FastMutex() { InitializeCriticalSection(&cs); }
        ~FastMutex() { DeleteCriticalSection(&cs); }
        void lock() { EnterCriticalSection(&cs); }
        void unlock() { LeaveCriticalSection(&cs); }
#else
        pthread_mutex_t m{};
        FastMutex() {
            pthread_mutexattr_t a{};
            pthread_mutexattr_init(&a);
            pthread_mutexattr_settype(&a, PTHREAD_MUTEX_NORMAL);
            pthread_mutex_init(&m, &a);
            pthread_mutexattr_destroy(&a);
        }
        ~FastMutex() { pthread_mutex_destroy(&m); }
        void lock() { pthread_mutex_lock(&m); }
        void unlock() { pthread_mutex_unlock(&m); }
#endif
    };

    /**
     * Portable read-write lock without std::shared_mutex.
     */
    struct SharedLock {
#if defined(_WIN32)
        SRWLOCK lock_{ SRWLOCK_INIT };

        void lock_shared()   noexcept { AcquireSRWLockShared(&lock_); }
        void unlock_shared() noexcept { ReleaseSRWLockShared(&lock_); }

        void lock()          noexcept { AcquireSRWLockExclusive(&lock_); }
        void unlock()        noexcept { ReleaseSRWLockExclusive(&lock_); }

        bool try_lock_shared() noexcept { return TryAcquireSRWLockShared(&lock_) != 0; }
        bool try_lock()        noexcept { return TryAcquireSRWLockExclusive(&lock_) != 0; }
#else
        pthread_rwlock_t rw{};

        SharedLock() { pthread_rwlock_init(&rw, nullptr); }
        ~SharedLock() { pthread_rwlock_destroy(&rw); }

        void lock_shared()   noexcept { pthread_rwlock_rdlock(&rw); }
        void unlock_shared() noexcept { pthread_rwlock_unlock(&rw); }

        void lock()          noexcept { pthread_rwlock_wrlock(&rw); }
        void unlock()        noexcept { pthread_rwlock_unlock(&rw); }

        bool try_lock_shared() noexcept { return pthread_rwlock_tryrdlock(&rw) == 0; }
        bool try_lock()        noexcept { return pthread_rwlock_trywrlock(&rw) == 0; }
#endif
    };

    /**
     * C-style helpers preserved for call-site parity.
     */
    inline void func_LockShared(SharedLock* l) { l->lock_shared(); }
    inline void func_UnlockShared(SharedLock* l) { l->unlock_shared(); }
    inline void func_LockExclusive(SharedLock* l) { l->lock(); }
    inline void func_UnlockExclusive(SharedLock* l) { l->unlock(); }

    /**
     * Read-guard RAII.
     */
    struct SharedReadGuard {
        SharedLock& L;
        explicit SharedReadGuard(SharedLock& l) : L(l) { L.lock_shared(); }
        ~SharedReadGuard() { L.unlock_shared(); }
    };

    /**
     * Write-guard RAII.
     */
    struct SharedWriteGuard {
        SharedLock& L;
        explicit SharedWriteGuard(SharedLock& l) : L(l) { L.lock(); }
        ~SharedWriteGuard() { L.unlock(); }
    };
}
