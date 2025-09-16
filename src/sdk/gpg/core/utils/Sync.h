// gpg/core/mutex.h
#pragma once
#include <cstdint>
#include <chrono>

#include "platform/Platform.h"

namespace gpg::core
{
    /**
     *  // Initialization (в своём коде/SDK):
	 *  #if defined(_WIN32)
	 *  statItem.sync.init_critical_section();
	 *  // or:
	 *  // statItem.sync.init_kernel_mutex();
	 *  #else
	 *  statItem.sync.init_portable();
	 *  #endif
     *  
	 *  {
	 *      gpg::core::MutexGuard guard(statItem.sync);
	 *      // ... something ...
	 *  } // unlock() will be called automatically
     *  
	 *  // If external object:
	 *  #if defined(_WIN32)
	 *  statItem.sync.attach(externalCS, gpg::core::LockKind::CriticalSection);
	 *	#endif
     */

    // One byte mode with an ownership flag packed in.
    enum class LockKind : uint8_t {
        kKernelWaitable = 0,  // expects HANDLE (ReleaseMutex on unlock)
        kCriticalSection = 1, // expects CRITICAL_SECTION*
    };

    // Bits inside `lockMode_`: lower bit -> kind, top bit -> owned
    namespace detail {
        constexpr uint8_t kOwnedBit = 0x80;
        constexpr uint8_t kKindMask = 0x01;
    }

    // A compact, in-place mutex wrapper matching the game's layout.
    // Size (x86): 8 bytes total -> [void* 4B][uint8_t 1B][pad 3B]
#pragma pack(push, 4)
    struct Mutex {
        // ---- Binary layout (must match game fields) ----
        void* native_;     // 0x00: HANDLE or CRITICAL_SECTION*
        uint8_t lockMode_;   // 0x04: bit0=kind, bit7=owned ; 0x05..0x07: implicit padding

        // ---- Helpers: accessors for packed bits ----
        // NOTE: These helpers do not change the physical layout.
        LockKind kind() const noexcept {
            return (static_cast<uint8_t>(lockMode_) & detail::kKindMask)
                ? LockKind::kCriticalSection
                : LockKind::kKernelWaitable;
        }
        bool owned() const noexcept {
            return (static_cast<uint8_t>(lockMode_) & detail::kOwnedBit) != 0;
        }
        void set_kind(LockKind k) noexcept {
            uint8_t b = static_cast<uint8_t>(lockMode_) & ~detail::kKindMask;
            b |= (k == LockKind::kCriticalSection) ? 1u : 0u;
            lockMode_ = b;
        }
        void set_owned(bool v) noexcept {
            uint8_t b = static_cast<uint8_t>(lockMode_);
            b = v ? (b | detail::kOwnedBit) : (b & ~detail::kOwnedBit);
            lockMode_ = b;
        }

        // ---- Construction shortcuts ----
#if defined(_WIN32)
		// Initialize as CRITICAL_SECTION (owned; will be deleted by destroy()).
        void init_critical_section() noexcept {
            destroy(); // in case it was already set and owned
            auto* cs = new CRITICAL_SECTION{};
            InitializeCriticalSection(cs);
            native_ = cs;
            set_kind(LockKind::kCriticalSection);
            set_owned(true);
        }

        // Initialize as kernel mutex HANDLE (owned).
        // nameW may be nullptr; initially_owned=false by default.
        void init_kernel_mutex(const bool initiallyOwned = false, const wchar_t* nameW = nullptr) noexcept {
            destroy(); // in case it was already set and owned
            const HANDLE h = CreateMutexW(nullptr, initiallyOwned ? TRUE : FALSE, nameW);
            native_ = h;
            set_kind(LockKind::kKernelWaitable);
            set_owned(true);
        }

        // Attach to an external object (non-owning). You must pass the correct kind.
        void attach(void* native, LockKind k) noexcept {
            destroy(); // release previous if owned
            native_ = native;
            set_kind(k);
            set_owned(false);
        }
#else
    // Portable fallback: store std::timed_mutex* in native_, treat as "kernel" kind.
        void init_portable() noexcept {
            destroy();
            native_ = new std::timed_mutex();
            set_kind(LockKind::KernelWaitable);
            set_owned(true);
        }
        void attach_portable(std::timed_mutex* m) noexcept {
            destroy();
            native_ = m;
            set_kind(LockKind::KernelWaitable);
            set_owned(false);
        }
#endif

        // ---- Destruction ----
        // Frees resources only if `owned()==true`.
        void destroy() noexcept {
#if defined(_WIN32)
            if (!native_ || !owned()) { native_ = nullptr; set_owned(false); return; }
            if (kind() == LockKind::kCriticalSection) {
                auto* cs = reinterpret_cast<CRITICAL_SECTION*>(native_);
                DeleteCriticalSection(cs);
                delete cs;
            } else {
                CloseHandle(reinterpret_cast<HANDLE>(native_));
            }
            native_ = nullptr;
            set_owned(false);
#else
            if (!native_ || !owned()) { native_ = nullptr; set_owned(false); return; }
            delete reinterpret_cast<std::timed_mutex*>(native_);
            native_ = nullptr;
            set_owned(false);
#endif
        }

        // ---- Locking API ----
        void lock() const noexcept {
#if defined(_WIN32)
            if (!native_) return;
            if (kind() == LockKind::kCriticalSection) {
                EnterCriticalSection(static_cast<CRITICAL_SECTION*>(native_));
            } else {
                (void)WaitForSingleObject(reinterpret_cast<HANDLE>(native_), INFINITE);
            }
#else
            if (!native_) return;
            reinterpret_cast<std::timed_mutex*>(native_)->lock();
#endif
        }

        [[nodiscard]] bool try_lock() const noexcept {
#if defined(_WIN32)
            if (!native_) return false;
            if (kind() == LockKind::kCriticalSection) {
                return !!TryEnterCriticalSection(static_cast<CRITICAL_SECTION*>(native_));
            } else {
	            const DWORD r = WaitForSingleObject(reinterpret_cast<HANDLE>(native_), 0);
                return r == WAIT_OBJECT_0;
            }
#else
            if (!native_) return false;
            return reinterpret_cast<std::timed_mutex*>(native_)->try_lock();
#endif
        }

        template<class Rep, class Period>
        [[nodiscard]] bool try_lock_for(const std::chrono::duration<Rep, Period>& d) noexcept {
#if defined(_WIN32)
            if (!native_) return false;
            if (kind() == LockKind::kCriticalSection) {
                // No native timed wait for CS: emulate with TryEnter + Sleep(0)
                const auto deadline = std::chrono::steady_clock::now() + d;
                do {
                    if (TryEnterCriticalSection(static_cast<CRITICAL_SECTION*>(native_)))
                        return true;
                    Sleep(0);
                } while (std::chrono::steady_clock::now() < deadline);
                return false;
            } else {
                using namespace std::chrono;
                const auto ms = duration_cast<milliseconds>(d).count();
                const DWORD to = ms < 0 ? 0u
	                                 : ms > static_cast<long long>(std::numeric_limits<DWORD>::max())
	                                 ? std::numeric_limits<DWORD>::max()
	                                 : static_cast<DWORD>(ms);
                const DWORD r = WaitForSingleObject(reinterpret_cast<HANDLE>(native_), to);
                return r == WAIT_OBJECT_0;
            }
#else
            if (!native_) return false;
            return reinterpret_cast<std::timed_mutex*>(native_)->try_lock_for(d);
#endif
        }

        void unlock() const noexcept {
#if defined(_WIN32)
            if (!native_) return;
            if (kind() == LockKind::kCriticalSection) {
                LeaveCriticalSection(static_cast<CRITICAL_SECTION*>(native_));
            } else {
                // Assuming HANDLE is a mutex. If you discover Event/Semaphore in some site,
                // adjust this branch accordingly.
                (void)ReleaseMutex(reinterpret_cast<HANDLE>(native_));
            }
#else
            if (!native_) return;
            reinterpret_cast<std::timed_mutex*>(native_)->unlock();
#endif
        }
    };
#pragma pack(pop)

    // RAII guard (like std::lock_guard).
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
    static_assert(sizeof(void*) == 8, "This wrapper is meant for x86 game layout; audit for x64.");
#endif

    struct FastMutex {
#if defined(_WIN32)
        // CRITICAL_SECTION layout is opaque; 24 bytes on x86.
        CRITICAL_SECTION cs{};
        FastMutex() { InitializeCriticalSection(&cs); }
        ~FastMutex() { DeleteCriticalSection(&cs); }
        void lock() { EnterCriticalSection(&cs); }
        void unlock() { LeaveCriticalSection(&cs); }
#else
        std::mutex m;
        void lock() { m.lock(); }
        void unlock() { m.unlock(); }
#endif
    };

    /**
     * Portable RW lock with Windows SRWLOCK or std::shared_mutex fallback.
     * API mirrors typical read/write lock usage.
     */
    struct SharedLock {
#if defined(_WIN32)
        // SRWLOCK is a slim, non-reentrant read-write lock on Windows Vista+
        SRWLOCK lock_{ SRWLOCK_INIT };

        void lock_shared()   noexcept { AcquireSRWLockShared(&lock_); }
        void unlock_shared() noexcept { ReleaseSRWLockShared(&lock_); }

        void lock()          noexcept { AcquireSRWLockExclusive(&lock_); }
        void unlock()        noexcept { ReleaseSRWLockExclusive(&lock_); }

        bool try_lock_shared() noexcept { return TryAcquireSRWLockShared(&lock_) != 0; }
        bool try_lock()        noexcept { return TryAcquireSRWLockExclusive(&lock_) != 0; }

#else
        // Fallback to standard shared_mutex
        std::shared_mutex mtx;

        void lock_shared()   noexcept { mtx.lock_shared(); }
        void unlock_shared() noexcept { mtx.unlock_shared(); }

        void lock()          noexcept { mtx.lock(); }
        void unlock()        noexcept { mtx.unlock(); }

        bool try_lock_shared() noexcept { return mtx.try_lock_shared(); }
        bool try_lock()        noexcept { return mtx.try_lock(); }
#endif
    };

    /**
     * C-style helpers to match original call sites seen in disassembly.
     */
    inline void func_LockShared(SharedLock* l) { l->lock_shared(); }
    inline void func_UnlockShared(SharedLock* l) { l->unlock_shared(); }
    inline void func_LockExclusive(SharedLock* l) { l->lock(); }
    inline void func_UnlockExclusive(SharedLock* l) { l->unlock(); }

    /**
     * RAII guards for convenience.
     */
    struct SharedReadGuard {
        SharedLock& L;
        explicit SharedReadGuard(SharedLock& l) : L(l) { L.lock_shared(); }
        ~SharedReadGuard() { L.unlock_shared(); }
    };

    struct SharedWriteGuard {
        SharedLock& L;
        explicit SharedWriteGuard(SharedLock& l) : L(l) { L.lock(); }
        ~SharedWriteGuard() { L.unlock(); }
    };
}
