// boost/thread.hpp — minimal Win32-only stub for legacy Boost 1.33–1.34 era
// x86 / MSVC8 ABI-minded, without pulling the whole Boost.
//
// Tunable ABI:
//   Define BOOST_THREAD_SIZE_WORDS to force the class size in pointer-words.
//   Default = 2 (two void* fields = 8 bytes on x86).
//
//   static_assert is guarded for pre-C++11 compilers (MSVC8).
//
// Supported subset:
//   - boost::thread(F)        // start callable F by _beginthreadex
//   - ~thread()               // detach if still joinable
//   - joinable(), join(), detach()
//   - get_id(), native_handle()
//   - hardware_concurrency(), yield(), sleep(ms)
//   - move-only semantics (when available)
//
// Not supported (intentionally omitted):
//   - interruption points, futures/promises, attributes, scheduling policy,
//     TLS cleanup hooks, cooperative cancellation, etc.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <process.h>   // _beginthreadex
#include <cstddef>
#include <cstdint>

#ifndef BOOST_THREAD_SIZE_WORDS
#  define BOOST_THREAD_SIZE_WORDS 2
#endif

namespace boost {

    class thread {
    public:
        // Very small 'id' compatible with old style comparisons/printing.
        struct id {
            unsigned long value; // DWORD thread id
            bool operator==(id rhs) const { return value == rhs.value; }
            bool operator!=(id rhs) const { return value != rhs.value; }
            bool operator< (id rhs) const { return value < rhs.value; }
            explicit operator bool() const { return value != 0; }
        };

        using native_handle_type = HANDLE;

    private:
#pragma pack(push, 4)
        // Layout: keep the first two fields as raw pointers to better match
        // MSVC8-era ABI expectations (two words total by default).
        void* handle_;   // actually HANDLE, stored as void* for ABI stability
        void* tidbox_;   // stores thread id as uintptr_t, or reserved
#if BOOST_THREAD_SIZE_WORDS > 2
        // Optional padding to reach requested ABI size.
        char   _abi_pad_[(BOOST_THREAD_SIZE_WORDS - 2) * sizeof(void*)];
#endif
#pragma pack(pop)

        // Non-copyable
        thread(const thread&);
        thread& operator=(const thread&);

        // Internal callable wrapper with manual vtable to avoid <functional>.
        struct callable_base {
            virtual ~callable_base() {}
            virtual void run() = 0;
        };

        template<class F>
        struct callable_impl : callable_base {
            F f_;
            explicit callable_impl(F const& f) : f_(f) {}
            explicit callable_impl(F&& f) : f_(static_cast<F&&>(f)) {}
            void run() { f_(); }
        };

        // Thread entry thunk: takes ownership of callable_base*.
        static unsigned __stdcall entry_(void* p) {
            callable_base* c = static_cast<callable_base*>(p);
            // Do not let exceptions escape the thread boundary.
            __try {
                if (c) c->run();
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // swallow to mimic old Boost behavior (no terminate propagation)
            }
            delete c;
            return 0u;
        }

        static unsigned long current_tid_legacy_() {
            // GetCurrentThreadId exists since WinNT4; safe for XP/2003/Vista.
            return ::GetCurrentThreadId();
        }

    public:
        // Default: not-a-thread
        thread() : handle_(0), tidbox_(0)
#if BOOST_THREAD_SIZE_WORDS > 2
            , _abi_pad_{}
#endif
        {
        }

        // Move support (available on newer compilers; harmless on MSVC8 if elided)
        thread(thread&& other)
            : handle_(other.handle_), tidbox_(other.tidbox_)
#if BOOST_THREAD_SIZE_WORDS > 2
            , _abi_pad_{}
#endif
        {
            other.handle_ = 0; other.tidbox_ = 0;
        }

        thread& operator=(thread&& other) {
            if (this != &other) {
                if (joinable()) detach();
                handle_ = other.handle_;
                tidbox_ = other.tidbox_;
                other.handle_ = 0; other.tidbox_ = 0;
            }
            return *this;
        }

        // Start a new thread with a generic callable (no args, returns void).
        // We avoid <functional> to keep the footprint tiny.
        template<class F>
        explicit thread(F&& f) : handle_(0), tidbox_(0)
#if BOOST_THREAD_SIZE_WORDS > 2
            , _abi_pad_{}
#endif
        {
            // Allocate callable wrapper on heap; ownership passed to entry_.
            callable_base* payload = 0;
            try {
                payload = new callable_impl<typename std::remove_reference<F>::type>(static_cast<F&&>(f));
            } catch (...) {
                payload = 0;
            }
            if (!payload) {
                // Creation failed
                return;
            }

            unsigned thread_id = 0;
            uintptr_t h = _beginthreadex(
                /*security=*/nullptr,
                /*stack_size=*/0,
                &thread::entry_,
                /*arg=*/payload,
                /*initflag=*/0,
                &thread_id);

            if (h == 0) {
                // Failed to start; free payload to avoid leak.
                delete payload;
                return;
            }

            handle_ = reinterpret_cast<void*>(static_cast<HANDLE>(reinterpret_cast<void*>(h)));
            // Store TID in the second word to keep the total size == 2 pointers.
            tidbox_ = reinterpret_cast<void*>(static_cast<uintptr_t>(thread_id));
        }

        ~thread() {
            // Old Boost would std::terminate on joinable(); we are gentle: detach.
            if (joinable()) detach();
        }

        bool joinable() const {
            return handle_ != 0;
        }

        void join() {
            if (!joinable()) return;
            HANDLE h = static_cast<HANDLE>(handle_);
            ::WaitForSingleObject(h, INFINITE);
            ::CloseHandle(h);
            handle_ = 0;
            tidbox_ = 0;
        }

        void detach() {
            if (!joinable()) return;
            ::CloseHandle(static_cast<HANDLE>(handle_));
            handle_ = 0;
            tidbox_ = 0;
        }

        void swap(thread& other) {
            void* h = handle_;   handle_ = other.handle_;   other.handle_ = h;
            void* t = tidbox_;   tidbox_ = other.tidbox_;   other.tidbox_ = t;
        }

        id get_id() const {
            id r; r.value = static_cast<unsigned long>(reinterpret_cast<uintptr_t>(tidbox_));
            return r;
        }

        native_handle_type native_handle() const {
            return static_cast<HANDLE>(handle_);
        }

        // Static helpers
        static unsigned hardware_concurrency() {
            SYSTEM_INFO si{};
            ::GetSystemInfo(&si);
            return si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1u;
        }

        static void yield() {
            // SwitchToThread may fail; Sleep(0) is a common fallback.
            if (!::SwitchToThread()) ::Sleep(0);
        }

        static void sleep(unsigned milliseconds) {
            ::Sleep(milliseconds);
        }
    };

    // Free swap
    inline void swap(thread& a, thread& b) { a.swap(b); }

    // this_thread subset
    namespace this_thread {
        inline thread::id get_id() {
            thread::id r;
            r.value = ::GetCurrentThreadId();
            return r;
        }
        inline void yield() { thread::yield(); }
        inline void sleep_for(unsigned ms) { thread::sleep(ms); }
        inline void sleep_until(unsigned /*ms_since_epoch*/) {
            // Minimal stub: not implemented; keep to satisfy old call sites if any.
            // You can convert absolute to relative and call sleep_for.
        }
    } // namespace this_thread

} // namespace boost

// Optional compile-time ABI check (C++11+).
#if !defined(_MSC_VER) || (_MSC_VER >= 1600) /* VS2010+ has static_assert */
static_assert(sizeof(boost::thread) == BOOST_THREAD_SIZE_WORDS * sizeof(void*),
    "boost::thread ABI size mismatch: adjust BOOST_THREAD_SIZE_WORDS");
#endif
