#include "Thread.h"

#include "platform/Platform.h"
using namespace moho;

uint32_t gDefaultThreadId;

void moho::THREAD_InitInvoke() {
    gDefaultThreadId = GetCurrentThreadId();
}

bool moho::THREAD_IsMainThread() {
    return gDefaultThreadId == GetCurrentThreadId();
}

uint32_t moho::THREAD_GetMainThreadId() {
    return gDefaultThreadId;
}

void moho::THREAD_InvokeAsync(const boost::function<void(), std::allocator<void>>& fn, const uint32_t threadId) {
    const DWORD tid = ResolveTid(threadId);
    const HANDLE hThread = ::OpenThread(kThreadAccessFa, FALSE, tid);
    if (!hThread) {
        // Fallback: run inline if thread handle cannot be opened
        try { if (fn) fn(); } catch (...) {}
        return;
    }

    // Allocate pair (8 bytes) and box (32 bytes)
    auto pair = static_cast<void**>(::operator new(8, std::nothrow));
    if (!pair) {
        ::CloseHandle(hThread);
        try { if (fn) fn(); } catch (...) {}
        return;
    }

    void* raw = ::operator new(32, std::nothrow);
    if (!raw) {
        ::operator delete(pair);
        ::CloseHandle(hThread);
        try { if (fn) fn(); } catch (...) {}
        return;
    }

    // Construct payload in-place inside the 32-byte box
    auto* box = ::new (raw) InvokePayload{ fn };

    pair[0] = box;
    pair[1] = nullptr; // async: no waiter

    (void)::QueueUserAPC(&pfnAPC, hThread, reinterpret_cast<ULONG_PTR>(pair));
    ::CloseHandle(hThread);
}

void moho::THREAD_InvokeWait(const boost::function<void(), std::allocator<void>>& fn, const uint32_t threadId) {
    const DWORD tid = ResolveTid(threadId);
    const HANDLE hThread = ::OpenThread(kThreadAccessFa, FALSE, tid);
    if (!hThread) {
        // As in async tail: inline fallback if thread unavailable
        try { if (fn) fn(); } catch (...) {}
        return;
    }

    WaitCtx ctx;
    ctx.begin(2);

    auto pair = static_cast<void**>(::operator new(8, std::nothrow));
    if (!pair) {
        ::CloseHandle(hThread);
        try { if (fn) fn(); } catch (...) {}
        ctx.end();
        return;
    }

    void* raw = ::operator new(32, std::nothrow);
    if (!raw) {
        ::operator delete(pair);
        ::CloseHandle(hThread);
        try { if (fn) fn(); } catch (...) {}
        ctx.end();
        return;
    }

    auto* box = ::new (raw) InvokePayload{ fn };
    pair[0] = box;
    pair[1] = &ctx;

    (void)::QueueUserAPC(&pfnAPC, hThread, reinterpret_cast<ULONG_PTR>(pair));

    // Block current thread until APC signals completion
    ctx.block();
    ::CloseHandle(hThread);
    ctx.end();
}

void moho::THREAD_SetAffinity(const bool preferLowest) noexcept {
    DWORD_PTR procMask = 0;
    DWORD_PTR sysMask = 0;

    // Query process and system affinity masks
    if (!::GetProcessAffinityMask(::GetCurrentProcess(), &procMask, &sysMask)) {
        return; // keep current affinity on failure
    }

    if (procMask == 0) {
        return; // nothing to choose
    }

    constexpr unsigned bitCount = sizeof(procMask) * 8U;
    DWORD_PTR chosen = 0;

    if (preferLowest) {
        // Scan from LSB to MSB
        for (unsigned b = 0; b < bitCount; ++b) {
            const DWORD_PTR bit = (static_cast<DWORD_PTR>(1) << b);
            if (procMask & bit) { chosen = bit; break; }
        }
    } else {
        // Scan from MSB to LSB
        for (int b = static_cast<int>(bitCount) - 1; b >= 0; --b) {
            const DWORD_PTR bit = (static_cast<DWORD_PTR>(1) << b);
            if (procMask & bit) { chosen = bit; break; }
        }
    }

    if (chosen != 0) {
        // Bind current thread to the chosen CPU; return value is previous mask (ignored)
        (void)::SetThreadAffinityMask(::GetCurrentThread(), chosen);
    }
}

void __stdcall moho::pfnAPC(const ULONG_PTR dwData) {
    // pair[0] = box (InvokePayload*), pair[1] = WaitCtx*
    const auto pair = reinterpret_cast<void**>(dwData);
    if (!pair) {
	    return;
    }

    auto* box = static_cast<InvokePayload*>(pair[0]);
    auto* ctx = static_cast<WaitCtx*>(pair[1]);

    if (box) {
        try { if (box->fn) box->fn(); } catch (...) { /* swallow */ }
        // Explicitly call dtor then free the 32-byte box
        box->~InvokePayload();
        ::operator delete(box);
    }

    if (ctx) ctx->signal();

    // Free the 8-byte pair
    ::operator delete(pair);
}

DWORD moho::ResolveTid(const std::uint32_t threadId) noexcept {
    if (threadId) {
        return threadId;
    }
    if (gDefaultThreadId) {
        return gDefaultThreadId;
    }
    return ::GetCurrentThreadId();
}
