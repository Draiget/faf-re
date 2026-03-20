#include "Logging.h"

#include <algorithm>
#include <cstdarg>
#include <vector>

#include "gpg/core/containers/String.h"
using namespace gpg;

namespace
{
constexpr std::size_t kInitialContextCapacity = 4;

void EnsureThreadContextCapacity(gpg::ThreadState* const tls, const std::size_t wantedCount)
{
    if (!tls) {
        return;
    }

    const std::size_t currentCount = (tls->begin && tls->end)
                                         ? static_cast<std::size_t>(tls->end - tls->begin)
                                         : 0;
    const std::size_t currentCapacity = (tls->begin && tls->cap)
                                            ? static_cast<std::size_t>(tls->cap - tls->begin)
                                            : 0;
    if (currentCapacity >= wantedCount) {
        return;
    }

    std::size_t newCapacity = currentCapacity ? currentCapacity : kInitialContextCapacity;
    while (newCapacity < wantedCount) {
        newCapacity *= 2;
    }

    auto** const newBuffer = new gpg::ThreadCtxEntry*[newCapacity]{};
    if (tls->begin && currentCount > 0) {
        std::copy(tls->begin, tls->begin + currentCount, newBuffer);
        delete[] tls->begin;
    }

    tls->begin = newBuffer;
    tls->end = newBuffer + currentCount;
    tls->cap = newBuffer + newCapacity;
}

gpg::ThreadState* EnsureThreadState()
{
    std::call_once(gpg::g_LogOnce, &gpg::InitLogSingleton);
    if (!gpg::g_LogCtx) {
        return nullptr;
    }

    gpg::ThreadState* tls = gpg::g_LogCtx->tss.get();
    if (!tls) {
        tls = new gpg::ThreadState{};
        gpg::g_LogCtx->tss.reset(tls);
    }
    return tls;
}

void PushThreadContext(gpg::ThreadState* const tls, gpg::ThreadCtxEntry* const entry)
{
    if (!tls || !entry) {
        return;
    }

    const std::size_t count = (tls->begin && tls->end)
                                  ? static_cast<std::size_t>(tls->end - tls->begin)
                                  : 0;
    EnsureThreadContextCapacity(tls, count + 1);
    tls->begin[count] = entry;
    tls->end = tls->begin + count + 1;
}

void RemoveThreadContext(gpg::ThreadState* const tls, gpg::ThreadCtxEntry* const entry)
{
    if (!tls || !entry || !tls->begin || tls->end == tls->begin) {
        return;
    }

    gpg::ThreadCtxEntry** const found = std::find(tls->begin, tls->end, entry);
    if (found == tls->end) {
        return;
    }

    std::move(found + 1, tls->end, found);
    --tls->end;
    *tls->end = nullptr;
}
} // namespace

void LogContext::Dispatch(const int level, const msvc8::string& msg) {
    // Shared traversal over targets
    rw.lock_shared();
    // Snapshot thread context
    ThreadState* tls = tss.get();
    std::vector<msvc8::string> snapshot;
    int prevDepth = 0;

    if (tls) {
        const std::size_t count =
            (tls->begin && tls->end) ? static_cast<std::size_t>(tls->end - tls->begin) : 0;

        snapshot.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            // Each entry has string at +4 (we model it as .text)
            snapshot.emplace_back(tls->begin[i]->text);
        }

        prevDepth = static_cast<int>(tls->depthCache);
        tls->depthCache = static_cast<std::uint32_t>(count);

        if (tls != lastTls) {
            // If thread changed, force prevDepth=0 and update cache
            prevDepth = 0;
            lastTls = tls;
        }
    }

    // Iterate intrusive list
    for (LogTargetNode* n = head.next; n != &head; ) {
        LogTargetNode* cur = n;
        n = n->next; // prefetch next in case of removal

        if (cur->busy) continue;
        cur->busy = 1;

        const int sendPrev = cur->flushOnce ? 0 : prevDepth;
        cur->flushOnce = 0;

        if (cur->obj) {
            cur->obj->OnLog(level, msg,
                std::span<const msvc8::string>(snapshot.data(), snapshot.size()),
                sendPrev);
        }

        cur->busy = 0;

        if (cur->pendingRemove) {
            // unlink
            cur->prev->next = cur->next;
            cur->next->prev = cur->prev;
            cur->prev = cur->next = cur;
            // lifetime of node is managed elsewhere (e.g., ~LogTarget)
        }
    }

    rw.unlock_shared();
}

ScopedLogContext::ScopedLogContext(const msvc8::string& text)
{
    mTls = EnsureThreadState();
    if (!mTls) {
        return;
    }

    mEntry = new ThreadCtxEntry{};
    mEntry->text = text;
    PushThreadContext(mTls, mEntry);
}

ScopedLogContext::ScopedLogContext(const char* const text)
    : ScopedLogContext(msvc8::string(text ? text : ""))
{
}

ScopedLogContext::~ScopedLogContext()
{
    if (!mEntry) {
        return;
    }

    if (mTls) {
        RemoveThreadContext(mTls, mEntry);
    }
    delete mEntry;
    mEntry = nullptr;
    mTls = nullptr;
}

// 0x00937CB0
// ReSharper disable once IdentifierTypo
void gpg::Logf(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);

    std::call_once(g_LogOnce, &InitLogSingleton);

    if (g_LogCtx) {
        g_LogCtx->Dispatch(kInfo, msg);
    }
}

// 0x00937D30
// ReSharper disable once IdentifierTypo
void gpg::Warnf(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);

    std::call_once(g_LogOnce, &InitLogSingleton);

    if (g_LogCtx) {
        g_LogCtx->Dispatch(kWarn, msg);
    }
}

// 0x00937C30
// ReSharper disable once IdentifierTypo
void gpg::Debugf(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);

    std::call_once(g_LogOnce, &InitLogSingleton);

    if (g_LogCtx) {
        g_LogCtx->Dispatch(kWarn, msg);
    }
}

FILETIME gpg::FileTimeLocal() {
    FILETIME ftUtc{}, ftLocal{};
    GetSystemTimeAsFileTime(&ftUtc);
    FileTimeToLocalFileTime(&ftUtc, &ftLocal);
    return ftLocal;
}

msvc8::string gpg::FileTimeToString(const LONGLONG time) {
    // Convert microseconds to 100-ns ticks expected by FILETIME APIs
    FILETIME ft100ns{};
    *reinterpret_cast<ULONGLONG*>(&ft100ns) =
        static_cast<ULONGLONG>(*reinterpret_cast<const ULONGLONG*>(&time)) * 10ULL;

    // FILETIME (UTC) -> local FILETIME -> SYSTEMTIME (local)
    FILETIME localFt{};
    SYSTEMTIME st{};
    if (!::FileTimeToLocalFileTime(&ft100ns, &localFt) ||
        !::FileTimeToSystemTime(&localFt, &st))
    {
        return {};
    }

    // Format as HH:MM:SS.mmm
    return STR_Printf("%02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}
