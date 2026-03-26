#include "Logging.h"

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <ios>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "gpg/core/containers/String.h"

using namespace gpg;

namespace
{
constexpr std::size_t kInitialContextCapacity = 4;
constexpr std::size_t kPipeChunkSize = 0x1000;
constexpr std::size_t kDebugOutputPayloadSize = 0x100;

std::mutex gHistoryMutex;
int gHistoryCapacity = 0;
msvc8::vector<msvc8::string> gHistoryEntries;

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

const char* SeverityText(const gpg::LogSeverity level)
{
    static const char* const kSeverity[] = { "debug", "info", "warning" };
    const int index = static_cast<int>(level);
    if (index < 0 || index >= static_cast<int>(std::size(kSeverity))) {
        return "info";
    }
    return kSeverity[index];
}

void WriteIndent(std::ostream& stream, const int count)
{
    for (int i = 0; i < count; ++i) {
        stream.put(' ');
    }
}

void AppendHistoryEntry(const msvc8::string& message)
{
    std::lock_guard<std::mutex> lock(gHistoryMutex);
    if (gHistoryCapacity <= 0) {
        return;
    }

    while (gHistoryEntries.size() >= static_cast<std::size_t>(gHistoryCapacity)) {
        gHistoryEntries.erase(gHistoryEntries.begin());
    }
    gHistoryEntries.push_back(message);
}
} // namespace

/**
 * Address: 0x00937E50 (FUN_00937E50)
 * Demangled: gpg::LogTarget::LogTarget(bool)
 *
 * What it does:
 * Initializes base log-target state and optionally registers with global logging.
 */
LogTarget::LogTarget(const bool autoRegister)
    : mNode(nullptr)
{
    if (autoRegister) {
        Attach();
    }
}

/**
 * Address: 0x00937ED0 (FUN_00937ED0)
 * Demangled: gpg::LogTarget deleting dtor thunk
 *
 * What it does:
 * Unregisters the target from global logging dispatch if currently attached.
 */
LogTarget::~LogTarget()
{
    Detach();
}

void LogTarget::Attach()
{
    if (mNode) {
        return;
    }

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (!g_LogCtx) {
        return;
    }

    auto* const node = new LogTargetNode{};
    node->obj = this;
    node->flushOnce = 1;

    g_LogCtx->rw.lock();
    node->prev = g_LogCtx->head.prev;
    node->next = &g_LogCtx->head;
    g_LogCtx->head.prev->next = node;
    g_LogCtx->head.prev = node;
    mNode = node;
    g_LogCtx->rw.unlock();
}

void LogTarget::Detach()
{
    LogTargetNode* const node = mNode;
    if (!node) {
        return;
    }

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (!g_LogCtx) {
        mNode = nullptr;
        return;
    }

    g_LogCtx->rw.lock();
    if (node->busy) {
        node->pendingRemove = 1;
        node->obj = nullptr;
        mNode = nullptr;
        g_LogCtx->rw.unlock();
        return;
    }

    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;
    delete node;
    mNode = nullptr;
    g_LogCtx->rw.unlock();
}

void LogTarget::OnLog(
    const int level,
    const msvc8::string& message,
    std::span<const msvc8::string> context,
    int previousDepth
)
{
    msvc8::vector<msvc8::string> contextCopy;
    contextCopy.reserve(context.size());
    for (const msvc8::string& entry : context) {
        contextCopy.push_back(entry);
    }

    if (previousDepth < 0) {
        previousDepth = 0;
    }
    if (previousDepth > static_cast<int>(contextCopy.size())) {
        previousDepth = static_cast<int>(contextCopy.size());
    }

    OnMessage(static_cast<LogSeverity>(level), message, contextCopy, previousDepth);
}

/**
 * Address: 0x00906C00 (FUN_00906C00)
 * Demangled: gpg::StreamLogTarget::StreamLogTarget(std::ostream&,unsigned int)
 *
 * What it does:
 * Initializes stream-backed log target and controls ownership/auto-registration by flags.
 */
StreamLogTarget::StreamLogTarget(std::ostream& stream, const unsigned int flags)
    : LogTarget((flags & 0x1U) != 0),
      mStream(&stream),
      mOwnStream(static_cast<std::uint8_t>((flags >> 1U) & 0x1U)),
      mPad0(0),
      mPad1(0),
      mPad2(0)
{
}

/**
 * Address: 0x00906CA0 (FUN_00906CA0)
 * Demangled: gpg::StreamLogTarget deleting dtor thunk
 *
 * What it does:
 * Tears down owned stream (when flagged) and unregisters from logging dispatch.
 */
StreamLogTarget::~StreamLogTarget()
{
    if (mOwnStream != 0 && mStream) {
        delete mStream;
        mStream = nullptr;
    }
}

/**
 * Address: 0x00906CF0 (FUN_00906CF0)
 * Demangled: gpg::StreamLogTarget::OnMessage
 *
 * What it does:
 * Formats contextual log output to the target stream with indentation and newline folding.
 */
void StreamLogTarget::OnMessage(
    const LogSeverity level,
    const msvc8::string& message,
    const msvc8::vector<msvc8::string>& context,
    int previousDepth
)
{
    if (!mStream) {
        return;
    }

    std::ostream& out = *mStream;
    if (previousDepth < 0) {
        previousDepth = 0;
    }

    const int contextCount = static_cast<int>(context.size());
    if (previousDepth > contextCount) {
        previousDepth = contextCount;
    }

    int indent = previousDepth * 4;
    for (int i = previousDepth; i < contextCount; ++i) {
        WriteIndent(out, indent);
        out << context[static_cast<std::size_t>(i)].c_str() << ":\n";
        indent += 4;
    }

    const char* const severity = SeverityText(level);
    WriteIndent(out, indent);
    out << severity << ": ";
    const int continuationIndent = indent + static_cast<int>(std::strlen(severity)) + 2;

    const char* cursor = message.c_str();
    const char* lineBreak = std::strchr(cursor, '\n');
    if (!lineBreak) {
        out << cursor;
        out.put('\n');
    } else {
        out.write(cursor, static_cast<std::streamsize>(lineBreak - cursor + 1));
        cursor = lineBreak + 1;

        while (*cursor != '\0') {
            WriteIndent(out, continuationIndent);
            lineBreak = std::strchr(cursor, '\n');
            if (!lineBreak) {
                out << cursor;
                out.put('\n');
                break;
            }
            out.write(cursor, static_cast<std::streamsize>(lineBreak - cursor + 1));
            cursor = lineBreak + 1;
        }
    }

    if ((out.rdstate() & (std::ios::badbit | std::ios::failbit)) == 0) {
        std::streambuf* const streamBuffer = out.rdbuf();
        if (!streamBuffer || streamBuffer->pubsync() == -1) {
            out.setstate(std::ios::badbit);
        }
    }
}

/**
 * Address: 0x00906510 (FUN_00906510)
 * Demangled: gpg::PipeBuf::PipeBuf
 *
 * What it does:
 * Initializes a lock-protected ring of 4KB stream chunks and primes get/put windows.
 */
PipeBuf::PipeBuf()
    : std::streambuf(),
      mMutex(),
      mChunks(),
      mReadLimit(nullptr),
      mWriteCommit(nullptr)
{
    auto* const first = new StreamBuffer{};
    mChunks.push_back(first);
    mReadLimit = first->bytes;
    mWriteCommit = first->bytes;
    setg(
        reinterpret_cast<char*>(first->bytes),
        reinterpret_cast<char*>(first->bytes),
        reinterpret_cast<char*>(first->bytes)
    );
    setp(
        reinterpret_cast<char*>(first->bytes),
        reinterpret_cast<char*>(first->bytes + kPipeChunkSize)
    );
}

/**
 * Address: 0x00906BD0 (FUN_00906BD0)
 * Demangled: gpg::PipeBuf deleting dtor thunk
 *
 * What it does:
 * Releases all queued stream chunks and destroys synchronization state.
 */
PipeBuf::~PipeBuf()
{
    setg(nullptr, nullptr, nullptr);
    setp(nullptr, nullptr);

    while (!mChunks.empty()) {
        StreamBuffer* const chunk = mChunks.pop_front();
        delete chunk;
    }
    mReadLimit = nullptr;
    mWriteCommit = nullptr;
}

PipeBuf::StreamBuffer* PipeBuf::HeadBuffer()
{
    return mChunks.front();
}

PipeBuf::StreamBuffer* PipeBuf::TailBuffer()
{
    return mChunks.back();
}

bool PipeBuf::IsSingleBuffer()
{
    StreamBuffer* const head = HeadBuffer();
    return head && head == TailBuffer();
}

/**
 * Address: 0x00906610 (FUN_00906610)
 * Demangled: gpg::PipeBuf::overflow
 *
 * What it does:
 * Appends one byte to the write tail, allocating a new 4KB chunk when put space is exhausted.
 */
PipeBuf::int_type PipeBuf::overflow(const int_type ch)
{
    if (traits_type::eq_int_type(ch, traits_type::eof())) {
        return traits_type::eof();
    }

    char* const putNext = pptr();
    char* const putEnd = epptr();
    if (putNext != putEnd) {
        *putNext = traits_type::to_char_type(ch);
        pbump(1);
        return ch;
    }

    auto* const fresh = new StreamBuffer{};
    {
        boost::mutex::scoped_lock lock(mMutex);
        if (IsSingleBuffer()) {
            mReadLimit = reinterpret_cast<std::uint8_t*>(putEnd);
        }
        mChunks.push_back(fresh);
        mWriteCommit = fresh->bytes;
    }

    fresh->bytes[0] = static_cast<std::uint8_t>(traits_type::to_char_type(ch));
    setp(
        reinterpret_cast<char*>(fresh->bytes + 1),
        reinterpret_cast<char*>(fresh->bytes + kPipeChunkSize)
    );
    return ch;
}

/**
 * Address: 0x009066E0 (FUN_009066E0)
 * Demangled: gpg::PipeBuf::xsputn
 *
 * What it does:
 * Appends a byte span to the write tail, chaining new chunks as needed.
 */
std::streamsize PipeBuf::xsputn(const char* const src, const std::streamsize count)
{
    if (!src || count <= 0) {
        return 0;
    }

    const char* cursor = src;
    std::streamsize remaining = count;
    while (remaining > 0) {
        const std::streamsize writable = static_cast<std::streamsize>(epptr() - pptr());
        if (writable > 0) {
            const std::streamsize chunk = (remaining < writable) ? remaining : writable;
            std::memcpy(pptr(), cursor, static_cast<std::size_t>(chunk));
            pbump(static_cast<int>(chunk));
            cursor += chunk;
            remaining -= chunk;
            if (remaining <= 0) {
                break;
            }
        }

        auto* const fresh = new StreamBuffer{};
        {
            boost::mutex::scoped_lock lock(mMutex);
            if (IsSingleBuffer()) {
                mReadLimit = reinterpret_cast<std::uint8_t*>(epptr());
            }
            mChunks.push_back(fresh);
            mWriteCommit = fresh->bytes;
        }

        setp(
            reinterpret_cast<char*>(fresh->bytes),
            reinterpret_cast<char*>(fresh->bytes + kPipeChunkSize)
        );
    }

    return count;
}

/**
 * Address: 0x009067E0 (FUN_009067E0)
 * Demangled: gpg::PipeBuf::showmanyc
 *
 * What it does:
 * Computes readable bytes currently committed across head/middle/tail chunk windows.
 */
std::streamsize PipeBuf::showmanyc()
{
    boost::mutex::scoped_lock lock(mMutex);

    StreamBuffer* const head = HeadBuffer();
    StreamBuffer* const tail = TailBuffer();
    if (!head || !tail || !gptr()) {
        return 0;
    }

    std::streamsize available =
        static_cast<std::streamsize>(mReadLimit - reinterpret_cast<const std::uint8_t*>(gptr()));
    if (head != tail) {
        for (DListItem<StreamBuffer>* node = head->mNext; node != tail; node = node->mNext) {
            available += static_cast<std::streamsize>(kPipeChunkSize);
        }
        available += static_cast<std::streamsize>(mWriteCommit - tail->bytes);
    }

    return available;
}

/**
 * Address: 0x00906840 (FUN_00906840)
 * Demangled: gpg::PipeBuf::underflow
 *
 * What it does:
 * Ensures a readable byte exists by advancing/freeing exhausted head chunks.
 */
PipeBuf::int_type PipeBuf::underflow()
{
    std::uint8_t* readNext = reinterpret_cast<std::uint8_t*>(gptr());
    std::uint8_t* readEnd = reinterpret_cast<std::uint8_t*>(egptr());
    if (readNext < readEnd) {
        return traits_type::to_int_type(*readNext);
    }

    while (true) {
        boost::mutex::scoped_lock lock(mMutex);

        StreamBuffer* head = HeadBuffer();
        StreamBuffer* tail = TailBuffer();
        if (!head || !tail) {
            return traits_type::eof();
        }

        if (reinterpret_cast<std::uintptr_t>(readEnd) < reinterpret_cast<std::uintptr_t>(mReadLimit)) {
            setg(
                reinterpret_cast<char*>(head->bytes),
                reinterpret_cast<char*>(readNext),
                reinterpret_cast<char*>(mReadLimit)
            );
            return traits_type::to_int_type(*readNext);
        }

        if (head == tail) {
            return traits_type::eof();
        }

        StreamBuffer* const consumed = mChunks.pop_front();
        delete consumed;

        head = HeadBuffer();
        tail = TailBuffer();
        if (!head || !tail) {
            return traits_type::eof();
        }

        mReadLimit = (head == tail) ? mWriteCommit : (head->bytes + kPipeChunkSize);
        setg(
            reinterpret_cast<char*>(head->bytes),
            reinterpret_cast<char*>(head->bytes),
            reinterpret_cast<char*>(mReadLimit)
        );

        readNext = reinterpret_cast<std::uint8_t*>(gptr());
        readEnd = reinterpret_cast<std::uint8_t*>(egptr());
        if (readNext < readEnd) {
            return traits_type::to_int_type(*readNext);
        }
    }
}

/**
 * Address: 0x00906980 (FUN_00906980)
 * Demangled: gpg::PipeBuf::xsgetn
 *
 * What it does:
 * Copies readable bytes out of queued chunks while compacting consumed head buffers.
 */
std::streamsize PipeBuf::xsgetn(char* const dst, const std::streamsize count)
{
    if (!dst || count <= 0) {
        return 0;
    }

    std::streamsize copied = 0;
    while (copied < count) {
        std::uint8_t* const readNext = reinterpret_cast<std::uint8_t*>(gptr());
        std::uint8_t* const readEnd = reinterpret_cast<std::uint8_t*>(egptr());
        const std::streamsize available = static_cast<std::streamsize>(readEnd - readNext);
        if (available > 0) {
            const std::streamsize chunk = ((count - copied) < available) ? (count - copied) : available;
            std::memcpy(dst + copied, readNext, static_cast<std::size_t>(chunk));
            gbump(static_cast<int>(chunk));
            copied += chunk;
            if (copied >= count) {
                break;
            }
            continue;
        }

        boost::mutex::scoped_lock lock(mMutex);
        StreamBuffer* head = HeadBuffer();
        StreamBuffer* tail = TailBuffer();
        if (!head || !tail) {
            break;
        }

        if (reinterpret_cast<std::uintptr_t>(readEnd) < reinterpret_cast<std::uintptr_t>(mReadLimit)) {
            setg(
                reinterpret_cast<char*>(head->bytes),
                reinterpret_cast<char*>(readNext),
                reinterpret_cast<char*>(mReadLimit)
            );
            continue;
        }

        if (head == tail) {
            break;
        }

        StreamBuffer* const consumed = mChunks.pop_front();
        delete consumed;

        head = HeadBuffer();
        tail = TailBuffer();
        if (!head || !tail) {
            break;
        }

        mReadLimit = (head == tail) ? mWriteCommit : (head->bytes + kPipeChunkSize);
        setg(
            reinterpret_cast<char*>(head->bytes),
            reinterpret_cast<char*>(head->bytes),
            reinterpret_cast<char*>(mReadLimit)
        );
    }

    return copied;
}

/**
 * Address: 0x00906B00 (FUN_00906B00)
 * Demangled: gpg::PipeBuf::sync
 *
 * What it does:
 * Publishes the current write cursor as the committed read boundary.
 */
int PipeBuf::sync()
{
    boost::mutex::scoped_lock lock(mMutex);
    mWriteCommit = reinterpret_cast<std::uint8_t*>(pptr());
    if (IsSingleBuffer()) {
        mReadLimit = mWriteCommit;
    }
    return 0;
}

/**
 * Address: 0x00935860 (FUN_00935860)
 * Demangled: gpg::DebugOutputStreambuf deleting dtor thunk
 *
 * What it does:
 * Flushes pending debug line content to OutputDebugStringA and tears down streambuf state.
 */
DebugOutputStreambuf::~DebugOutputStreambuf()
{
    (void)sync();
}

/**
 * Address: 0x009357E0 (FUN_009357E0)
 * Demangled: gpg::DebugOutputStreambuf::overflow
 *
 * What it does:
 * Publishes pending debug output and appends one character into the internal line buffer.
 */
DebugOutputStreambuf::int_type DebugOutputStreambuf::overflow(const int_type ch)
{
    (void)sync();
    if (!traits_type::eq_int_type(ch, traits_type::eof())) {
        if (pptr() != nullptr && epptr() > pptr()) {
            *pptr() = traits_type::to_char_type(ch);
            pbump(1);
            return ch;
        }

        (void)std::streambuf::overflow(static_cast<unsigned char>(traits_type::to_char_type(ch)));
    }

    return ch;
}

/**
 * Address: 0x00935750 (FUN_00935750)
 * Demangled: gpg::DebugOutputStreambuf::sync
 *
 * What it does:
 * NUL-terminates and flushes the buffered line through OutputDebugStringA, then resets put state.
 */
int DebugOutputStreambuf::sync()
{
    char* const writeCursor = pptr();
    if (writeCursor != nullptr && writeCursor != mBuffer) {
        *writeCursor = '\0';
        OutputDebugStringA(mBuffer);
    }

    setp(mBuffer, mBuffer + kDebugOutputPayloadSize);
    return 0;
}

void LogContext::Dispatch(const int level, const msvc8::string& msg)
{
    rw.lock_shared();

    ThreadState* const tls = tss.get();
    std::vector<msvc8::string> snapshot;
    int prevDepth = 0;

    if (tls) {
        const std::size_t count =
            (tls->begin && tls->end) ? static_cast<std::size_t>(tls->end - tls->begin) : 0;

        snapshot.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            snapshot.emplace_back(tls->begin[i]->text);
        }

        prevDepth = static_cast<int>(tls->depthCache);
        tls->depthCache = static_cast<std::uint32_t>(count);

        if (tls != lastTls) {
            prevDepth = 0;
            lastTls = tls;
        }
    }

    for (LogTargetNode* node = head.next; node != &head; ) {
        LogTargetNode* const current = node;
        node = node->next;

        if (current->busy) {
            continue;
        }

        current->busy = 1;
        const int sendPrev = current->flushOnce ? 0 : prevDepth;
        current->flushOnce = 0;

        if (current->obj) {
            current->obj->OnLog(
                level,
                msg,
                std::span<const msvc8::string>(snapshot.data(), snapshot.size()),
                sendPrev
            );
        }

        current->busy = 0;
        if (current->pendingRemove) {
            current->prev->next = current->next;
            current->next->prev = current->prev;
            current->prev = current;
            current->next = current;
            delete current;
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

/**
 * Address: 0x00937CB0 (FUN_00937CB0)
 *
 * What it does:
 * Formats and dispatches an info-level log message.
 */
void gpg::Logf(const char* fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);

    AppendHistoryEntry(msg);

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(kInfo, msg);
    }
}

/**
 * Address: 0x00937D30 (FUN_00937D30)
 *
 * What it does:
 * Formats and dispatches a warning-level log message.
 */
void gpg::Warnf(const char* fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);

    AppendHistoryEntry(msg);

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(kWarn, msg);
    }
}

/**
 * Address: 0x00937C30 (FUN_00937C30)
 *
 * What it does:
 * Formats and dispatches a debug-level log message.
 */
void gpg::Debugf(const char* fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    const msvc8::string msg = STR_Va(fmt, va);
    va_end(va);

    AppendHistoryEntry(msg);

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(kDebug, msg);
    }
}

/**
 * Address: 0x008E4A40 (?EnableLogHistory@gpg@@YAXH@Z)
 *
 * What it does:
 * Configures bounded in-memory logging history size.
 */
void gpg::EnableLogHistory(const int maxEntries)
{
    std::lock_guard<std::mutex> lock(gHistoryMutex);
    gHistoryCapacity = (maxEntries > 0) ? maxEntries : 0;

    if (gHistoryCapacity == 0) {
        gHistoryEntries.clear();
        return;
    }

    while (gHistoryEntries.size() > static_cast<std::size_t>(gHistoryCapacity)) {
        gHistoryEntries.erase(gHistoryEntries.begin());
    }
}

msvc8::string gpg::GetRecentLogLines()
{
    std::lock_guard<std::mutex> lock(gHistoryMutex);

    std::string merged;
    for (const msvc8::string& line : gHistoryEntries) {
        merged.append(line.c_str());
        merged.push_back('\n');
    }

    msvc8::string result;
    result.assign_owned(merged);
    return result;
}

FILETIME gpg::FileTimeLocal()
{
    FILETIME ftUtc{};
    FILETIME ftLocal{};
    GetSystemTimeAsFileTime(&ftUtc);
    FileTimeToLocalFileTime(&ftUtc, &ftLocal);
    return ftLocal;
}

msvc8::string gpg::FileTimeToString(const LONGLONG time)
{
    FILETIME ft100ns{};
    *reinterpret_cast<ULONGLONG*>(&ft100ns) =
        static_cast<ULONGLONG>(*reinterpret_cast<const ULONGLONG*>(&time)) * 10ULL;

    FILETIME localFt{};
    SYSTEMTIME st{};
    if (!::FileTimeToLocalFileTime(&ft100ns, &localFt) ||
        !::FileTimeToSystemTime(&localFt, &st))
    {
        return {};
    }

    return STR_Printf(
        "%02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds)
    );
}
