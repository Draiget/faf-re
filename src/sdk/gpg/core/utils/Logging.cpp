#include "Logging.h"

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <ios>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

using namespace gpg;

namespace
{
constexpr std::size_t kInitialContextCapacity = 4;
constexpr std::size_t kPipeChunkSize = 0x1000;
constexpr std::size_t kDebugOutputPayloadSize = 0x100;

class HistoryLogTarget final : public gpg::LogTarget
{
public:
    enum class EntryKind : std::int32_t
    {
        Message = 0,
        Context = 1,
    };

    struct Entry
    {
        EntryKind kind = EntryKind::Message;
        gpg::LogSeverity severity = gpg::LogSeverity::Info;
        msvc8::string text{};
        std::int32_t contextDepth = 0;
    };

    /**
     * Address: 0x008E48E0 (FUN_008E48E0, HistoryLogTarget::HistoryLogTarget)
     *
     * What it does:
     * Constructs one history log target, auto-registers it, and seeds the
     * retained-message cap.
     */
    explicit HistoryLogTarget(const std::int32_t maxMessages)
        : gpg::LogTarget(true),
          mMaxMessages(maxMessages)
    {
    }

    /**
     * Address: 0x008E49D0 (FUN_008E49D0, HistoryLogTarget::Enable)
     *
     * What it does:
     * Updates the retained-message cap and trims retained entries to fit.
     */
    void Enable(const std::int32_t maxMessages)
    {
        boost::recursive_mutex::scoped_lock lock(mLock);
        mMaxMessages = maxMessages;
        TrimLocked();
    }

    /**
     * Address: 0x008E4B30 (FUN_008E4B30, HistoryLogTarget::OnMessage)
     *
     * What it does:
     * Appends replay-context entries plus one message entry into retained
     * history, then enforces the retained-message cap.
     */
    void OnMessage(
        const gpg::LogSeverity level,
        const msvc8::string& message,
        const msvc8::vector<msvc8::string>& context,
        const int previousDepth
    ) override
    {
        boost::recursive_mutex::scoped_lock lock(mLock);

        int startDepth = previousDepth;
        if (startDepth < 0) {
            startDepth = 0;
        }

        const int contextCount = static_cast<int>(context.size());
        if (startDepth < contextCount) {
            for (int depth = startDepth; depth < contextCount; ++depth) {
                Entry replayEntry{};
                replayEntry.kind = EntryKind::Context;
                replayEntry.severity = level;
                replayEntry.text = context[static_cast<std::size_t>(depth)];
                replayEntry.contextDepth = depth;
                mEntries.push_back(replayEntry);
            }
        }

        Entry messageEntry{};
        messageEntry.kind = EntryKind::Message;
        messageEntry.severity = level;
        messageEntry.text = message;
        messageEntry.contextDepth = contextCount;
        mEntries.push_back(messageEntry);
        ++mMessageCount;

        TrimLocked();
    }

    /**
     * Address: 0x008E4CF0 (FUN_008E4CF0, HistoryLogTarget::ReplayTo)
     *
     * What it does:
     * Replays retained history entries into a target, preserving context-depth
     * transitions, then trims retained entries after replay unlock.
     */
    void ReplayTo(gpg::LogTarget& target)
    {
        msvc8::vector<Entry> snapshot{};
        {
            boost::recursive_mutex::scoped_lock lock(mLock);
            if (mEntries.empty()) {
                return;
            }

            ++mReplayDepth;
            snapshot = mEntries;
        }

        msvc8::vector<msvc8::string> context{};
        int previousDepth = 0;
        for (const Entry& entry : snapshot) {
            const int retainedDepth = entry.contextDepth;
            if (retainedDepth < 0) {
                continue;
            }
            const int currentDepth = static_cast<int>(context.size());
            if (retainedDepth < currentDepth) {
                previousDepth = retainedDepth;
                context.erase(
                    context.begin() + static_cast<std::size_t>(retainedDepth),
                    context.end()
                );
            }

            if (retainedDepth != static_cast<int>(context.size())) {
                continue;
            }

            if (entry.kind == EntryKind::Context) {
                context.push_back(entry.text);
                continue;
            }

            target.OnMessage(entry.severity, entry.text, context, previousDepth);
            previousDepth = retainedDepth;
        }

        {
            boost::recursive_mutex::scoped_lock lock(mLock);
            if (mReplayDepth > 0) {
                --mReplayDepth;
            }
            TrimLocked();
        }
    }

private:
    /**
     * Address: 0x008E4770 (FUN_008E4770, HistoryLogTarget::TrimLocked)
     *
     * What it does:
     * Removes oldest retained message entries (and stale context lanes) until
     * retained message count is within the configured cap.
     */
    void TrimLocked()
    {
        if (mReplayDepth != 0) {
            return;
        }

        if (mMaxMessages < 0 || mMessageCount <= mMaxMessages) {
            return;
        }

        while (mMessageCount > mMaxMessages && !mEntries.empty()) {
            bool removedMessage = false;
            int currentDepth = 0;

            for (std::size_t index = 0; index < mEntries.size();) {
                const int entryDepth = mEntries[index].contextDepth;
                if (entryDepth < 0) {
                    mEntries.erase(mEntries.begin() + index);
                    continue;
                }
                if (entryDepth < currentDepth) {
                    if (index == 0) {
                        currentDepth = entryDepth;
                    } else {
                        --index;
                        mEntries.erase(mEntries.begin() + index);
                        --currentDepth;
                    }
                    continue;
                }

                currentDepth = entryDepth;

                if (mEntries[index].kind == EntryKind::Context) {
                    ++currentDepth;
                    ++index;
                    continue;
                }

                mEntries.erase(mEntries.begin() + index);
                --mMessageCount;
                removedMessage = true;
                break;
            }

            if (!removedMessage) {
                break;
            }
        }
    }

    boost::recursive_mutex mLock{};
    msvc8::vector<Entry> mEntries{};
    std::int32_t mMaxMessages = 0;
    std::int32_t mMessageCount = 0;
    std::int32_t mReplayDepth = 0;
};

HistoryLogTarget* gLogHistoryTarget = nullptr;
std::once_flag gLogHistoryAtexitOnce;

void DestroyLogHistoryTarget()
{
    delete gLogHistoryTarget;
    gLogHistoryTarget = nullptr;
}

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
 * Address: 0x00937E80 (FUN_00937E80, gpg::LogTarget::~LogTarget)
 * Address: 0x00937ED0 (FUN_00937ED0)
 * Demangled: gpg::LogTarget deleting dtor thunk
 *
 * What it does:
 * Removes this target from global logging dispatch when attached,
 * covering both complete-destructor and deleting-thunk lanes.
 */
LogTarget::~LogTarget()
{
    Detach();
}

/**
 * Address: 0x00936770 (FUN_00936770, struct_LogContext::~struct_LogContext)
 *
 * What it does:
 * Detaches and destroys all registered target nodes, clears current-thread TSS
 * state, and restores the intrusive ring sentinel links.
 */
LogContext::~LogContext()
{
    rw.lock();
    while (head.next != &head) {
        LogTargetNode* const node = head.next;
        node->prev->next = node->next;
        node->next->prev = node->prev;
        node->next = node;
        node->prev = node;

        if (node->obj != nullptr) {
            node->obj->mNode = nullptr;
        }

        delete node;
    }
    head.next = &head;
    head.prev = &head;
    rw.unlock();

    if (tss.get() != nullptr) {
        tss.reset(nullptr);
    }
    lastTls = nullptr;
}

/**
 * Address: 0x009364A0 (FUN_009364A0, struct_LogContext::AddTarget)
 *
 * What it does:
 * Asserts detached target state, allocates one intrusive target node,
 * and appends it into the global log-target ring.
 */
void LogContext::AddTarget(LogTarget* const target)
{
    if (target == nullptr) {
        return;
    }

    if (target->mNode != nullptr) {
        HandleAssertFailure(
            "!target->mImpl",
            286,
            "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\utils\\log.cpp"
        );
        return;
    }

    rw.lock();
    auto* const node = new LogTargetNode{};
    node->obj = target;
    node->flushOnce = 1;
    node->busy = 0;
    node->pendingRemove = 0;
    node->prev = head.prev;
    node->next = &head;
    head.prev->next = node;
    head.prev = node;
    target->mNode = node;
    rw.unlock();
}

/**
 * Address: 0x00936570 (FUN_00936570, struct_LogContext::RemoveTarget)
 *
 * What it does:
 * Detaches one target node from the global log-target ring, or marks
 * pending removal when dispatch is currently inside that target.
 */
void LogContext::RemoveTarget(LogTarget* const target)
{
    if (target == nullptr) {
        return;
    }

    rw.lock();
    LogTargetNode* const node = target->mNode;
    if (node == nullptr) {
        rw.unlock();
        return;
    }

    if (node->busy) {
        node->pendingRemove = 1;
        target->mNode = nullptr;
        rw.unlock();
        return;
    }

    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;
    delete node;
    target->mNode = nullptr;
    rw.unlock();
}

/**
 * Address: 0x00937DB0 (FUN_00937DB0, gpg::LogTarget::Install)
 *
 * What it does:
 * Validates detached state, initializes global logging singleton,
 * and registers this target in the global target ring.
 */
void LogTarget::Attach()
{
    if (mNode != nullptr) {
        HandleAssertFailure(
            "!mImpl",
            413,
            "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\utils\\log.cpp"
        );
        return;
    }

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx != nullptr) {
        g_LogCtx->AddTarget(this);
    }
}

/**
 * Address: 0x00937E00 (FUN_00937E00, gpg::LogTarget::Uninstall)
 *
 * What it does:
 * Removes this target from the global target ring when currently attached.
 */
void LogTarget::Detach()
{
    if (mNode == nullptr) {
        return;
    }

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (!g_LogCtx) {
        HandleAssertFailure(
            "state",
            425,
            "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\utils\\log.cpp"
        );
        return;
    }

    g_LogCtx->RemoveTarget(this);
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

/**
 * Address: 0x00937640 (FUN_00937640, gpg::LogContext::push)
 *
 * What it does:
 * Clones current thread logging context labels, computes the previously
 * emitted depth for this thread lane, then calls every attached target while
 * processing deferred removals safely after callback return.
 */
void LogContext::Dispatch(const LogSeverity level, const msvc8::string& msg)
{
    rw.lock();

    ThreadState* const tls = tss.get();
    msvc8::vector<msvc8::string> snapshot;
    int prevDepth = 0;

    if (tls) {
        const std::size_t count =
            (tls->begin && tls->end) ? static_cast<std::size_t>(tls->end - tls->begin) : 0;

        snapshot.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            snapshot.push_back(tls->begin[i]->text);
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
            current->obj->OnMessage(level, msg, snapshot, sendPrev);
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

    rw.unlock();
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

// ---------------------------------------------------------------------------
// Global log-scope depth lanes.
//
// The two integer counters and the shared padding string back the nested
// logging indentation used by `gpg::LogScopeEntry` and by a handful of
// engine init paths (e.g. `Moho::CWldTerrainRes::Load`) that call the
// Increase/Decrease helpers directly.
//
// Binary lanes:
//   dword_10A6630  -> g_LogScopeDepth
//   dword_10A6634  -> g_LogScopeDepthScale
//   stru_10A6614   -> g_LogScopePadding
// ---------------------------------------------------------------------------
int gpg::g_LogScopeDepth = 0;
int gpg::g_LogScopeDepthScale = 0;
msvc8::string gpg::g_LogScopePadding{};

namespace {

/// Rebuilds `gpg::g_LogScopePadding` to `width` space characters, using the
/// owning-copy lane so the embedded SSO limit of `msvc8::string` is not a
/// cap. Matches the original binary's `std::string::assign_1(tmp, width, 0x20)
/// -> std::string::assign(global, tmp, 0, -1)` flow behaviourally, without
/// the decompiler-shaped raw-byte ctor/dtor dance.
void RefreshLogScopePadding(const unsigned int width)
{
    if (width == 0u) {
        gpg::g_LogScopePadding.assign_owned(std::string_view{});
        return;
    }

    const std::string spaces(width, ' ');
    gpg::g_LogScopePadding.assign_owned(std::string_view(spaces.data(), spaces.size()));
}

} // namespace

/**
 * Address: 0x00406110 (FUN_00406110, sub_406110)
 *
 * IDA signature:
 * std::string *sub_406110();
 *
 * What it does:
 * Bumps the global log-scope depth counter, multiplies it by the
 * per-level scale, rebuilds the global padding string to that many
 * space characters, and returns a pointer to the refreshed global
 * padding string.
 */
msvc8::string* gpg::IncreaseLogScopeDepth()
{
    const unsigned int width =
        static_cast<unsigned int>(++g_LogScopeDepth) *
        static_cast<unsigned int>(g_LogScopeDepthScale);

    RefreshLogScopePadding(width);
    return &g_LogScopePadding;
}

/**
 * Address: 0x004061B0 (FUN_004061B0, sub_4061B0)
 *
 * IDA signature:
 * std::string *sub_4061B0();
 *
 * What it does:
 * Mirror of `IncreaseLogScopeDepth`: decrements the depth counter,
 * refreshes the shared padding string, and returns the global padding
 * pointer.
 */
msvc8::string* gpg::DecreaseLogScopeDepth()
{
    const unsigned int width =
        static_cast<unsigned int>(--g_LogScopeDepth) *
        static_cast<unsigned int>(g_LogScopeDepthScale);

    RefreshLogScopePadding(width);
    return &g_LogScopePadding;
}

/**
 * Address: 0x00406280 (FUN_00406280, ??0StrArg@gpg@@QAE@@Z)
 * Mangled: gpg::StrArg::StrArg
 *
 * IDA signature:
 * std::string *__stdcall gpg::StrArg::StrArg(std::string *a1, std::string *a2);
 *
 * What it does:
 * Initializes the embedded body string to empty SSO state, assigns the
 * full contents of `fmt` into the body via the owning-copy lane, zeroes
 * the severity field, and bumps the global log-scope depth through
 * `IncreaseLogScopeDepth`.
 */
gpg::LogScopeEntry::LogScopeEntry(const msvc8::string& fmt)
{
    body.assign_owned(fmt.view());
    severity = LogSeverity::Debug;
    (void)IncreaseLogScopeDepth();
}

/**
 * Address: 0x004062E0 (FUN_004062E0, func_Log)
 *
 * IDA signature:
 * void __stdcall func_Log(std::string *a1);
 *
 * What it does:
 * Decrements the global log-scope depth, formats the stored body string
 * with `gpg::STR_Printf` using an integer width argument derived from
 * `field_0x38`, dispatches the result through `gpg::LogMessage` at the
 * stored severity, then resets the embedded body string to empty SSO
 * state.
 *
 * Note: the binary loads the STR_Printf width argument from an
 * uninitialized stack local that the compiler happens to have zeroed
 * via a preceding 52-byte memset. The behaviorally-equivalent source is
 * `width = 0u - field_0x38`.
 */
void gpg::LogScopeEntry::Emit()
{
    (void)DecreaseLogScopeDepth();

    const unsigned int widthArg = 0u - field_0x38;
    const msvc8::string formatted = STR_Printf(body.c_str(), widthArg);
    LogMessage(severity, formatted);

    body.clear();
}

/**
 * Address: 0x00937C00 (FUN_00937C00, gpg::LogMessage)
 *
 * What it does:
 * Dispatches one preformatted message with explicit severity to registered targets.
 */
void gpg::LogMessage(const LogSeverity level, const msvc8::string& message)
{
    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(level, message);
    }
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

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(LogSeverity::Info, msg);
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

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(LogSeverity::Warn, msg);
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

    std::call_once(g_LogOnce, &InitLogSingleton);
    if (g_LogCtx) {
        g_LogCtx->Dispatch(LogSeverity::Debug, msg);
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
    if (gLogHistoryTarget != nullptr) {
        gLogHistoryTarget->Enable(maxEntries);
        return;
    }

    gLogHistoryTarget = new HistoryLogTarget(maxEntries);
    std::call_once(gLogHistoryAtexitOnce, [] {
        std::atexit(DestroyLogHistoryTarget);
    });
}

/**
 * Address: 0x008E4F20 (FUN_008E4F20, gpg::ReplayLogHistory)
 *
 * What it does:
 * Replays retained log-history entries into one caller-supplied log target.
 */
bool gpg::ReplayLogHistory(LogTarget* const target)
{
    if (target == nullptr || gLogHistoryTarget == nullptr) {
        return false;
    }

    gLogHistoryTarget->ReplayTo(*target);
    return true;
}

/**
 * Address: 0x008E4AD0 + 0x008E4CF0 + 0x008E4F20 path
 *
 * What it does:
 * Builds one newline-delimited UTF-8 text snapshot by replaying retained
 * history entries through a stream log target.
 */
msvc8::string gpg::GetRecentLogLines()
{
    std::ostringstream stream{};
    StreamLogTarget sink(stream, 0u);
    (void)ReplayLogHistory(&sink);

    msvc8::string result;
    result.assign_owned(stream.str());
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

/**
 * Address: 0x00485CB0 (FUN_00485CB0, func_FileTimeToString)
 *
 * What it does:
 * Converts microsecond timestamp to local `HH:MM:SS.mmm` text.
 */
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
