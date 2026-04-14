#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <ostream>
#include <span>
#include <streambuf>

#include "boost/Mutex.h"
#include "gpg/core/containers/DList.h"
#include "Sync.h"
#include "Tss.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
    /**
     * Severity levels mapped to original call sites.
     */
    enum class LogSeverity : int
    {
        Debug = 0,
        Info = 1,
        Warn = 2,
    };

    inline constexpr int kDebug = static_cast<int>(LogSeverity::Debug);
    inline constexpr int kInfo = static_cast<int>(LogSeverity::Info);
    inline constexpr int kWarn = static_cast<int>(LogSeverity::Warn);

    class LogTarget;

    /**
     * Intrusive list node for targets (layout mirrors reverse engineered one).
     */
    struct LogTargetNode
    {
        LogTargetNode* prev{ this };
        LogTargetNode* next{ this };
        LogTarget* obj{ nullptr };
        std::uint8_t flushOnce{ 0 };
        std::uint8_t busy{ 0 };
        std::uint8_t pendingRemove{ 0 };
        std::uint8_t pad{ 0 };
    };
    static_assert(sizeof(LogTargetNode) == 0x10, "LogTargetNode size must be 0x10");

    /**
     * VFTABLE: 0x00D47990
     * COL:  0x00E52EF0
     */
    class LogTarget
    {
    public:
        /**
         * Address: 0x00937E80 (FUN_00937E80, gpg::LogTarget::~LogTarget)
         * Address: 0x00937ED0 (FUN_00937ED0)
         * Demangled: gpg::LogTarget deleting dtor thunk
         *
         * What it does:
         * Removes this target from global logging dispatch when attached,
         * covering both complete-destructor and deleting-thunk lanes.
         */
        virtual ~LogTarget();

        virtual void OnMessage(
            LogSeverity level,
            const msvc8::string& message,
            const msvc8::vector<msvc8::string>& context,
            int previousDepth
        ) = 0;

        /**
         * Adapter used by recovered dispatch code to pass thread-context spans.
         */
        virtual void OnLog(
            int level,
            const msvc8::string& message,
            std::span<const msvc8::string> context,
            int previousDepth
        );

    protected:
        /**
         * Address: 0x00937E50 (FUN_00937E50)
         * Demangled: gpg::LogTarget::LogTarget(bool)
         *
         * What it does:
         * Initializes base log-target state and optionally registers with global logging.
         */
        explicit LogTarget(bool autoRegister);

    private:
        /**
         * Address: 0x00937DB0 (FUN_00937DB0, gpg::LogTarget::Install)
         *
         * What it does:
         * Validates detached state, initializes global logging singleton,
         * and registers this target in the global target ring.
         */
        void Attach();

        /**
         * Address: 0x00937E00 (FUN_00937E00, gpg::LogTarget::Uninstall)
         *
         * What it does:
         * Removes this target from the global target ring when currently attached.
         */
        void Detach();

        LogTargetNode* mNode{};

        friend struct LogContext;
    };
    static_assert(sizeof(LogTarget) == 0x08, "LogTarget size must be 0x08");

    /**
     * VFTABLE: 0x00D44BF8
     * COL:  0x00E51658
     */
    class StreamLogTarget final : public LogTarget
    {
    public:
        /**
         * Address: 0x00906C00 (FUN_00906C00)
         * Demangled: gpg::StreamLogTarget::StreamLogTarget(std::ostream&,unsigned int)
         *
         * What it does:
         * Initializes stream-backed log target and controls ownership/auto-registration by flags.
         */
        StreamLogTarget(std::ostream& stream, unsigned int flags);

        /**
         * Address: 0x00906C30 (FUN_00906C30, ??1StreamLogTarget@gpg@@UAE@XZ)
         * Address: 0x00906CA0 (FUN_00906CA0)
         * Demangled: gpg::StreamLogTarget::~StreamLogTarget
         * Demangled: gpg::StreamLogTarget deleting dtor thunk
         *
         * What it does:
         * Tears down owned stream (when flagged) and then lets the base
         * `LogTarget` destructor unregister this sink from global dispatch.
         */
        ~StreamLogTarget() override;

        /**
         * Address: 0x00906CF0 (FUN_00906CF0)
         * Demangled: gpg::StreamLogTarget::OnMessage
         *
         * What it does:
         * Formats contextual log output to the target stream with indentation and newline folding.
         */
        void OnMessage(
            LogSeverity level,
            const msvc8::string& message,
            const msvc8::vector<msvc8::string>& context,
            int previousDepth
        ) override;

    private:
        std::ostream* mStream{};
        std::uint8_t mOwnStream{};
        std::uint8_t mPad0{};
        std::uint8_t mPad1{};
        std::uint8_t mPad2{};
    };
    static_assert(sizeof(StreamLogTarget) == 0x10, "StreamLogTarget size must be 0x10");

    /**
     * VFTABLE: 0x00D44BBC
     * COL:  0x00E5160C
     */
    class PipeBuf : public std::streambuf
    {
    public:
        /**
         * Address: 0x00906510 (FUN_00906510)
         * Demangled: gpg::PipeBuf::PipeBuf
         *
         * What it does:
         * Initializes a lock-protected ring of 4KB stream chunks and primes get/put windows.
         */
        PipeBuf();

        /**
         * Address: 0x00906BD0 (FUN_00906BD0)
         * Demangled: gpg::PipeBuf deleting dtor thunk
         *
         * What it does:
         * Releases all queued stream chunks and destroys synchronization state.
         */
        ~PipeBuf() override;

    protected:
        /**
         * Address: 0x00906610 (FUN_00906610)
         * Demangled: gpg::PipeBuf::overflow
         *
         * What it does:
         * Appends one byte to the write tail, allocating a new 4KB chunk when put space is exhausted.
         */
        int_type overflow(int_type ch) override;

        /**
         * Address: 0x009066E0 (FUN_009066E0)
         * Demangled: gpg::PipeBuf::xsputn
         *
         * What it does:
         * Appends a byte span to the write tail, chaining new chunks as needed.
         */
        std::streamsize xsputn(const char* src, std::streamsize count) override;

        /**
         * Address: 0x009067E0 (FUN_009067E0)
         * Demangled: gpg::PipeBuf::showmanyc
         *
         * What it does:
         * Computes readable bytes currently committed across head/middle/tail chunk windows.
         */
        std::streamsize showmanyc() override;

        /**
         * Address: 0x00906840 (FUN_00906840)
         * Demangled: gpg::PipeBuf::underflow
         *
         * What it does:
         * Ensures a readable byte exists by advancing/freeing exhausted head chunks.
         */
        int_type underflow() override;

        /**
         * Address: 0x00906980 (FUN_00906980)
         * Demangled: gpg::PipeBuf::xsgetn
         *
         * What it does:
         * Copies readable bytes out of queued chunks while compacting consumed head buffers.
         */
        std::streamsize xsgetn(char* dst, std::streamsize count) override;

        /**
         * Address: 0x00906B00 (FUN_00906B00)
         * Demangled: gpg::PipeBuf::sync
         *
         * What it does:
         * Publishes the current write cursor as the committed read boundary.
         */
        int sync() override;

    private:
        struct StreamBuffer : DListItem<StreamBuffer>
        {
            std::uint8_t bytes[0x1000]{};
        };
        static_assert(sizeof(StreamBuffer) == 0x1008, "PipeBuf::StreamBuffer size must be 0x1008");

        StreamBuffer* HeadBuffer();
        StreamBuffer* TailBuffer();
        bool IsSingleBuffer();

        boost::mutex mMutex{};
        DList<StreamBuffer, void> mChunks{};
        std::uint8_t* mReadLimit{};
        std::uint8_t* mWriteCommit{};
    };

    /**
     * VFTABLE: 0x00D478A0
     * COL:  0x00E52EA4
     */
    class DebugOutputStreambuf : public std::streambuf
    {
    public:
        /**
         * Address: 0x00935860 (FUN_00935860)
         * Demangled: gpg::DebugOutputStreambuf deleting dtor thunk
         *
         * What it does:
         * Flushes pending debug line content to OutputDebugStringA and tears down streambuf state.
         */
        ~DebugOutputStreambuf() override;

    protected:
        /**
         * Address: 0x009357E0 (FUN_009357E0)
         * Demangled: gpg::DebugOutputStreambuf::overflow
         *
         * What it does:
         * Publishes pending debug output and appends one character into the internal line buffer.
         */
        int_type overflow(int_type ch) override;

        /**
         * Address: 0x00935750 (FUN_00935750)
         * Demangled: gpg::DebugOutputStreambuf::sync
         *
         * What it does:
         * NUL-terminates and flushes the buffered line through OutputDebugStringA, then resets put state.
         */
        int sync() override;

    private:
        char mBuffer[0x101]{};
    };

    /**
     * Thread-local entry holding a prefix text (shape inferred).
     */
    struct ThreadCtxEntry
    {
        void* reserved{};
        msvc8::string text;
    };

    /**
     * Thread-local state, stored in TSS.
     */
    struct ThreadState
    {
        ThreadCtxEntry** begin{};
        ThreadCtxEntry** end{};
        ThreadCtxEntry** cap{};
        std::uint32_t depthCache{};

        ~ThreadState() {
            if (begin) {
                for (ThreadCtxEntry** it = begin; it != end; ++it) {
                    delete *it;
                }
                delete[] begin;
            }
            begin = end = cap = nullptr;
            depthCache = 0;
        }
    };

    /**
     * Global logging context singleton (size 0x1C).
     */
    struct LogContext
    {
        core::TssPtr<ThreadState> tss;
        core::SharedLock rw;
        LogTargetNode head;
        ThreadState* lastTls{};

        /**
         * Address: 0x00937A70 (FUN_00937A70, ??0LogContext@gpg@@QAE@@Z)
         *
         * What it does:
         * Initializes TSS/lock state, self-links the target-list sentinel, and
         * clears last-thread cache pointer.
         */
        LogContext();

        /**
         * Address: 0x00936770 (FUN_00936770, struct_LogContext::~struct_LogContext)
         *
         * What it does:
         * Detaches and destroys all registered target nodes, clears current-thread
         * TSS state, and leaves the intrusive target ring in sentinel form.
         */
        ~LogContext();

        /**
         * Address: 0x009364A0 (FUN_009364A0, struct_LogContext::AddTarget)
         *
         * What it does:
         * Asserts detached target state, allocates one intrusive target node,
         * and appends it into the global log-target ring.
         */
        void AddTarget(LogTarget* target);

        /**
         * Address: 0x00936570 (FUN_00936570, struct_LogContext::RemoveTarget)
         *
         * What it does:
         * Detaches one target node from the global log-target ring, or marks
         * pending removal when dispatch is currently inside that target.
         */
        void RemoveTarget(LogTarget* target);

        /**
         * Address: 0x00937640 (FUN_00937640, gpg::LogContext::push)
         *
         * What it does:
         * Captures one thread-local context snapshot and dispatches the message
         * to each registered log target, honoring one-shot flush and pending
         * detach flags.
         */
        void Dispatch(LogSeverity level, const msvc8::string& msg);
    };

    /**
     * RAII scope that pushes one thread-local logging context label for nested logs.
     */
    class ScopedLogContext
    {
    public:
        explicit ScopedLogContext(const msvc8::string& text);
        explicit ScopedLogContext(const char* text);
        ~ScopedLogContext();

        ScopedLogContext(const ScopedLogContext&) = delete;
        ScopedLogContext& operator=(const ScopedLogContext&) = delete;

    private:
        ThreadState* mTls{};
        ThreadCtxEntry* mEntry{};
    };

    /**
     * Globals (mirror original dword_*).
     */
    inline LogContext* g_LogCtx = nullptr;
    inline std::once_flag g_LogOnce;

    /**
     * Address: 0x00937AD0 (FUN_00937AD0, func_Init_LogContext)
     *
     * What it does:
     * Allocates the global log-context singleton and registers one process-exit
     * handler that destroys it.
     */
    void InitLogContextSingleton();

    /**
     * One-time initializer for logging singleton.
     */
    inline void InitLogSingleton()
    {
        InitLogContextSingleton();
    }

    /**
     * Address: 0x00937C00 (FUN_00937C00, gpg::LogMessage)
     *
     * What it does:
     * Dispatches one preformatted log line at a requested severity.
     */
    void LogMessage(LogSeverity level, const msvc8::string& message);

    // ReSharper disable once IdentifierTypo
    /**
     * Printf-style logging helper (info severity).
     * Builds a formatted string and dispatches it to registered targets.
     * Address: 0x00937CB0 (FUN_00937CB0)
     *
     * @param fmt Format string
     * @param ... Arguments
     */
    void Logf(const char* fmt, ...);

    // ReSharper disable once IdentifierTypo
    /**
     * Printf-style logging helper (warning severity).
     * Builds a formatted string and dispatches it to registered targets.
     * Address: 0x00937D30 (FUN_00937D30)
     *
     * @param fmt Format string
     * @param ... Arguments
     */
    void Warnf(const char* fmt, ...);

    // ReSharper disable once IdentifierTypo
    /**
     * Printf-style logging helper (debug severity).
     * Builds a formatted string and dispatches it to registered targets.
     * Address: 0x00937C30 (FUN_00937C30)
     *
     * @param fmt Format string
     * @param ... Arguments
     */
    void Debugf(const char* fmt, ...);

    /**
     * Address: 0x008E4A40 (?EnableLogHistory@gpg@@YAXH@Z)
     *
     * What it does:
     * Enables bounded in-memory log history with a maximum retained message count.
     */
    void EnableLogHistory(int maxEntries);

    /**
     * Address: 0x008E4F20 (FUN_008E4F20, gpg::ReplayLogHistory)
     *
     * What it does:
     * Replays retained log-history entries into a caller-supplied target.
     */
    bool ReplayLogHistory(LogTarget* target);

    /**
     * What it does:
     * Returns the currently retained in-memory log history as a newline-delimited
     * UTF-8 text blob.
     */
    msvc8::string GetRecentLogLines();

    FILETIME FileTimeLocal();

    /**
     * Address: 0x00485CB0 (FUN_00485CB0, func_FileTimeToString)
     *
     * What it does:
     * Converts microsecond timestamp to local `HH:MM:SS.mmm` text.
     */
    msvc8::string FileTimeToString(LONGLONG time);

    /**
     * Global state backing nested log-scope indentation. `g_LogScopeDepth`
     * tracks the current scope depth; `g_LogScopeDepthScale` is the per-level
     * width multiplier; `g_LogScopePadding` is refreshed to a spaces-only
     * string of `depth * scale` characters whenever the depth changes.
     *
     * Binary data lanes:
     *   g_LogScopeDepth        orig: dword_10A6630
     *   g_LogScopeDepthScale   orig: dword_10A6634
     *   g_LogScopePadding      orig: stru_10A6614
     */
    extern int g_LogScopeDepth;
    extern int g_LogScopeDepthScale;
    extern msvc8::string g_LogScopePadding;

    /**
     * Address: 0x00406110 (FUN_00406110, sub_406110)
     *
     * What it does:
     * Increments the global log-scope depth counter, rebuilds
     * `g_LogScopePadding` to `depth * scale` space characters, and returns
     * a pointer to the refreshed global padding string.
     */
    msvc8::string* IncreaseLogScopeDepth();

    /**
     * Address: 0x004061B0 (FUN_004061B0, sub_4061B0)
     *
     * What it does:
     * Mirror of `IncreaseLogScopeDepth`: decrements the global depth
     * counter, refreshes the shared padding string, and returns the
     * global padding pointer.
     */
    msvc8::string* DecreaseLogScopeDepth();

    /**
     * Binary identity: `class gpg::StrArg` (mangled `VStrArg@gpg`).
     *
     * RAII-style helper used by subsystem init paths to emit an indented
     * log line on scope exit. The constructor copies a format string into
     * an embedded `msvc8::string` and bumps the global log-scope depth;
     * `Emit` formats the stored body with the current scope width and
     * dispatches it through `gpg::LogMessage` at the stored severity,
     * then resets the embedded body string.
     *
     * Named by behavior rather than by the binary symbol because the
     * simple API-level alias `gpg::StrArg = const char*` already occupies
     * that identifier elsewhere in this SDK.
     *
     * Layout is partial: the fields at `+0x38` and `+0x50` are read by
     * the recovered emit path but initialized externally by callers that
     * have not yet been recovered. Intermediate slabs are kept as opaque
     * byte arrays so the proven offsets stay binary-accurate. No size
     * assertion is added because the complete-object size upper bound is
     * not yet confirmed.
     */
    class LogScopeEntry
    {
    public:
        /**
         * Address: 0x00406280 (FUN_00406280, ??0StrArg@gpg@@QAE@@Z)
         * Mangled: gpg::StrArg::StrArg
         *
         * What it does:
         * Initializes the embedded body string to empty SSO state,
         * assigns the full contents of `fmt` into the body, zeroes the
         * severity lane, and bumps the global log-scope depth through
         * `IncreaseLogScopeDepth`.
         */
        explicit LogScopeEntry(const msvc8::string& fmt);

        /**
         * Address: 0x004062E0 (FUN_004062E0, func_Log)
         *
         * What it does:
         * Decrements the global log-scope depth, formats the stored body
         * string with `gpg::STR_Printf` using an integer width argument
         * derived from `field_0x38`, dispatches the formatted line
         * through `gpg::LogMessage` at the stored severity, and resets
         * the embedded body string to empty SSO state.
         */
        void Emit();

        LogScopeEntry(const LogScopeEntry&) = delete;
        LogScopeEntry& operator=(const LogScopeEntry&) = delete;

        // +0x00 .. +0x1C
        msvc8::string body{};
        // +0x1C .. +0x38 - unproven 28-byte slab kept opaque so the
        // known offsets of later fields stay binary-accurate.
        std::array<std::byte, 0x1C> aux_0x1C{};
        // +0x38 - loaded by Emit() as the subtrahend when computing the
        // STR_Printf width argument (`eax = 0 - [esi+38h]`). Left
        // zero-initialized; real value is set externally by callers
        // that have not yet been recovered.
        std::uint32_t field_0x38{};
        // +0x3C .. +0x50 - unproven 20-byte slab kept opaque.
        std::array<std::byte, 0x14> pad_0x3C{};
        // +0x50 - log severity consumed by Emit(). The constructor
        // zeroes this lane; callers set it before invoking Emit().
        LogSeverity severity{LogSeverity::Debug};
    };
    static_assert(offsetof(LogScopeEntry, body) == 0x00,
        "LogScopeEntry body must live at +0x00");
    static_assert(offsetof(LogScopeEntry, field_0x38) == 0x38,
        "LogScopeEntry field_0x38 must live at +0x38");
    static_assert(offsetof(LogScopeEntry, severity) == 0x50,
        "LogScopeEntry severity must live at +0x50");
} // namespace gpg

