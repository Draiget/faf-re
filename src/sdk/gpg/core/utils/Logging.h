#pragma once
#include <cstddef>
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
         * Address: 0x00937ED0 (FUN_00937ED0)
         * Demangled: gpg::LogTarget deleting dtor thunk
         *
         * What it does:
         * Unregisters the target from global logging dispatch if currently attached.
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
        void Attach();
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
         * Address: 0x00906CA0 (FUN_00906CA0)
         * Demangled: gpg::StreamLogTarget deleting dtor thunk
         *
         * What it does:
         * Tears down owned stream (when flagged) and unregisters from logging dispatch.
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
         * Dispatch formatted message to targets with TLS snapshot.
         */
        void Dispatch(int level, const msvc8::string& msg);
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
     * One-time initializer for logging singleton.
     */
    inline void InitLogSingleton()
    {
        if (!g_LogCtx) {
            g_LogCtx = new LogContext();
            std::atexit([] {
                delete g_LogCtx;
                g_LogCtx = nullptr;
            });
        }
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
} // namespace gpg
