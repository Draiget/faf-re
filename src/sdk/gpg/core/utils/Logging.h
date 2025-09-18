#pragma once
#include <span>

#include "Sync.h"
#include "Tss.h"
#include "legacy/containers/String.h"

namespace gpg
{
    /**
     * Severity levels mapped to original call sites.
     */
    enum : int {
        kDebug = 0,
        kInfo = 1,
        kWarn = 2,
    };

    /**
     * Log target interface (sink).
     */
    struct ILogTarget
	{
        virtual ~ILogTarget() = default;
        /**
         * Receive a log message with thread-context snapshot.
         */
        virtual void OnLog(int level,
            const msvc8::string& msg,
            std::span<const msvc8::string> ctx,
            int prev_depth
        ) = 0;
    };

    /**
     * Intrusive list node for targets (layout mirrors reverse engineered one).
     */
    struct LogTargetNode {
        LogTargetNode* prev{ this };
        LogTargetNode* next{ this };
        ILogTarget* obj{ nullptr };
        uint8_t        flushOnce{ 0 };       // if set, pass prev_depth=0 once
        uint8_t        busy{ 0 };            // reentrancy guard
        uint8_t        pendingRemove{ 0 };   // remove after call
        uint8_t        pad{ 0 };
    };

    /**
     * Thread-local entry holding a prefix text (shape inferred).
     */
    struct ThreadCtxEntry {
        void* reserved{};   // +0x00
        msvc8::string  text;         // +0x04
    };

    /**
     * Thread-local state, stored in TSS.
     */
    struct ThreadState {
        ThreadCtxEntry** begin{};    // +0x04
        ThreadCtxEntry** end{};      // +0x08
        ThreadCtxEntry** cap{};      // +0x0C
        std::uint32_t    depthCache{}; // +0x10
    };

    /**
     * Global logging context singleton (size 0x1C)
     */
    struct LogContext {
        core::TssPtr<ThreadState> tss; // +0x00 (accessed via boost::detail::tss::get)
        core::SharedLock rw;           // +0x04
        LogTargetNode head;            // sentinel at +0x14 (prev/next form a ring)
        ThreadState* lastTls;          // +0x18

        /**
         * Dispatch formatted message to targets with TLS snapshot
         */
        void Dispatch(int level, const msvc8::string& msg);
    };

    /**
     * Globals (mirror original dword_*).
     */
    inline LogContext* g_LogCtx = nullptr; // dword_F8EBC0
    inline std::once_flag g_LogOnce;       // dword_F8EBBC (binary layout of once_flag)

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

    // ReSharper disable once IdentifierTypo
    /**
     * Printf-style logging helper (info  severity).
     * Builds a formatted string and dispatches it to registered targets.
     * Address: 0x00937CB0
     *
     * @param fmt Format string
     * @param ... Arguments
     */
    void Logf(const char* fmt, ...);

    // ReSharper disable once IdentifierTypo
    /**
     * Printf-style logging helper (warning severity).
     * Builds a formatted string and dispatches it to registered targets.
     * Address: 0x00937D30
     *
     * @param fmt Format string
     * @param ... Arguments
     */
    void Warnf(const char* fmt, ...);

    // ReSharper disable once IdentifierTypo
    /**
     * Printf-style logging helper (debug severity).
     * Builds a formatted string and dispatches it to registered targets.
     * Address: 0x00937C30
     *
     * @param fmt Format string
     * @param ... Arguments
     */
    void Debugf(const char* fmt, ...);

    msvc8::string FileTimeToString(FILETIME time);
}
