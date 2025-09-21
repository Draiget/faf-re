#pragma once

#include <memory>
#include "boost/function.h"
#include "moho/collision/AABB.h"

namespace moho
{
	/**
	 * Exact mask used by FA (MSVC8 era): THREAD_ALL_ACCESS
	 */
	constexpr DWORD kThreadAccessFa =
		STANDARD_RIGHTS_REQUIRED   // 0x000F0000
		| SYNCHRONIZE              // 0x00100000
		| 0x000003FF;              // thread-specific rights bits [0..9]

	/**
	 * Address: 0x100119F0
	 *
	 * @return 
	 */
	void THREAD_InitInvoke();

	/**
	 * Address: 0x10011A00
	 *
	 * @return 
	 */
	bool THREAD_IsMainThread();

	/**
	 * Address: 0x10011A20
	 *
	 * @return 
	 */
	uint32_t THREAD_GetMainThreadId();

	/**
	 * Address: 0x10011AC0
	 *
	 * @param function 
	 * @param threadId 
	 * @return 
	 */
	void THREAD_InvokeAsync(const boost::function<void(), std::allocator<void>>& fn, uint32_t threadId);

	/**
	 * Address: 0x10011BA0
	 *
	 * @param function 
	 * @param threadId 
	 * @return 
	 */
	void THREAD_InvokeWait(const boost::function<void(), std::allocator<void>>& fn, uint32_t threadId);

	/**
	 * Address: 0x10012100
	 *
	 * @return 
	 */
	void THREAD_SetAffinity(bool preferLowest) noexcept;

	/**
     * Small payload that will live in a 32-byte box.
     * Must fit into 32 bytes to mimic the observed allocation size.
     */
	struct InvokePayload
	{
		boost::function<void()> fn;
	};
	static_assert(sizeof(InvokePayload) <= 32, "InvokePayload must fit into 32 bytes (box size)");

    /**
     * Minimal wait context mirroring sub_104DB6C0/7F0/790 trio.
     */
    struct WaitCtx
    {
        HANDLE evt{ nullptr };

        /**
         * Initialize context (asm passes '2'; ignored here, kept for parity).
         */
        void begin(int /*mode*/) noexcept {
            // Auto-reset, initially non-signaled
            evt = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
        }

        /**
         * Alertable wait until signaled by the APC side.
         */
        void block() noexcept {
            if (!evt) return;
            ::WaitForSingleObjectEx(evt, INFINITE, TRUE);
        }

        /**
         * Signal completion from APC.
         */
        void signal() noexcept {
            if (evt) ::SetEvent(evt);
        }

        /**
         * Cleanup.
         */
        void end() noexcept {
            if (evt) { ::CloseHandle(evt); evt = nullptr; }
        }
    };

    /**
     * APC thunk: run payload->fn(), signal waiter (if any), destroy heap blocks.
     */
	VOID CALLBACK pfnAPC(ULONG_PTR dwData);

    /**
     * Resolve TID like the binary: given threadId or global, else current.
     */
	DWORD ResolveTid(std::uint32_t threadId) noexcept;
}
