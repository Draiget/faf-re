#pragma once
#include <cstdint>
#include "../../gpg/core/utils/Sync.h"

namespace moho
{
    /**
	 * Lightweight event slot used at offset +0x74.
	 * In the binary it is signaled via sub_AC22F0(&slot) and never ResetEvent()'ed here.
	 * Treat it as an auto-reset "notify" event: one waiter wakes per signal.
	 */
    struct EventSlot {
#if defined(_WIN32)
        // Auto-reset event handle created elsewhere (engine owns lifetime).
        HANDLE h{ nullptr };

        /** Signal/wake one waiter (maps to SetEvent). */
        void signal() { if (h) ::SetEvent(h); }

        /** Optional: explicit reset if engine wants to clear it. */
        void reset() { if (h) ::ResetEvent(h); }
#else
        // Portable fallback: auto-reset semantics using a flag + mutex + condvar.
        std::mutex              m;
        std::condition_variable cv;
        bool                    signaled{ false };

        void signal() {
            std::lock_guard<std::mutex> lk(m);
            signaled = true;
            cv.notify_one();
        }
        void reset() {
            std::lock_guard<std::mutex> lk(m);
            signaled = false;
        }
#endif
    };

    /** Driver operating mode mirrored from +0x8C. */
    enum class ISTIMode : int32_t {
        kUnknown = 0,
        kStage1 = 1,
        kStage2 = 2,
        kStop4 = 4,   // observed terminal states
        kStop5 = 5,
    };

	class ISTIDriver
	{
        // Primary vftable (40 entries)
	public:
        /**
         * Scalar deleting destructor thunk.
         * Calls real dtor, then frees memory when requested.
         *
         * Address: 0x0073B910
         * VFTable SLOT: ~0
         */
        virtual ~ISTIDriver() = default;

        /**
         * Prime backend once under lock (+0x30): backend->vfunc(+0x68),
         * init first stamp at [+0x60] and SetEvent(@+0x48+24).
         *
         * Address: 0x73BBF0
         * VFTable SLOT: 1
         */
        virtual void PrimeBackendOnce() = 0;

        /**
         * Graceful shutdown: stop worker A (flag @+0x58, SetEvent @+0x48+24),
         * stop worker B (flag @+0x70, signal @+0x74),
         * wait Mode!=3/4/5 as observed, join/free resources.
         *
         * Address: 0x73BC80
         * VFTable SLOT: 2
         */
        virtual void Shutdown() = 0;

        /**
         * Returns raw backend pointer stored at [+0x08].
         *
         * Address: 0x73B190
         * VFTable SLOT: 3
         */
        virtual void* GetBackendRaw() const = 0;

        virtual void sub_73BDE0() = 0; // 0x73BDE0 (slot 4)

        /**
         * Pump/tick: deliver pending message to listener, recompute active flag,
         * run small state machine over Mode, signal @+0x74 on transitions.
         *
         * Address: 0x73C250
         * VFTable SLOT: 5
         */
        virtual void Pump() = 0;

        virtual void sub_73C410() = 0; // 0x73C410 (slot 6)
        virtual void sub_73C440() = 0; // 0x73C440 (slot 7)

        /**
         * Under lock (+0x30), returns (dword@+0xA0)!=0 - pending items/queue non-empty flag.
         *
         * Address: 0x73C4F0
         * VFTable SLOT: 8
         */
        virtual bool HasPendingItems() const = 0;

        /**
         * Dequeue one item (waits until +0xA0!=0), writes first dword of item
         * into [+0x1C], stamps [+0x60] and SetEvent(@+0x48+24);
         * ResetEvent(@+0xA4) if queue became empty.
         * Returns item pointer
         *
         * Address: 0x73C520
         * VFTable SLOT: 9
         */
        virtual void* DequeueOne() = 0;

        /**
         * Returns HANDLE/event stored at [+0xA4] (items-available event).
         *
         * Address: 0x73B1A0
         * VFTable SLOT: 10
         */
        virtual void* GetItemsEventHandle() const = 0;

        /**
         * Returns 0.0 (stub metric).
         *
         * Address: 0x73C630
         * VFTable SLOT: 11
         */
        virtual double GetZeroMetric() const = 0;

        /**
         * Set param at [+0xB0]; if first time-stamp at [+0x60] is zero,
         * stamp it and SetEvent(@+0x48+24).
         *
         * Address: 0x73B1B0
         * VFTable SLOT: 12
         */
        virtual void SetParamB0(int value) = 0;

        /**
         * Validate that local 712-byte records ring matches external snapshot;
         * otherwise resync/flush (sub_73F630).
         *
         * Address: 0x73B270
         * VFTable SLOT: 13
         */
        virtual bool ValidateSnapshot(const void* extBegin, const void* extEnd) = 0;

        /**
         * Fast-path submit (sub_401C50) under lock (+0x30). Frees a6 if it differs from a9.
         *
         * Address: 0x73B3F0
         * VFTable SLOT: 14
         */
        virtual void SubmitFast(void* a6, void* a9) = 0;

        /**
         * Slow-path submit if fast path fails: store a4 at [+0x100],
         * queue payload via sub_4028E0(&a6).
         * Frees a6 if it differs from a9.
         *
         * Address: 0x73B4B0
         * VFTable SLOT: 15
         */
        virtual void SubmitSlow(int a4, void* a6, void* a9) = 0;

        /**
         * Set single byte flag at [+0xF0] under lock (+0x30).
         *
         * Address: 0x73B240
         * VFTable SLOT: 16
         */
        virtual void SetFlagF0(uint8_t v) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+12) 'kick';
         * if first stamp empty, stamp [+0x60] and SetEvent(@+0x48+24).
         * Returns dword at [+0x24].
         *
         * Address: 0x73C660
         * VFTable SLOT: 17
         */
        virtual uint32_t Stream_KickAndGet() = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+16).
         * Stamps & signals as above.
         * Returns dword at [+0x24].
         *
         * Address: 0x73C700
         * VFTable SLOT: 18
         */
        virtual uint32_t Stream_Cmd16() = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+20).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73C7A0
         * VFTable SLOT: 19
         */
        virtual uint32_t Stream_Cmd20() = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+24)(a3,a4,a5,a6).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73C840
         * VFTable SLOT: 20
         */
        virtual uint32_t Stream_Cmd24(int a3, int a4, int a5, float a6) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+28)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73C8F0
         * VFTable SLOT: 21
         */
        virtual uint32_t Stream_Cmd28(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+32)(a3).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73C990
         * VFTable SLOT: 22
         */
        virtual uint32_t Stream_Cmd32(int a3) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+36)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CA30
         * VFTable SLOT: 23
         */
        virtual uint32_t Stream_Cmd36(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+40)(a3,a4,a5).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CAD0
         * VFTable SLOT: 24
         */
        virtual uint32_t Stream_Cmd40(int a3, int a4, int a5) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+44)(a3,a4,a5).
         * Does NOT stamp/signal.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CB70
         * VFTable SLOT: 25
         */
        virtual uint32_t Stream_Cmd44(int a3, int a4, int a5) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+48)(a3,a4,a5).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CC10
         * VFTable SLOT: 26
         */
        virtual uint32_t Stream_Cmd48(int a3, int a4, int a5) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+52)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CCB0
         * VFTable SLOT: 27
         */
        virtual uint32_t Stream_Cmd52(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+56)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CD50
         * VFTable SLOT: 28
         */
        virtual uint32_t Stream_Cmd56(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+60)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CDF0
         * VFTable SLOT: 29
         */
        virtual uint32_t Stream_Cmd60(int a3, int a4) = 0;

        /**
         * In binary: sub_73CE90
         * Note: Forwards to internal stream @+0x28: vfunc(+64)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CE90
         * VFTable SLOT: 30
         */
        virtual uint32_t Stream_Cmd64(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+68)(a3,a4,a5).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CF30
         * VFTable SLOT: 31
         */
        virtual uint32_t Stream_Cmd68(int a3, int a4, int a5) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+72)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73CFD0
         * VFTable SLOT: 32
         */
        virtual uint32_t Stream_Cmd72(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+76)(a3,a4).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73D070
         * VFTable SLOT: 33
         */
        virtual uint32_t Stream_Cmd76(int a3, int a4) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+80)(a3,a4,a5).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73D110
         * VFTable SLOT: 34
         */
        virtual uint32_t Stream_Cmd80(int a3, int a4, int a5) = 0;

        /**
         * Forwards to internal stream @+0x28: vfunc(+84)(a3,a4,a5,a6).
         * Stamps & signals.
         * Returns dword at [+0x24].
         *
         * Address: 0x73D1B0
         * VFTable SLOT: 35
         */
        virtual uint32_t Stream_Cmd84(int a3, int a4, int a5, int a6) = 0;

        /**
         * Enter exclusive section for front-end:
         * ++holdCounter(@+0xAC);
         * set Active(@+0xA8)=1;
         * if Mode==3, spin/yield until leaves;
         * return handle at [+0x04].
         *
         * Address: 0x73DEA0
         * VFTable SLOT: 36
         */
        virtual void* EnterExclusiveAndGetHandle() = 0;

        /**
		 * Decrements the re-entrant hold counter at dword[43] (offset +0xAC).
		 * Counterpart to the "enter exclusive" path (sub_73DEA0).
		 * No locking, signaling or other side effects.
		 *
		 * Address: 0x73DF50
		 * VFTable SLOT: 37
		 */
        virtual void LeaveExclusive() = 0;

        /**
         * Under the command lock (+0x30 via sub_AC1AB0(this+12)), writes a new control/queued
         * parameter to dword[100] (offset +0x190), signals EventB at +0x74 (sub_AC22F0(this+29))
         * to wake the consumer/worker, and increments the revision counter dword[15] (offset +0x3C).
         *
         * Address: 0x73DF60
         * VFTable SLOT: 38
         */
        virtual void SetDesiredSpeed(int value) = 0;

        /**
         * Renders an on-screen debug overlay (font: "Courier New") with networking/simulation
         * statistics. Builds lines such as: "ping / maxsp / data / behind / avail",
         * "inflight: %d, available: %d, queued: %d",
         * "sim time: %.3f, max speed=%+d",
         * "desired speed: %+d, actual speed: %+d".
         * Queries runtime/back-end via the object at [+0x08], iterates per-connection data,
         * measures text, computes layout and draws using the engine's text APIs
         * (sub_4478C0/sub_4386A0/sub_426470, etc.). Uses a4/a5 as anchor (bottom-right)
         * and a6/a7 as scale for pixel-aligned placement (floor() snapping).
         * No persistent state changes.
         *
         * Address: 0x73DFE0
         * VFTable SLOT: 39
         */
        virtual void DrawNetSimOverlay(
            int pass, 
            int drawList,
            float anchorX, 
            float anchorY,
            float scaleX, 
            float scaleY
        ) = 0;

	private:
        // Offset: 0x04
        // Returned by sub_73DEA0; freed in shutdown path
        void* front_handle_;

        // Offset: 0x08
        // Backend object (vcall +0x68 etc.)
        void* backend_;

        // Offset: 0x0C
        // sub_AC1AB0/AC1AD0(this+0x0C) in queue/validation paths
        gpg::core::FastMutex lock_queue_;

        // Offset: 0x1C
        // First dword of dequeued item (set in sub_73C520)
        uint32_t last_dequeue_key_;

        // Offset: 0x20
        // Base index/pointer minus 1 (used in HUD math, sub_73DFE0)
        uint32_t inflight_base_m1_;

        // Offset: 0x24
        // Value read back by Stream_CmdXX wrappers
        uint32_t stream_ret_dword_;

        // Offset: 0x28
        // Object with dense vtable (+0x0C..+0x54, +0x48..+0x54)
        void* stream_obj_;

        // Offset: 0x30
        // Primary lock (Pump, Dequeue, most methods use this)
        gpg::core::FastMutex lock_main_;

        // Offset: 0x38
        // Worker A handle (start/stop/free in sub_73BC80)
        void* worker_a_;

        // Offset: 0x48
        // HANDLE used with SetEvent() after first-stamp
        void* event_kick_h_;

        // Offset: 0x50
        // Stamp set in sub_73C520 (low @0x50, high @0x54)
        uint64_t dequeue_stamp_;

        // Offset: 0x58
        // Stop flag for worker A
        uint8_t stop_a_;

        // Offset: 0x60
        // One-shot stamp written by sub_955700(this+0x40/0x64)
        uint64_t first_stamp_;

        // Offset: 0x6C
        // Worker B handle
        void* worker_b_;

        // Offset: 0x70
        // Stop flag for worker B
        uint8_t stop_b_;

        // Offset: 0x74
        // Signaled via sub_AC22F0(this+0x74)
        EventSlot event_b_;

        // Offset: 0x8C
        // State machine mode (seen: 1/2 working, 3 wait, 4/5 stopping)
        ISTIMode mode_;

        // Offset: 0xA0
        // Non-zero when queue has items (polled in sub_73C4F0/73C520)
        uint32_t queue_nonempty_;

        // Offset: 0xA4
        // HANDLE ResetEvent()'ed when queue becomes empty
        void* items_event_h_;

        // Offset: 0xA8
        // Activity flag (set in sub_73DEA0, maintained in Pump)
        uint8_t active_;

        // Offset: 0xAC
        // Re-entrant hold counter (++ in sub_73DEA0, -- in sub_73DF50)
        int32_t hold_counter_;

        // Offset: 0xB0
        // Control parameter (sub_73B1B0)
        int32_t param_b0_;

        // Offset: 0xB8
        // Begin of 712-byte records block (used in sub_73B270)
        uint8_t* rec_begin_;

        // Offset: 0xBC
        // End of 712-byte records block (used in sub_73B270)
        uint8_t* rec_end_;

        // Offset: 0xF0
        // Byte flag (set by sub_73B240)
        uint8_t flag_f0_;

        // Offset: 0x100
        // Stored by slow-path submit (sub_73B4B0: this[64]=a4)
        int32_t submit_code_;

        // Offset: 0x190
        // Union-like: message target in Pump / desired speed in sub_73DF60
        void* msg_target_or_speed_;

        // Offset: 0x194
        // Pending message flag for Pump
        uint8_t msg_has_pending_;

        // Offset: 0x198
        // Message type code for Pump
        uint8_t msg_type_;            

        // Offset: 0x19C
        // Message text pointer for Pump
        char* msg_text_;  
	};
}
