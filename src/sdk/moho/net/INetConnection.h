#pragma once

#include "IMessageReceiver.h"
#include "legacy/containers/String.h"

namespace moho
{
    class CMessageStream;

    struct NetDataSpan
    {
        uint8_t* start;
        uint8_t* end;

        /**
         * Construct from raw pointers.
         */
        NetDataSpan(uint8_t* b, uint8_t* e) noexcept
            : start(b), end(e) {
        }

        /**
         * Construct from CMessageStream using its write window [mWriteStart, mWriteEnd).
         */
        explicit NetDataSpan(const CMessageStream& s) noexcept;

        /**
         * Size in bytes.
         */
        [[nodiscard]]
    	size_t size() const noexcept { return static_cast<size_t>(end - start); }

        /**
         * Address: 0x00000000
         * Data pointer.
         */
        [[nodiscard]]
        uint8_t* data() const noexcept { return start; }
    };

	/**
     * VFTABLE: 0x00E0499C
     * COL:     0x00E60C88
     */
	class INetConnection : public CMessageDispatcher
	{
	public:
        /**
         * Address: 0x00A82547
         * Slot: 0
         */
        virtual u_long GetAddr() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 1
         */
        virtual u_short GetPort() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 2
         */
        virtual float GetPing() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 3
         */
        virtual float GetTime() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 4
         */
        virtual void Write(NetDataSpan* data) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 5
         */
        virtual void Close() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 6
         */
        virtual msvc8::string ToString() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 7
         */
        virtual void ScheduleDestroy() = 0;

        /**
         * Convenience overload: write from CMessageStream written window.
         * Does not change vtable; just forwards to the virtual Write(NetDataSpan*).
         */
        void Write(const CMessageStream& stream) {
            // [mWriteStart, mWriteHead)
            NetDataSpan tmp(stream);     
            // forwarded to engine virtual
            Write(&tmp);           
        }
	};
}
