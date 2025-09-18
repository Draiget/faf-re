#pragma once

#include <string>

#include "IMessageReceiver.h"
#include "legacy/containers/String.h"

namespace moho
{
    struct NetDataSpan
    {
        uint8_t* start;
        uint8_t* end;
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
	};
}
