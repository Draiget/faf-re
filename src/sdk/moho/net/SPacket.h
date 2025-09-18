#pragma once

#include "General.h"
#include "legacy/containers/String.h"
#include "moho/misc/TDatList.h"

namespace moho
{
    struct SPacket;

#pragma pack(push, 4)

	struct SPacketHeader
	{
        TDatList<SPacket, void> mList;
		int64_t mSentTime;
        int32_t mResendCount;
        int32_t mSize;
	};

    struct SPacketData
    {
        EPacketState mState;
        uint32_t mEarlyMask;
        uint16_t mSerialNumber;
        uint16_t mInResponseTo;
        uint16_t mSequenceNumber;
        uint16_t mExpectedSequenceNumber;
        uint16_t mPayloadLength;
        int32_t mVar;
        int64_t mTime;
        ENetCompressionMethod mCompMethod;
        char mDat1[32];
        char mDat2[32];
        char gap[412];
    };
    static_assert(sizeof(SPacketData) == 0x200, "SPacketData must be 0x34");

	struct SPacket : SPacketHeader, SPacketData
	{
        /**
         * Address: 0x00488BC0
         */
		[[nodiscard]]
		msvc8::string ToString() const;
	};
#pragma pack(pop)
}
