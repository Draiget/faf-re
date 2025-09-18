#pragma once

#include "legacy/containers/String.h"

namespace moho
{
	struct SPacket;

	struct SPacketHeader
	{
        TDatList<SPacket, void> mList;
		int64_t mSentTime;
		int mResendCount;
		int mSize;
	};

    struct SPacketData
    {
        char mState;
        int mEarlyMask;
        uint16_t mSerialNumber;
        uint16_t mInResponseTo;
        uint16_t mSequenceNumber;
        uint16_t mExpectedSequenceNumber;
        uint16_t mPayloadLength;
        int mVar;
        int64_t mTime;
        char mCompMethod;
        char mDat1[32];
        char mDat2[32];
        char gap[420]; // until size is 0x200
    };

	struct SPacket : SPacketHeader, SPacketData
	{
		msvc8::string ToString(); // 0x00488BC0
	};
}
