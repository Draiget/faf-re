#pragma once

#include <map>

#include "boost/Mutex.h"
#include "gpg/core/time/Timer.h"
#include "platform/Platform.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/TDatList.h"

namespace moho
{
    struct CHostManager;

    enum class ENetConnectionState
    {
        Pending = 0,
        Connecting = 1,
        Answering = 2,
        Establishing = 3,
        TimedOut = 4,
        Errored = 5,
    };

    enum EPacketState
    {
        CONNECT,
        ANSWER,
        RESETSERIAL,
        SERIALRESET,
        DATA,
        ACK,
        KEEPALIVE,
        GOODBYE,
        NATTRAVERSAL,
    };

    enum ENetCompressionMethod : int32_t
    {
        NETCOMP_None = 0,
        NETCOMP_Deflate = 1,
    };

    enum class ENetProtocolType : int32_t
    {
        TCP = 1, // guess
        UDP = 2  // confirmed by GetType()
    };

    struct NetPacketTime
    {
        unsigned short mSource;
        gpg::time::Timer mTime;
    };

    struct NetSpeeds
    {
        float vals[25];
        int v1;
        int head;
        int tail;

        ~NetSpeeds(){}
    };

    struct SendStamp
    {
        uint32_t v0;
        uint32_t v1;
        FILETIME when; // used as 64-bit tick container in the binary
        uint32_t size;
        uint32_t v4;
    };

    struct SendStampView
    {
        msvc8::vector<SendStamp> items; // contiguous vector of copies
        FILETIME from;                  // threshold = now - window
        FILETIME to;                    // now
    };

    struct SendStampBuffer
    {
        static constexpr uint32_t kCap = 4096;
        static constexpr uint32_t kMask = kCap - 1;

        SendStamp mDat[kCap];
        int mEnd = 0; // oldest
        int mStart = 0; // next write

        /**
         * Address: 0x0047D110
         *
         * lower-bound in circular buffer, copy window into out
         */
        void ExtractWindow(SendStampView& out, uint64_t now, uint64_t window) const;

        /**
         * Address: 0x0047D990
         */
        void Reset();

        [[nodiscard]]
        bool empty() const noexcept {
            return mStart == mEnd;
        }

        [[nodiscard]]
        uint32_t size() const noexcept {
            return mStart - mEnd & kMask; // valid for power-of-two capacity
        }

        void push(const SendStamp& s) noexcept {
            mDat[mStart] = s;
            mStart = mStart + 1 & kMask;
            if (mStart == mEnd) {
                mEnd = mEnd + 1 & kMask;
            }
        }
    };
    
    /**
     * Address: 0x0047F990
     */
    CHostManager* NET_GetHostManager();

	/**
	 * Address: 0x0047FEE0
	 */
	msvc8::string NET_GetHostName(u_long address);
}
