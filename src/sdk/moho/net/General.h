#pragma once

#include <algorithm>
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

    enum EPacketState : uint8_t
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

    enum ENetCompressionMethod : uint8_t
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

        NetSpeeds() : vals{}, v1{ 0 }, head{ 0 }, tail{ 0 } {}

        ~NetSpeeds() = default;

        MOHO_FORCEINLINE int Append(const float sample) noexcept {
            // next position after current tail
            const int next = (tail + 1) % 25;

            // if full (next would collide with head) - drop oldest by advancing head
            if (next == head) {
                head = (head + 1) % 25;
            }

            // write sample at current tail
            vals[tail] = sample;

            // return 1 if we wrapped, 0 otherwise (matches (tail+1)/25 from binary)
            const int wrapped = (tail + 1) / 25;

            // advance tail
            tail = next;

            return wrapped;
        }

        MOHO_FORCEINLINE float Median() const noexcept {
            // gather values from `head <-> tail` into a small stack array
            float tmp[25];
            int i = 0;
            int h = head;
            const int t = tail;

            while (h != t) {
                tmp[i++] = vals[h];
                h = (h + 1) % 25;
            }

            if (i == 0) {
                return 0.0f;
            }

            std::sort(tmp, tmp + i);
            return tmp[i / 2];
        }

        MOHO_FORCEINLINE float Jitter(const float center) const noexcept {
            float tmp[25];
            int i = 0;
            int h = head;
            const int t = tail;

            while (h != t) {
                tmp[i++] = std::fabs(vals[h] - center);
                h = (h + 1) % 25;
            }

            if (i == 0) {
                return 0.0f;
            }

            std::sort(tmp, tmp + i);
            return tmp[i / 2];
        }
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
