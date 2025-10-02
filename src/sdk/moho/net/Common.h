#pragma once

#include <algorithm>

#include "INetNATTraversalProvider.h"
#include "boost/weak_ptr.h"
#include "platform/Platform.h"
#include "gpg/core/time/Timer.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
	class INetConnector;
	struct CHostManager;

    enum ENetConnectionState
    {
        kNetStatePending = 0,
        kNetStateConnecting = 1,
        kNetStateAnswering = 2,
        kNetStateEstablishing = 3,
        kNetStateTimedOut = 4,
        kNetStateErrored = 5,
    };

    enum EPacketState : uint8_t
    {
        CONNECT = 0,
        ANSWER = 1,
        RESETSERIAL = 2,
        SERIALRESET = 3,
        DATA = 4,
        ACK = 5,
        KEEPALIVE = 6,
        GOODBYE = 7,
        NATTRAVERSAL = 8,
    };

    void NetPacketStateToStr(EPacketState state, msvc8::string& out);
    const char* NetConnectionStateToStr(ENetConnectionState state);

    enum ENetCompressionMethod : uint8_t
    {
        NETCOMP_None = 0,
        NETCOMP_Deflate = 1,
    };

    enum class ENetProtocolType : int32_t
    {
        kNone = 0,
        kTcp = 1, // guess
        kUdp = 2  // confirmed by GetType()
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

    struct SSendStamp
    {
        uint32_t direction;
        uint32_t v1;
        uint64_t time; // used as 64-bit tick container in the binary
        uint32_t size;
        uint32_t v4;
    };

    struct SSendStampView
    {
        msvc8::vector<SSendStamp> items; // contiguous vector of copies
        uint64_t from;                  // threshold = now - window
        uint64_t to;                    // now

        /**
         * Address: 0x0047D1D0
         * NOTE: Inlined
         *
         * @param start 
         * @param end 
         */
        SSendStampView(const uint64_t start, const uint64_t end) :
            items{},
            from{ start },
            to{ end }
        {
        }
    };

    struct SSendStampBuffer
    {
        static constexpr uint32_t cap = 4096;

        SSendStamp mDat[cap];
        uint32_t mEnd = 0; // oldest
        uint32_t mStart = 0; // next write

        /**
         * Address: 0x0047D110
         *
         * lower-bound in circular buffer, copy window into out
         */
        SSendStampView GetBetween(uint64_t startTime, uint64_t endTime);

        /**
         * Address: 0x0047D990
         */
        void Reset();

        /**
         * Address: 0x0047D0A0
         */
        uint32_t Push(int dir, LONGLONG timeUs, int size) noexcept;

        /**
         * Address: 0x0047D0A0
         */
        void Add(int direction, LONGLONG time, int size);

        /**
         * Address: 0x0047D630
         */
        void Append(const SSendStamp* s);

        [[nodiscard]]
        bool empty() const noexcept {
            return mStart == mEnd;
        }

        [[nodiscard]]
        uint32_t size() const noexcept {
            return mStart - mEnd & cap; // valid for power-of-two capacity
        }

        void push(const SSendStamp& s) noexcept {
            mDat[mStart] = s;
            mStart = mStart + 1 & cap;
            if (mStart == mEnd) {
                mEnd = mEnd + 1 & cap;
            }
        }

        SSendStamp& Get(const size_t index) {
            return mDat[(mStart + index) % 4096];
        }

    private:
        /**
         * Place entry at mStart and advance mStart by 1 (mod 4096).
         * Address: 0x0047D630
         */
        MOHO_FORCEINLINE uint32_t EmplaceAndAdvance(const SSendStamp& s) noexcept
        {
            mDat[mStart] = s;
            mStart = (mStart + 1u) & cap;
            return mStart;
        }
    };

    /**
     * Address: 0x0047F5A0
     */
    bool NET_Init();

    /**
     * Address: 0x0047F990
     */
    CHostManager* NET_GetHostManager();

	/**
	 * Address: 0x0047FEE0
	 */
	msvc8::string NET_GetHostName(u_long address);

    /**
     * Address: 0x0047F5F0
     * Render getnameinfo/gai/WSA error to string for logs.
     *
     * @return
     */
    MOHO_FORCEINLINE const char* NET_GetWinsockErrorString() noexcept;

    /**
     * Address: 0x004801C0
     * @param number 
     * @return 
     */
    MOHO_FORCEINLINE msvc8::string NET_GetDottedOctetFromUInt32(uint32_t number);

    /**
     * Address: 0x0047ED50
     *
     * @param str 
     * @return 
     */
    ENetProtocolType NET_ProtocolFromString(const char* str);

    /**
     * Address: 0x0048BBE0
     */
    INetConnector* NET_MakeUDPConnector(u_short port, boost::weak_ptr<INetNATTraversalProvider> prov);
}
