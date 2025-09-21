#pragma once
#include "INetConnection.h"
#include "INetConnector.h"
#include "SNetPacket.h"
#include "boost/weak_ptr.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/streams/ZLibOutputFilterStream.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/BoostUtils.h"
#include "legacy/containers/String.h"

namespace moho
{
	class INetNATTraversalProvider;
	// Forward declarations
    class CNetUDPConnector;

    static ENetCompressionMethod net_CompressionMethod = NETCOMP_Deflate;

	/**
     * VFTABLE: 0x00E06118
     * COL:  0x00E60D70
     */
	class CNetUDPConnection :
		public INetConnection,
        public TDatListItem<CNetUDPConnection, void>,
        public boost::noncopyable_::noncopyable
	{
    public:
        /**
	     * Address: 0x00485BE0
	     * Slot: 0
	     * Demangled: moho::CNetUDPConnection::GetAddr
	     */
        u_long GetAddr() override {
            return mAddr;
        }

        /**
         * Address: 0x00485BF0
         * Slot: 1
         * Demangled: moho::CNetUDPConnection::GetPort
         */
        uint16_t GetPort() override {
            return mPort;
        }

        /**
         * Address: 0x00489550
         * Slot: 2
         * Demangled: moho::CNetUDPConnection::GetPing
         */
        float GetPing() override;

        /**
         * Address: 0x00489590
         * Slot: 3
         * Demangled: moho::CNetUDPConnection::GetTime
         */
        float GetTime() override;

        /**
         * Address: 0x00489130
         * Slot: 4
         * Demangled: moho::CNetUDPConnection::Write
         */
        void Write(NetDataSpan* data) override;

        /**
         * Address: 0x004893F0
         * Slot: 5
         * Demangled: moho::CNetUDPConnection::Close
         */
        void Close() override;

        /**
         * Address: 0x004894C0
         * Slot: 6
         * Demangled: moho::CNetUDPConnection::ToString
         */
        msvc8::string ToString() override;

        /**
         * Address: 0x00489660
         * Slot: 7
         * Demangled: moho::CNetUDPConnection::ScheduleDestroy
         */
        void ScheduleDestroy() override;

        /**
         * Address: 0x00485D30
         */
        CNetUDPConnection(CNetUDPConnector& connector, u_long address, u_short port, ENetConnectionState state);

        /**
         * Address: 0x00486150
         */
        virtual ~CNetUDPConnection();

        /**
		 * Initialize receive-side filter stream according to compression method.
		 *
         * Address: 0x00486910
         */
        void CreateFilterStream();

        /**
         * Address: 0x00486380
         */
        bool ProcessConnect(const SNetPacket* pack);

        /**
         * Address: 0x004865E0
         */
        void ProcessAnswer(const SNetPacket* pack);

        /**
         * Address: 0x00486B10
         */
        bool ProcessAckInternal(const SNetPacket* packet);

        /**
         * Address: 0x00486DB0
         */
        void ProcessData(SNetPacket* packet);

        /**
         * Address: 0x00487310
         */
        bool ProcessAck(const SNetPacket* packet);

        /**
         * Address: 0x00487340
         */
        bool ProcessKeepAlive(const SNetPacket* packet);

        /**
         * Address: 0x00487370
         */
        bool ProcessGoodbye(const SNetPacket* packet);

        /**
         * Address: 0x00488170
         */
        int64_t CalcResendDelay(const SNetPacket* packet) const;

        /**
         * Address: 0x00488260
         */
        int GetBacklog(int64_t time);

        /**
         * Address: 0x004882C0
         */
        int GetBacklogTimeout(LONGLONG time, int32_t& timeout);

        /**
         * Address: 0x004881F0
         */
        int64_t TimeSince(int64_t time) const;

        /**
         * Address: 0x00488300
         */
        int64_t SendData();

        /**
         * Address: 00488145
         */
        template<class T>
        constexpr T ChooseTimeout(T cur, T candidate) {
            const T inf = static_cast<T>(-1);
            if (cur == inf) {
	            return candidate;
            }
            if (candidate == inf) {
	            return cur;
            }
            using U = std::make_unsigned_t<T>;
            return (static_cast<U>(candidate) >= static_cast<U>(cur)) ? cur : candidate;
        }

        /**
         * Address: 0x00488730
         */
        bool HasPacketWaiting(int64_t nowUs);

        /**
         * Address: 0x00488980
         */
        SNetPacket* ReadPacket();

        /**
         * Address: 0x00488810
         */
        [[nodiscard]]
		SNetPacket* NewConnectPacket() const;

        /**
         * Address: 0x004888C0
         */
        [[nodiscard]]
		SNetPacket* NewAnswerPacket() const;

        /**
         * Address: 0x00488AA0
         */
        [[nodiscard]]
		SNetPacket* NewGoodbyePacket() const;

        /**
         * Address: 0x00488B20
         */
        [[nodiscard]]
		SNetPacket* NewPacket(bool inherit, int size, EPacketState state) const;

        /**
         * Address: 0x00488D80
         */
        void SendPacket(SNetPacket* packet);

        /**
         * Address: 0x00487590
         */
        void FlushInput();

        /**
         * Address: 0x004879E0
         */
        bool FlushOutput();

        /**
         * Address: 0x004876A0
         */
        void DispatchFromInput();

        /**
         * Address: 0x00487B90
         */
        void Debug();

	private:
        /**
         * Address: 0x00488220
         */
        void AdoptPacket(const SNetPacket* packet);

        /**
         * Address: 0x004874C0
         */
        void UpdatePingInfoFromPacket(const SNetPacket& packet);

        MOHO_FORCEINLINE bool InsertEarlySorted(SNetPacket* packet);

        MOHO_FORCEINLINE SNetPacket* EarlyPopFront();

        MOHO_FORCEINLINE void EarlyRebuildAckMask(uint16_t expected, uint32_t& mask);

        MOHO_FORCEINLINE void ConsumePacketHeaderData(SNetPacket* packet);

        MOHO_FORCEINLINE void InsertUnAckedSorted(SNetPacket* packet);
	public:
        // ...
        // +0x410  ListEntry linkInConnector
        // +0x42C  uint32_t state            // 0=Idle, 1=Init, 2=Active, 3=Closing?, 5=Retired
        // +0xE40  uint8_t  flagBusy         // used as "not busy" filter
        // +0xE41  uint8_t  flagDeleteNow    // immediate shutdown signal/flag
        // vtable[0]: uint32_t RemoteAddrBE() const
        // vtable[1]: uint16_t RemotePort()  const
        // vtable[7]: void CloseOrRelease()

        CNetUDPConnector* mConnector;
        u_long mAddr;
        u_short mPort;
        WORD gap1;
        ENetCompressionMethod mOurCompressionMethod;
        int mReceivedCompressionMethod;
        ENetConnectionState mState;
        gpg::time::Timer mLastSend;
        int64_t mSendTime;
        int64_t mLastRecv;
        int64_t mLastKeepAlive;
        uint32_t mKeepAliveFreqUs{ 2'000'000 }; // set to 0x1E8480 (~2s)
        char mNonceA[32];
        char mNonceB[32];
        int v293;
        int64_t mTime1;
        uint16_t mNextSerialNumber;
        uint16_t mInResponseTo;
        gpg::time::Timer mSendBy;
        uint16_t mNextSequenceNumber;
        uint16_t mRemoteExpectedSequenceNumber;
        uint16_t mExpectedSequenceNumber;
        uint16_t v1;
        gpg::PipeStream mPendingOutputData;
        gpg::ZLibOutputFilterStream* mOutputFilterStream;
        bool mHasWritten;
        DWORD mFlushedOutputData;
        bool mOutputShutdown;
        bool mSentShutdown;
        WORD gap50E;
        TDatList<SNetPacket, void> mUnAckedPayloads;
        NetPacketTime mTimings[128];
        NetSpeeds mPings;
        float mPingTime;
        TDatList<SNetPacket, void> mEarlyPackets;
        uint32_t mMask;
        gpg::PipeStream mInputBuffer;
        gpg::ZLibOutputFilterStream* mFilterStream{nullptr};
        bool mReceivedEndOfInput;
        bool mDispatchedEndOfInput;
        CMessage mMessage;
        DWORD v866;
        bool  mScheduleDestroy;
        bool mDestroyed;
        bool  mClosed;
        int64_t mTotalBytesQueued;
        int64_t mTotalBytesSent;
        int64_t mTotalBytesReceived;
        int64_t mTotalBytesDispatched;
        gpg::MD5Context mTotalBytesQueuedMD5;
        gpg::MD5Context mTotalBytesSentMD5;
        gpg::MD5Context mTotalBytesReceivedMD5;
        gpg::MD5Context mTotalBytesDispatchedMD5;
	};
}
