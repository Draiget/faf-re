#pragma once
#include <cstdint>

#include "platform/Platform.h"
#include "CNetUDPConnection.h"
#include "Common.h"
#include "INetConnector.h"
#include "INetNATTraversalHandler.h"
#include "INetNATTraversalProvider.h"
#include "SNetPacket.h"
#include "boost/recursive_mutex.h"
#include "boost/weak_ptr.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Sync.h"
#include "legacy/containers/Deque.h"
#include "moho/containers/TDatList.h"

namespace moho
{
    constexpr uint32_t kReceiveUdpPacketPoolSize = 20;

    struct SReceivePacket
    {
	    SNetPacket* mPacket;
    	u_long mAddr;
    	u_short mPort;
    };

#pragma pack(push, 1)
    /**
     * 16-byte header written before each payload block in .pktlog.
     */
    struct PacketLogRecord
    {
        int64_t  timestamp_us;  // a3
        uint32_t addr;          // IPv4 (host-order as in asm)
        uint16_t len_flags;     // low 15 bits = payload len, bit15 (0x8000) = incoming
        uint16_t port;          // host-order
    };
    static_assert(sizeof(PacketLogRecord) == 16, "PacketLogRecord must be 16 bytes");
#pragma pack(pop)

    /*
     * Game Types:
     *
     * Multiplayer - CLobby::LaunchGame
     * Replay - VCR_SetupReplaySession
     * SinglePlayer - WLD_SetupSessionInfo
     * Saved Game - CSavedGame::CreateSinglePlayerSession
     *
     * Session State
     * 0 - None?
     * 1 - Loading?
     * 2 - Started?
     * 3 - SIM Initialized
     * 4 - SIM Started
     * 5 - Game Started
     * 7 - Restart Requested
     * 8 - Session Halted
     */
	class CNetUDPConnector :
		public INetConnector,
		public INetNATTraversalHandler
	{
	public:

        /**
		 * Releases lists, socket/event, packet pool, NAT provider weak_ptr.
		 *
         * Address: 0x004899E0
         * Slot: 0
         * Demangled: Moho::CNetUDPConnector::dtr
         */
        ~CNetUDPConnector() override;

        /**
         * Address: 0x004896F0
         */
        CNetUDPConnector(SOCKET sock, boost::weak_ptr<INetNATTraversalProvider>& prov);

        /**
		 * In binary this does:
		 * 1) locks weak_ptr to NAT provider and notifies it with local port
		 * 2) clears weak_ptr safely
		 * 3) calls a "close/shutdown" on each connection
		 * 4) sets a "stopping" flag and signals worker event
		 *
         * Address: 0x00489D20
         * Slot: 1
         * Demangled: Moho::CNetUDPConnector::Destroy
         */
        void Destroy() override;

        /**
         * Address: 0x00485CA0
         * Slot: 2
         * Demangled: Moho::CNetUDPConnector::GetProtocol
         */
        ENetProtocolType GetProtocol() override {
            return ENetProtocolType::kUdp;
        }

        /**
         * Address: 0x0048B250
         * Slot: 3
         * Demangled: Moho::CNetUDPConnector::GetLocalPort
         */
        u_short GetLocalPort() override;

        /**
         * Address: 0x0048B2B0
         * Slot: 4
         * Demangled: Moho::CNetUDPConnector::Connect
         */
        CNetUDPConnection* Connect(u_long address, u_short port) override;

        /**
         * Address: 0x0048B410
         * Slot: 5
         * Demangled: Moho::CNetUDPConnector::FindNextAddr
         */
        bool FindNextAddress(u_long& outAddress, u_short& outPort) override;

        /**
         * Address: 0x0048B4F0
         * Slot: 6
         * Demangled: Moho::CNetUDPConnector::Accept
         */
        INetConnection* Accept(u_long address, u_short port) override;

        /**
         * Address: 0x0048B500
         * Slot: 7
         * Demangled: Moho::CNetUDPConnector::Reject
         */
        void Reject(u_long address, u_short port) override;

        /**
         * Address: 0x0048B5C0
         * Slot: 8
         * Demangled: Moho::CNetUDPConnector::Pull
         */
        void Pull() override;

        /**
         * Address: 0x0048B7F0
         * Slot: 9
         * Demangled: Moho::CNetUDPConnector::Push
         */
        void Push() override;

        /**
         * Address: 0x0048B9A0
         * Slot: 10
         * Demangled: Moho::CNetUDPConnector::SelectEvent
         */
        void SelectEvent(HANDLE ev) override;

        /**
         * Address: 0x0048B8E0
         * Slot: 11
         * Demangled: Moho::CNetUDPConnector::Debug
         */
        void Debug() override;

        /**
         * Address: 0x0048B9E0
         * Slot: 12
         * Demangled: Moho::CNetUDPConnector::Func3
         */
        SSendStampView SnapshotSendStamps(uint64_t since) override;

        /**
         * Address: 0x00489F30
         *
         * Returns a monotonic microsecond timestamp based on (v14 baseline) + (timer elapsed),
         * clamped so it never goes backwards.
         */
        int64_t GetTime();

        /**
         * Address: 0x00488150
         */
        static int32_t ChooseTimeout(int32_t current, int32_t choice);

        /**
         * Address: 0x0048A288
         */
        int64_t ReceiveData();

        /**
         * Address: 0x0048AA40
         */
        void ProcessConnect(const SNetPacket* packet, u_long address, u_short port);

        /**
         * Address: 0x0048B040
         *
         * @param direction
         * @param timestampUs
         * @param addressHost
         * @param portHost
         * @param payload
         * @param payloadLen
         */
        MOHO_FORCEINLINE void LogPacket(
            int direction,
            std::int64_t timestampUs,
            std::uint32_t addressHost,
            std::uint16_t portHost,
            const void* payload,
            int payloadLen
        );

        /**
         * Address: 0x00489ED0
         */
        void DisposePacket(SNetPacket* packet);

        /**
         * Address: 0x0048BA80
         */
        void Func1(CMessage* msg) override;

        /**
         * Address: 0x0048BAE0
         */
        void ReceivePacket(u_long address, u_short port, const char* dat, size_t size) override;

        /**
         * Address: 0x00489E80
         */
        SNetPacket* NewPacket();

        /**
         * Address: 0x00489F90
         */
        void Entry();

        /**
         * Address: 0x0048AC40
         */
        int32_t SendData();

	public:
        /**
         * Address: 00489ED0
         * @param packet 
         */
        void AddPacket(SNetPacket* packet);

	public:
        // +0x00  vptr(INetConnector)
        // +0x04  vptr(INetNATTraversalHandler)

        boost::recursive_mutex lock_;
        SOCKET socket_;
        HANDLE event_;
        boost::weak_ptr<INetNATTraversalProvider> mNatTraversalProvider;
        TDatList<CNetUDPConnection, void> mConnections;
        TDatList<SNetPacket, void> mPacketList;
        uint32_t mPacketPoolSize;
        int64_t initTime_;
        gpg::time::Timer mTimer;
        int64_t mCurTime{ 0 };
        bool mClosed{ false };
        bool mIsPulling{ false };
        msvc8::deque<SReceivePacket> mPackets1;
        msvc8::deque<SReceivePacket> mPackets2;
        HANDLE mSelectedEvent;
        SSendStampBuffer mBuff;
        FILE* mFile;
        int gap;
	};
}
