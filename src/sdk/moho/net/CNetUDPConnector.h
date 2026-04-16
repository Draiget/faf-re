#pragma once
#include <cstddef>
#include <cstdint>

#include "boost/recursive_mutex.h"
#include "boost/weak_ptr.h"
#include "CNetUDPConnection.h"
#include "Common.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Sync.h"
#include "INetConnector.h"
#include "INetNATTraversalHandler.h"
#include "INetNATTraversalProvider.h"
#include "legacy/containers/Deque.h"
#include "moho/containers/TDatList.h"
#include "platform/Platform.h"
#include "SNetPacket.h"

namespace moho
{
  constexpr uint32_t kReceiveUdpPacketPoolSize = 20;

  struct SReceivePacket
  {
    SNetPacket* mPacket{nullptr};
    u_long mAddr{0};
    u_short mPort{0};
  };

  /**
   * 16-byte header written before each payload block in .pktlog.
   */
  struct PacketLogRecord
  {
    int64_t timestamp_us{0}; // a3
    uint32_t addr{0};        // IPv4 (host-order as in asm)
    uint16_t len_flags{0};   // low 15 bits = payload len, bit15 (0x8000) = incoming
    uint16_t port{0};        // host-order
  };
  static_assert(offsetof(PacketLogRecord, timestamp_us) == 0x00, "PacketLogRecord::timestamp_us must be +0x00");
  static_assert(offsetof(PacketLogRecord, addr) == 0x08, "PacketLogRecord::addr must be +0x08");
  static_assert(offsetof(PacketLogRecord, len_flags) == 0x0C, "PacketLogRecord::len_flags must be +0x0C");
  static_assert(offsetof(PacketLogRecord, port) == 0x0E, "PacketLogRecord::port must be +0x0E");
  static_assert(sizeof(PacketLogRecord) == 16, "PacketLogRecord must be 16 bytes");

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
  class CNetUDPConnector : public INetConnector, public INetNATTraversalHandler
  {
  public:
    /**
     * Releases lists, socket/event, packet pool, NAT provider weak_ptr.
     *
     * Address: 0x004899E0 (FUN_004899E0, deleting wrapper)
     * Address: 0x00489BC0 (FUN_00489BC0)
     * Address: 0x10083420 (sub_10083420, deleting wrapper)
     * Address: 0x10083600 (sub_10083600, non-deleting destructor)
     * Slot: 0
     * Demangled: Moho::CNetUDPConnector::dtr
     */
    ~CNetUDPConnector() override;

    /**
     * Address: 0x004896F0 (FUN_004896F0)
     *
     * What it does:
     * Initializes connector runtime state, starts worker `Entry` thread, and
     * registers NAT traversal callback with provider.
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
     * Address: 0x10083760 (sub_10083760)
     * Slot: 1
     * Demangled: Moho::CNetUDPConnector::Destroy
     */
    void Destroy() override;

    /**
     * Address: 0x00485CA0 (FUN_00485CA0)
     * Address: 0x1007F750 (sub_1007F750)
     * Slot: 2
     * Demangled: Moho::CNetUDPConnector::GetProtocol
     *
     * What it does:
     * Returns UDP transport protocol tag for this connector implementation.
     */
    ENetProtocolType GetProtocol() override;

    /**
     * Address: 0x0048B250
     * Address: 0x10084C10 (sub_10084C10)
     * Slot: 3
     * Demangled: Moho::CNetUDPConnector::GetLocalPort
     */
    u_short GetLocalPort() override;

    /**
     * Address: 0x0048B2B0 (FUN_0048B2B0)
     * Address: 0x10084C70 (sub_10084C70)
     * Slot: 4
     * Demangled: Moho::CNetUDPConnector::Connect
     *
     * What it does:
     * Returns an existing connection for endpoint handshakes or allocates a
     * new outbound connection.
     */
    CNetUDPConnection* Connect(u_long address, u_short port) override;

    /**
     * Address: 0x0048B410
     * Address: 0x10084DD0 (sub_10084DD0)
     * Slot: 5
     * Demangled: Moho::CNetUDPConnector::FindNextAddr
     */
    bool FindNextAddress(u_long& outAddress, u_short& outPort) override;

    /**
     * Address: 0x0048B4F0
     * Address: 0x10084EB0 (sub_10084EB0)
     * Slot: 6
     * Demangled: Moho::CNetUDPConnector::Accept
     */
    INetConnection* Accept(u_long address, u_short port) override;

    /**
     * Address: 0x0048B500
     * Address: 0x10084EC0 (sub_10084EC0)
     * Slot: 7
     * Demangled: Moho::CNetUDPConnector::Reject
     */
    void Reject(u_long address, u_short port) override;

    /**
     * Address: 0x0048B5C0 (FUN_0048B5C0)
     * Address: 0x10084F80 (sub_10084F80)
     * Slot: 8
     * Demangled: Moho::CNetUDPConnector::Pull
     *
     * What it does:
     * Drains connector input and NAT traversal queues and dispatches input.
     */
    void Pull() override;

    /**
      * Alias of FUN_0048B7F0 (non-canonical helper lane).
     * Address: 0x100851A0 (sub_100851A0)
     * Slot: 9
     * Demangled: Moho::CNetUDPConnector::Push
     */
    void Push() override;

    /**
     * Address: 0x0048B9A0
     * Address: 0x10085340 (sub_10085340)
     * Slot: 10
     * Demangled: Moho::CNetUDPConnector::SelectEvent
     */
    void SelectEvent(HANDLE ev) override;

    /**
     * Address: 0x0048B8E0 (FUN_0048B8E0)
     * Address: 0x10085280 (sub_10085280)
     * Slot: 11
     * Demangled: Moho::CNetUDPConnector::Debug
     *
     * What it does:
     * Logs connector and per-connection diagnostics.
     */
    void Debug() override;

    /**
     * Address: 0x0048B9E0 (FUN_0048B9E0)
     * Address: 0x10085380 (sub_10085380)
     * Slot: 12
     * Demangled: Moho::CNetUDPConnector::Func3
     *
     * What it does:
     * Returns a snapshot view of send/recv stamps from `since` milliseconds up to current connector time.
     */
    SSendStampView SnapshotSendStamps(int32_t since) override;

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
     * Address: 0x0048A280 (FUN_0048A280)
     * Address: 0x0048A288 (SEH-prologue label inside FUN_0048A280)
     *
     * What it does:
     * Receives and dispatches UDP packets, recycling unconsumed buffers.
     */
    void ReceiveData();

    /**
     * Address: 0x0048AA40 (FUN_0048AA40)
     *
     * What it does:
     * Handles incoming CONNECT packets and creates pending connections.
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
    void LogPacket(
      int direction,
      std::int64_t timestampUs,
      std::uint32_t addressHost,
      std::uint16_t portHost,
      const void* payload,
      int payloadLen
    );

    /**
     * Address: 0x00485C10 (FUN_00485C10)
     *
     * What it does:
     * Signals this connector's socket wake event.
     */
    bool SignalSocketEvent() noexcept;

    /**
     * Address: 0x00485C20 (FUN_00485C20)
     *
     * What it does:
     * Relinks a connection's intrusive node to the front of connector list.
     */
    CNetUDPConnection& RelinkConnectionToFront(CNetUDPConnection& connection) noexcept;

    /**
     * Address: 0x00489ED0
     */
    void DisposePacket(SNetPacket* packet);

    /**
     * Address: 0x0048BA80 (FUN_0048BA80)
     * Address: 0x10085450 (sub_10085450)
     *
     * What it does:
     * Initializes outbound NAT traversal message marker (type byte 8).
     */
    void PrepareTraversalMessage(CMessage* msg) override;

    /**
     * Address: 0x0048BAE0 (FUN_0048BAE0)
     * Address: 0x100854B0 (sub_100854B0)
     *
     * What it does:
     * Enqueues NAT traversal payload for UDP send to (`address`,`port`) and
     * signals connector event.
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
      * Alias of FUN_0048AC40 (non-canonical helper lane).
     */
    int32_t SendData();

  public:
    /**
     * Helper alias used by recovered callsites that map to `DisposePacket`.
     *
     * No standalone FA symbol; behavior is FA `0x00489ED0` (`DisposePacket`).
     */
    void AddPacket(SNetPacket* packet);

  public:
    // +0x00  vptr(INetConnector)
    // +0x04  vptr(INetNATTraversalHandler)

    boost::recursive_mutex lock_;
    SOCKET socket_{INVALID_SOCKET};
    HANDLE event_{nullptr};
    boost::weak_ptr<INetNATTraversalProvider> mNatTraversalProvider;
    TDatList<CNetUDPConnection, void> mConnections;
    TDatList<SNetPacket, void> mPacketList;
    uint32_t mPacketPoolSize{0};
    // FILETIME-based absolute microsecond baseline captured at ctor.
    int64_t mTimeBaseUs{0};
    gpg::time::Timer mTimer;
    // Monotonic connector time in microseconds (never decreases).
    int64_t mCurrentTimeUs{0};
    // Worker-thread close/pull coordination flags.
    bool mClosed{false};
    bool mIsPulling{false};
    // Outbound NAT traversal queue and inbound NAT traversal queue.
    msvc8::deque<SReceivePacket> mOutboundPackets;
    msvc8::deque<SReceivePacket> mInboundTraversalPackets;
    // Optional externally provided wake event for select-style polling.
    HANDLE mSelectedEvent{nullptr};
    // Rolling send/recv stamp window for diagnostics/snapshot APIs.
    SSendStampBuffer mSendStampBuffer;
    // Optional packet-log stream (.pktlog).
    FILE* mPacketLogFile{nullptr};
    // Tail alignment slot. Binary allocates 0x18090 bytes for CNetUDPConnector.
    uint32_t mTailPadding{0};
  };

  static_assert(sizeof(CNetUDPConnector) == 0x18090, "CNetUDPConnector size must be 0x18090");
} // namespace moho
