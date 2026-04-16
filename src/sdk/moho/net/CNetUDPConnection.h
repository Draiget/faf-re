#pragma once
#include <cstddef>

#include "boost/weak_ptr.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/streams/ZLibOutputFilterStream.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/BoostUtils.h"
#include "INetConnection.h"
#include "INetConnector.h"
#include "legacy/containers/String.h"
#include "SNetPacket.h"

namespace moho
{
  // Forward declarations
  class INetNATTraversalProvider;
  class CNetUDPConnector;

  /**
   * VFTABLE: 0x00E06118
   * COL:     0x00E60D70
   */
  class CNetUDPConnection : public INetConnection,
                            public TDatListItem<CNetUDPConnection, void>,
                            public boost::noncopyable_::noncopyable
  {
  public:
    /**
     * Address: 0x00485BE0
     * Slot: 0
     * Demangled: moho::CNetUDPConnection::GetAddr
     */
    u_long GetAddr() override;

    /**
     * Address: 0x00485BF0
     * Slot: 1
     * Demangled: moho::CNetUDPConnection::GetPort
     */
    uint16_t GetPort() override;

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
     * Address: 0x1007F7E0 (sub_1007F7E0)
     */
    CNetUDPConnection(CNetUDPConnector& connector, u_long address, u_short port, ENetConnectionState state);

    /**
     * Address: 0x00486150
     * Address: 0x1007FC10 (sub_1007FC10)
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
     * Address: 0x00485BA0 (FUN_00485BA0)
     *
     * What it does:
     * Returns current UDP connection state enum lane.
     */
    [[nodiscard]] ENetConnectionState GetConnectionState() const noexcept;

    /**
     * Address: 0x00485BB0 (FUN_00485BB0)
     *
     * What it does:
     * Returns true while state is before errored (`< kNetStateErrored`).
     */
    [[nodiscard]] bool IsBeforeErroredState() const noexcept;

    /**
     * Address: 0x00485BD0 (FUN_00485BD0)
     *
     * What it does:
     * Returns whether destroy was already requested.
     */
    [[nodiscard]] bool IsDestroyScheduled() const noexcept;

    /**
     * Address: 0x00485BC0 (FUN_00485BC0)
     *
     * What it does:
     * Returns whether this connection is already fully destroyed.
     */
    [[nodiscard]] bool IsDestroyedFlagSet() const noexcept;

    /**
     * Address: 0x00486B10
     */
    bool ProcessAckInternal(const SNetPacket* packet);

    /**
       * Address: 0x00486DB0 (FUN_00486DB0)
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
     * Address: 0x00488260 (Moho::CNetUDPConnection::GetSentTime)
     */
    int GetSentTime(int64_t time);

    /**
     * Address: 0x004882C0 (FUN_004882C0, inlined/chunk helper lane)
     * Address: 0x0048AC40 (inlined helper inside FUN_0048AC40)
     *
     * Helper extracted from inlined connector send loop.
     * Binary evidence:
     * - FA 0x004882C0 (standalone chunk in this export set)
     * - FA 0x0048AC40 (sub_48AC40)
     */
    int GetBacklogTimeout(int64_t time, int32_t& timeout);

    /**
     * Address: 0x004881F0
     */
    [[nodiscard]]
    int TimeSince(int64_t time) const;

    /**
     * Address: 0x00488300
     */
    int SendData();

    /**
     * Address: 0x00488145
     */
    template <class T>
    constexpr T ChooseTimeout(T cur, T candidate)
    {
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
    SNetPacket* NewPacket(bool inherit, int size, EPacketType state) const;

    /**
       * Address: 0x00488D80 (FUN_00488D80)
     */
    void SendPacket(SNetPacket* packet);

    /**
     * Address: 0x00487590
     * Address: 0x10080FD0 (sub_10080FD0)
     */
    void FlushInput();

    /**
     * Address: 0x004879E0 (FUN_004879E0, inlined/chunk helper lane)
     * Address: 0x0048B7F0 (inlined helper inside FUN_0048B7F0)
     *
     * Helper extracted from inlined connector push loop.
     * Binary evidence:
     * - FA 0x004879E0 (standalone chunk in this export set)
     * - FA 0x0048B7F0 (CNetUDPConnector::Push)
     */
    bool FlushOutput();

    /**
     * Address: 0x004876A0
     * Address: 0x100810D0 (sub_100810D0)
     * Address: 0x100813A0 (sub_100810D0, alias/chunk export)
     */
    void DispatchFromInput();

    /**
     * Address: 0x00487B90
     * Address: 0x10081570 (sub_10081570)
     */
    void Debug();

  private:
    /**
     * Address: 0x00488220
     */
    void AdoptPacket(const SNetPacket* packet);

    /**
     * Address: 0x00485AA0 (FUN_00485AA0)
     *
     * What it does:
     * Compares expected and received 32-byte nonce lanes.
     */
    static bool ReceiverNonceDiffers32(const char (&expected)[32], const char (&received)[32]) noexcept;

    template <std::size_t N>
    static bool ByteArrayDiffers(const char (&lhs)[N], const char (&rhs)[N]) noexcept
    {
      for (std::size_t i = 0; i < N; ++i) {
        if (lhs[i] != rhs[i]) {
          return true;
        }
      }
      return false;
    }

    /**
     * Address: 0x00486110 (FUN_00486110)
     *
     * What it does:
     * Unlinks this connection node from connector intrusive list.
     */
    void UnlinkFromConnectorList() noexcept;

    /**
     * Address: 0x004874C0
     */
    void UpdatePingInfoFromPacket(const SNetPacket& packet);

    /**
      * Alias of FUN_00486DB0 (non-canonical helper lane).
     */
    MOHO_FORCEINLINE bool InsertEarlySorted(SNetPacket* packet);

    /**
      * Alias of FUN_00486DB0 (non-canonical helper lane).
     */
    MOHO_FORCEINLINE SNetPacket* EarlyPopFront();

    /**
      * Alias of FUN_00486DB0 (non-canonical helper lane).
     */
    MOHO_FORCEINLINE void EarlyRebuildAckMask(uint16_t expected, uint32_t& mask);

    /**
      * Alias of FUN_00486DB0 (non-canonical helper lane).
     */
    MOHO_FORCEINLINE void ConsumePacketHeaderData(SNetPacket* packet);

    /**
      * Alias of FUN_00488D80 (non-canonical helper lane).
     */
    MOHO_FORCEINLINE void InsertUnAckedSorted(SNetPacket* packet);

  public:
    // ...
    // +0x410  intrusive list node (connector-owned connection list link)
    // +0x42C  ENetConnectionState
    //          0=Pending, 1=Connecting, 2=Answering, 3=Establishing, 4=TimedOut, 5=Errored

    CNetUDPConnector* mConnector{nullptr};
    u_long mAddr{0};
    u_short mPort{0};
    WORD mPadding422{0};
    ENetCompressionMethod mOurCompressionMethod{NETCOMP_None};
    ENetCompressionMethod mReceivedCompressionMethod{NETCOMP_None};
    ENetConnectionState mState{kNetStatePending};
    gpg::time::Timer mLastSend;
    int64_t mSendTime{0};
    int64_t mLastRecv{0};
    int64_t mLastKeepAlive{0};
    uint32_t mKeepAliveFreqUs{2000000}; // set in 0x00485DE6 (~2s)
    char mNonceA[32]{};
    char mNonceB[32]{};
    uint32_t mReserved494{0};
    int64_t mHandshakeTime{0};
    uint16_t mNextSerialNumber{0};
    uint16_t mInResponseTo{0};
    gpg::time::Timer mSendBy;
    uint16_t mNextSequenceNumber{0};
    uint16_t mRemoteExpectedSequenceNumber{0};
    uint16_t mExpectedSequenceNumber{0};
    uint16_t mReserved4B6{0};
    gpg::PipeStream mPendingOutputData;
    gpg::ZLibOutputFilterStream* mOutputFilterStream{nullptr};
    bool mOutputFlushPending{false};
    DWORD mFlushedOutputData{0};
    bool mOutputShutdown{false};
    bool mSentShutdown{false};
    WORD mPadding50E{0};
    TDatList<SNetPacket, void> mUnAckedPayloads;
    NetPacketTime mTimings[128];
    NetSpeeds mPings;
    float mPingTime{0.0f};
    TDatList<SNetPacket, void> mEarlyPackets;
    uint32_t mMask{0};
    gpg::PipeStream mInputBuffer;
    gpg::ZLibOutputFilterStream* mFilterStream{nullptr};
    bool mReceivedEndOfInput{false};
    bool mDispatchedEndOfInput{false};
    CMessage mMessage;
    uint32_t mReservedE38{0};
    bool mScheduleDestroy{false};
    bool mDestroyed{false};
    bool mClosed{false};
    int64_t mTotalBytesQueued{0};
    int64_t mTotalBytesSent{0};
    int64_t mTotalBytesReceived{0};
    int64_t mTotalBytesDispatched{0};
    gpg::MD5Context mTotalBytesQueuedMD5;
    gpg::MD5Context mTotalBytesSentMD5;
    gpg::MD5Context mTotalBytesReceivedMD5;
    gpg::MD5Context mTotalBytesDispatchedMD5;
  };
  static_assert(sizeof(CNetUDPConnection) == 0xFE8, "CNetUDPConnection size must be 0xFE8");
} // namespace moho
