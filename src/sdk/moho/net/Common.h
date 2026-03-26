#pragma once

#include <cstddef>

#include "boost/weak_ptr.h"
#include "gpg/core/time/Timer.h"
#include "INetNATTraversalProvider.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "NetConstants.h"
#include "NetMessageRanges.h"
#include "NetTransportEnums.h"
#include "platform/Platform.h"

namespace moho
{
  class INetConnector;
  struct CHostManager;

  /**
   * String versions is on 0x00DFEB14
   */
  enum class ENetworkPlayerState : int32_t
  {
    kUnknown = 0,
    kConnecting = 1,
    kConnected = 2,
    kPending = 3,
    kWaitingJoin = 4,
    kEstablished = 5,
    kDisconnected = 6,
    _Last
  };

  /**
   * Address: 0x007C0560
   *
   * @param state
   * @param out
   * @return
   */
  void ENetworkPlayerStateToStr(ENetworkPlayerState state, msvc8::string& out);

  struct NetPacketTime
  {
    unsigned short mSource{0};
    gpg::time::Timer mTime;
  };

  struct NetSpeeds
  {
    float vals[25]{};
    int mReserved0{0};
    int head{0};
    int tail{0};

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Initializes fixed-size sample ring state.
     */
    NetSpeeds();

    /**
     * Address: <synthetic host-build helper>
     */
    ~NetSpeeds();

    int Append(float sample) noexcept;
    float Median() const noexcept;
    float Jitter(float center) const noexcept;
  };

  struct SSendStamp
  {
    uint32_t direction{0};        // 0 = outbound, 1 = inbound (producer callsites)
    uint32_t reserved0{0};        // carried in records; semantics unresolved
    uint64_t timestampUs{0};      // microsecond timestamp
    uint32_t payloadSizeBytes{0}; // packet/message payload size in bytes
    uint32_t reserved1{0};        // carried in records; semantics unresolved
  };
  static_assert(sizeof(SSendStamp) == 0x18, "SSendStamp size must be 0x18");

  struct SSendStampView
  {
    msvc8::vector<SSendStamp> items; // contiguous vector of copied stamps
    uint64_t windowDurationUs{0};    // (endTimeUs - startTimeUs)
    uint64_t windowEndTimeUs{0};     // end of requested window

    /**
     * Address: 0x0047D1D0
     * NOTE: Inlined
     *
     * @param durationUs
     * @param endTimeUs
     */
    SSendStampView(uint64_t durationUs, uint64_t endTimeUs);
  };

  struct SSendStampBuffer
  {
    static constexpr uint32_t cap = 4096;

    SSendStamp mDat[cap]{};
    uint32_t mOldestIndex{0};    // oldest readable stamp
    uint32_t mNextWriteIndex{0}; // next write slot

    /**
     * Address: 0x0047D110
     *
     * lower-bound in circular buffer, copy window into out
     */
    SSendStampView GetBetween(uint64_t endTimeUs, uint64_t startTimeUs);

    /**
     * Address: 0x0047D990
     */
    void Reset();

    /**
     * Address: 0x0047D0A0
     */
    uint32_t Push(int direction, LONGLONG timeUs, int payloadSizeBytes) noexcept;

    /**
     * Address: 0x0047D0A0
     */
    void Add(int direction, LONGLONG timeUs, int payloadSizeBytes);

    /**
     * Address: 0x0047D630
     */
    void Append(const SSendStamp* stamp);

    [[nodiscard]]
    bool empty() const noexcept;

    [[nodiscard]]
    uint32_t size() const noexcept;

    void push(const SSendStamp& s) noexcept;

    SSendStamp& Get(size_t logicalIndex) noexcept;

  private:
    /**
     * Place entry at `mNextWriteIndex` and advance by one (mod 4096).
     * Address: <synthetic helper, shared by Push/Add paths>
     */
    uint32_t EmplaceAndAdvance(const SSendStamp& stamp) noexcept;
  };
  static_assert(sizeof(SSendStampBuffer) == 0x18008, "SSendStampBuffer size must be 0x18008");

  /**
   * Address: 0x0047F5A0
   */
  bool NET_Init();

  /**
   * Address: 0x0047F990 (FUN_0047F990)
   */
  CHostManager* NET_GetHostManager();

  /**
   * Address: 0x0047FEE0 (FUN_0047FEE0)
   */
  msvc8::string NET_GetHostName(u_long address);

  /**
   * Address: 0x0047F5F0
   * Render getnameinfo/gai/WSA error to string for logs.
   *
   * @return
   */
  const char* NET_GetWinsockErrorString() noexcept;

  /**
   * Address: 0x004801C0 (FUN_004801C0)
   *
   * uint32_t
   *
   * What it does:
   * Formats host-order IPv4 as "A.B.C.D".
   */
  msvc8::string NET_GetDottedOctetFromUInt32(uint32_t number);

  /**
   * Address: 0x00480200 (FUN_00480200)
   *
   * msvc8::string
   *
   * What it does:
   * Splits dotted IPv4 text by '.' and folds tokens using (acc << 8) | atoi(token).
   */
  uint32_t NET_GetUInt32FromDottedOcted(const msvc8::string& host);

  /**
   * Address: 0x0047FF10 (FUN_0047FF10)
   *
   * gpg::StrArg, unsigned short, bool, unsigned int &, unsigned short &
   *
   * What it does:
   * Resolves "host[:port]" through getaddrinfo(AF_INET) and returns host-order address/port.
   */
  bool NET_GetAddrInfo(const char* str, u_short defaultPort, bool isTcp, u_long& address, u_short& port);

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

  /**
   * Address: 0x004849A0 (FUN_004849A0)
   *
   * What it does:
   * Creates non-blocking TCP listening connector bound to `port`.
   */
  INetConnector* NET_MakeTCPConnector(u_short port);
} // namespace moho
