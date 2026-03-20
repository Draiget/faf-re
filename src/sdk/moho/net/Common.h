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
    int v1{0};
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
    uint32_t direction{0};
    uint32_t v1{0};
    uint64_t time{0}; // used as 64-bit tick container in the binary
    uint32_t size{0};
    uint32_t v4{0};
  };

  struct SSendStampView
  {
    msvc8::vector<SSendStamp> items; // contiguous vector of copies
    uint64_t from{0};                // threshold = now - window
    uint64_t to{0};                  // now

    /**
     * Address: 0x0047D1D0
     * NOTE: Inlined
     *
     * @param start
     * @param end
     */
    SSendStampView(uint64_t start, uint64_t end);
  };

  struct SSendStampBuffer
  {
    static constexpr uint32_t cap = 4096;

    SSendStamp mDat[cap]{};
    uint32_t mEnd{0};   // oldest
    uint32_t mStart{0}; // next write

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
    bool empty() const noexcept;

    [[nodiscard]]
    uint32_t size() const noexcept;

    void push(const SSendStamp& s) noexcept;

    SSendStamp& Get(size_t index) noexcept;

  private:
    /**
     * Place entry at mStart and advance mStart by 1 (mod 4096).
     * Address: <synthetic helper, shared by Push/Add paths>
     */
    uint32_t EmplaceAndAdvance(const SSendStamp& s) noexcept;
  };

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
