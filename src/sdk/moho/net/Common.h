#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"
#include "gpg/core/time/Timer.h"
#include "INetNATTraversalProvider.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "NetConstants.h"
#include "NetMessageRanges.h"
#include "NetTransportEnums.h"
#include "platform/Platform.h"

namespace gpg
{
  class BinaryReader;
}

namespace moho
{
  class CD3DPrimBatcher;
  class INetConnector;
  struct SNetCommandArg;
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

    /**
     * Address: 0x00485B60 (FUN_00485B60)
     *
     * What it does:
     * Initializes packet timing lane with zeroed source id and reset timer.
     */
    NetPacketTime();
  };

  struct NetSpeeds
  {
    float vals[25]{};
    int mReserved0{0};
    int head{0};
    int tail{0};

    /**
     * Address: <inlined constructor lane in owning ctors>
     *
     * What it does:
     * Initializes fixed-size rolling sample ring state.
     */
    NetSpeeds();

    /**
     * Address: 0x0048C320 (FUN_0048C320, struct_RollingFloat_25 dtor lane)
     *
     * What it does:
     * Resets rolling sample ring cursors to empty state.
     */
    ~NetSpeeds();

    /**
     * Address: 0x0048BEC0 (FUN_0048BEC0, struct_RollingFloat_25::roll)
     *
     * What it does:
     * Appends one sample to rolling ring and advances write head.
     */
    int Append(float sample) noexcept;

    /**
     * Address: 0x0048BF00 (FUN_0048BF00, struct_RollingFloat_25::median)
     *
     * What it does:
     * Computes median of current rolling samples.
     */
    float Median() const noexcept;

    /**
     * Address: 0x0048BF60 (FUN_0048BF60, struct_RollingFloat_25::jitter)
     *
     * What it does:
     * Computes median absolute deviation from `center`.
     */
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

    /**
     * Address: 0x0047D4D0 (FUN_0047D4D0, GetStampCount)
     *
     * What it does:
     * Returns current number of copied send-stamp records.
     */
    [[nodiscard]] uint32_t StampCount() const noexcept;

    /**
     * Address: 0x0047D3C0 (FUN_0047D3C0, ReserveStampCapacity)
     *
     * What it does:
     * Ensures contiguous capacity for at least `count` copied stamps.
     */
    void ReserveStamps(uint32_t count);

    /**
     * Address: 0x0047D500 (FUN_0047D500, AppendStamp)
     *
     * What it does:
     * Appends one copied send-stamp record to this view.
     */
    void AppendStamp(const SSendStamp& stamp);
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

    /**
     * Address: 0x0047D690 (FUN_0047D690, AdvanceOldestIndex)
     *
     * What it does:
     * Advances the oldest readable ring slot by one modulo capacity.
     */
    void AdvanceOldestIndex() noexcept;

  private:
    /**
     * Place entry at `mNextWriteIndex` and advance by one (mod 4096).
     * Address: <synthetic helper, shared by Push/Add paths>
     */
    uint32_t EmplaceAndAdvance(const SSendStamp& stamp) noexcept;
  };
  static_assert(sizeof(SSendStampBuffer) == 0x18008, "SSendStampBuffer size must be 0x18008");

  struct SBandwidthUsageSample
  {
    float outboundBytesPerSec{0.0f};
    float inboundBytesPerSec{0.0f};
  };
  static_assert(sizeof(SBandwidthUsageSample) == 0x8, "SBandwidthUsageSample size must be 0x8");

  struct SBandwidthUsageSeries
  {
    msvc8::vector<SBandwidthUsageSample> samples;

    /**
     * Address: 0x0047D6E0 (FUN_0047D6E0, GetBandwidthSampleCount)
     *
     * What it does:
     * Returns the number of generated bandwidth samples.
     */
    [[nodiscard]] uint32_t SampleCount() const noexcept;

    /**
     * Address: 0x0047DA00 (FUN_0047DA00, ResizeBandwidthSamples)
     *
     * What it does:
     * Resizes sample storage to `count`, zero-initializing new lanes.
     */
    void ResizeSamples(uint32_t count);

    /**
     * Address: 0x0047D6B0 (FUN_0047D6B0, EnsureBandwidthSampleCount)
     *
     * What it does:
     * Alias lane for `ResizeSamples`.
     */
    void EnsureSampleCount(uint32_t count);
  };

  /**
   * Address: 0x0047CC00 (FUN_0047CC00, BuildBandwidthUsageSeries)
   *
   * What it does:
   * Builds rolling in/out byte-rate samples from send-stamp events over the
   * requested time range and applies a 3-point smoothing pass.
   */
  void NET_BuildBandwidthUsageSeries(
    SBandwidthUsageSeries& outSeries,
    const SSendStampView& stamps,
    int sampleCount,
    uint64_t rangeStartUs,
    uint64_t rangeEndUs,
    uint64_t averagingWindowUs
  );

  /**
   * Address: 0x007F3F20 (FUN_007F3F20, func_ren_BandwidthUsage_Line)
   *
   * What it does:
   * Renders one outbound/inbound bandwidth series pair as two connected line
   * strips in screen space.
   */
  void REN_DrawBandwidthUsageLinePair(
    CD3DPrimBatcher& primBatcher,
    const SBandwidthUsageSeries& series,
    std::int32_t xOffset,
    std::int32_t yBase,
    float yScale,
    std::uint32_t inboundColor,
    std::uint32_t outboundColor
  );

  /**
   * Shared GPGNet socket decode lane:
   * Reads one uint32 length followed by exact payload bytes.
   */
  [[nodiscard]] msvc8::string NET_ReadLengthPrefixedArgPayload(gpg::BinaryReader& reader);

  /**
   * Shared GPGNet socket decode lane:
   * Decodes one wire argument (num/string/data) from stream payload.
   */
  [[nodiscard]] SNetCommandArg NET_DecodeSocketArg(gpg::BinaryReader& reader);

  /**
   * Address: 0x0047F5A0
   */
  bool NET_Init();

  /**
   * Address: 0x0047F540 (FUN_0047F540, NETMAIL_SendError)
   *
   * What it does:
   * Legacy no-op mail/error reporting hook.
   */
  void NETMAIL_SendError(const char* title, const char* message);

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
   * Address: 0x0047ED50 (FUN_0047ED50, NET_ProtocolFromString)
   *
   * What it does:
   * Parses "None"/"TCP"/"UDP" (case-insensitive) into `ENetProtocolType`,
   * otherwise throws `std::domain_error`.
   */
  ENetProtocolType NET_ProtocolFromString(const char* str);

  /**
   * Startup-owned protocol name vector backing protocol-list helper lanes.
   */
  extern msvc8::vector<msvc8::string> sProtocols;

  /**
   * Address: 0x00BC4690 (FUN_00BC4690, register_sProtocols)
   *
   * What it does:
   * Registers process-exit cleanup for the startup-owned `sProtocols` storage.
   */
  void register_sProtocols();

  /**
   * Address: 0x0047EC90 (FUN_0047EC90, NET_GetProtocolName)
   *
   * What it does:
   * Converts `ENetProtocolType` to `"None"`, `"TCP"`, or `"UDP"`, otherwise
   * throws `std::domain_error`.
   */
  msvc8::string NET_GetProtocolName(ENetProtocolType protocol);

  /**
   * Address: 0x0047EBF0 (FUN_0047EBF0, NET_MakeConnector)
   *
   * What it does:
   * Creates protocol-specific connector implementation for `port`, using NAT
   * traversal provider only on UDP.
   * Unknown/`kNone` protocol values produce a `CNetNullConnector`.
   */
  INetConnector* NET_MakeConnector(
    u_short port,
    ENetProtocolType protocol,
    const boost::weak_ptr<INetNATTraversalProvider>& natTraversalProvider
  );

  /**
   * Address: 0x0048BBE0 (FUN_0048BBE0)
   *
   * What it does:
   * Creates a non-blocking UDP connector bound to `port`, or returns null on
   * socket/ioctl/bind/allocation failure.
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
