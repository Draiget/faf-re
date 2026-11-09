#pragma once

#include <atomic>
#include <cstdint>

#include "NetTransportEnums.h"

namespace moho
{
  extern bool net_DebugCrash;            // 0x010A6380
  extern bool net_LogPackets;            // 0x010A6381
  extern int32_t net_DebugLevel;         // 0x010A6384
  extern int32_t net_PeerFeatures;       // engine addition (issue #285), off by default
  extern int32_t net_LobbyPeerFeatures;  // engine addition, on by default
  extern int32_t net_RejoinAccept;       // engine addition (issue #275), off by default
  extern int32_t net_RejoinSendRate;     // engine addition (issue #275)
  extern int32_t net_RejoinKeyframes;    // engine addition (issue #275)
  extern int32_t net_RejoinWindow;       // engine addition (issue #275)
  extern int32_t net_RejoinZstd;         // engine addition (issue #275)
  extern int32_t net_RejoinFastSave;     // engine addition (issue #275)
  extern int32_t net_AckDelay;           // 0x00F58DE0
  extern int32_t net_SendDelay;          // 0x00F58DE4
  extern int32_t net_MinResendDelay;     // 0x00F58DE8
  extern int32_t net_MaxResendDelay;     // 0x00F58DEC
  extern int32_t net_MaxSendRate;        // 0x00F58DF0
  extern int32_t net_MaxBacklog;         // 0x00F58DF4
  extern int32_t net_CompressionMethod;  // 0x00F58DF8
  extern float net_ResendPingMultiplier; // 0x00F58DFC
  extern int32_t net_ResendDelayBias;    // 0x00F58E00

  // Engine additions, not in the binary (see NetConVars.cpp).
  extern int32_t net_CheckOrderStreams;
  extern int32_t net_DebugAlterOrdersTo;
  extern int32_t net_SocketRecvBuffer;
  extern int32_t net_SocketSendBuffer;
  extern int32_t net_InEngineLinks;
  extern int32_t net_NativeNet;
  extern int32_t net_LogBeatWaitMs;
  extern int32_t net_LogTraffic;
  extern int32_t net_LogShownBeatMs;
  extern int32_t net_AdaptiveLagMax;

  // Totals of every UDP connection in this process, for net_LogTraffic.
  struct NetTrafficTotals
  {
    std::atomic<std::int64_t> packets{0};
    std::atomic<std::int64_t> bytes{0};
    std::atomic<std::int64_t> resends{0};
    std::atomic<std::int64_t> acks{0};
    std::atomic<std::int64_t> pingSamples{0};
    std::atomic<std::int64_t> pingMicrosSum{0};
  };
  extern NetTrafficTotals gNetTraffic;
  // Set once in-engine links exist; the headless builds have none. Logs what they have sent.
  extern void (*gNetLinkTrafficLog)(int beat);
  extern int32_t net_TestBurstBeat;
  extern int32_t net_TestBurstBytes;
  extern int32_t net_NativeNetWebRtc;
  extern int32_t net_NativeNetRedundancy;
  extern int32_t net_NativeNetEncrypt;
  extern int32_t net_FastRetransmit;
  extern float net_FastResendPings;
  extern int32_t net_FastAckDelay;

  // Issue #237: net_FastRetransmit, or /fastretransmit on the command line.
  bool NET_FastRetransmitEnabled();
  // How long a received packet waits for its acknowledgement, in ms: net_AckDelay, or
  // net_FastAckDelay when that is less and net_FastRetransmit is on.
  [[nodiscard]] int32_t NET_AckDelayMs();
  // Counts early resends; logs the first and every 1000th.
  void NET_CountFastRetransmits(int count);

  /**
   * Engine addition (wld_PreciseSharedStart): when this client's ready message (`CLIMSG_Ready`)
   * left on the wire (the latest over all UDP connections), in microseconds on the steady clock;
   * 0 before it did. It leaves up to `net_SendDelay` after it was queued, and the peers time that
   * departure too, from its arrival, so both sides time the same moment.
   */
  [[nodiscard]] std::int64_t NET_GetReadyDepartureUs() noexcept;

  /** Engine addition (wld_PreciseSharedStart): this client's ready message left just now. */
  void NET_NoteReadyLeftNow() noexcept;

  /** Engine addition (wld_PreciseSharedStart): forget the last session's ready departure. */
  void NET_ResetReadyDeparture() noexcept;

  /**
   * Engine addition (wld_PreciseSharedStart, wld_SkewCorrection): `std::chrono::steady_clock` in
   * microseconds, which every process on the PC reads alike.
   */
  [[nodiscard]] std::int64_t NET_SteadyClockMicroseconds() noexcept;
} // namespace moho
