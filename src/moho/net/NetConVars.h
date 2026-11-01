#pragma once

#include <cstdint>

#include "NetTransportEnums.h"

namespace moho
{
  extern bool net_DebugCrash;            // 0x010A6380
  extern bool net_LogPackets;            // 0x010A6381
  extern int32_t net_DebugLevel;         // 0x010A6384
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
  extern int32_t net_TestBurstBeat;
  extern int32_t net_TestBurstBytes;
  extern int32_t net_NativeNetWebRtc;
  extern int32_t net_NativeNetRedundancy;
  extern int32_t net_FastRetransmit;

  // Issue #237: net_FastRetransmit, or /fastretransmit on the command line.
  bool NET_FastRetransmitEnabled();
  // Counts early resends; logs the first and every 1000th.
  void NET_CountFastRetransmits(int count);
} // namespace moho
