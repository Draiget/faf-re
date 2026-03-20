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

  /**
   * Address bundle:
   * - 0x00BC4E70..0x00BC5130 (register_net_*_ConVarDef)
   *
   * What it does:
   * Registers static net convar definitions into the global console command registry.
   */
  void NET_RegisterConVarDefinitions();
} // namespace moho
