#include "moho/net/NetConVars.h"

#include <cstdint>
#include <cstdlib>

#include "moho/console/CConCommand.h"

namespace moho
{
  bool net_DebugCrash = false;                     // 0x010A6380
  bool net_LogPackets = false;                     // 0x010A6381
  int32_t net_DebugLevel = 0;                      // 0x010A6384
  int32_t net_AckDelay = 0;                        // 0x00F58DE0
  int32_t net_SendDelay = 0;                       // 0x00F58DE4
  int32_t net_MinResendDelay = 0;                  // 0x00F58DE8
  int32_t net_MaxResendDelay = 0;                  // 0x00F58DEC
  int32_t net_MaxSendRate = 1000;                  // 0x00F58DF0
  int32_t net_MaxBacklog = 0;                      // 0x00F58DF4
  int32_t net_CompressionMethod = NETCOMP_Deflate; // 0x00F58DF8
  float net_ResendPingMultiplier = 1.0f;           // 0x00F58DFC
  int32_t net_ResendDelayBias = 0;                 // 0x00F58E00

  namespace
  {
    TConVar<bool> sNetDebugCrashConVar{"net_DebugCrash", "If true, crash.", &net_DebugCrash};

    TConVar<int32_t> sNetDebugLevelConVar{"net_DebugLevel", "Amount of network debug spew", &net_DebugLevel};

    TConVar<int32_t> sNetAckDelayConVar{
      "net_AckDelay", "Number of milliseconds to delay before sending ACKs", &net_AckDelay
    };

    TConVar<int32_t> sNetSendDelayConVar{
      "net_SendDelay", "Number of milliseconds to delay before sending Data", &net_SendDelay
    };

    TConVar<bool> sNetLogPacketsConVar{"net_LogPackets", "Log all incomming/outgoing packets.", &net_LogPackets};

    TConVar<int32_t> sNetMinResendDelayConVar{
      "net_MinResendDelay", "Minimum number of milliseconds to delay before resending a packet.", &net_MinResendDelay
    };

    TConVar<int32_t> sNetMaxResendDelayConVar{
      "net_MaxResendDelay", "Maximum number of milliseconds to delay before resending a packet.", &net_MaxResendDelay
    };

    TConVar<int32_t> sNetMaxSendRateConVar{
      "net_MaxSendRate", "Maximum number of bytes to send per second to any one client.", &net_MaxSendRate
    };

    TConVar<int32_t> sNetMaxBacklogConVar{
      "net_MaxBacklog", "Maximum number of bytes to backlog to any one client.", &net_MaxBacklog
    };

    TConVar<int32_t> sNetCompressionMethodConVar{
      "net_CompressionMethod",
      "Compression method, 0=none, 1=deflate.  Only takes effect when connections are first established.",
      &net_CompressionMethod
    };

    TConVar<float> sNetResendPingMultiplierConVar{
      "net_ResendPingMultiplier",
      "The resend delay is ping*new_ResendPingMultiplier+net_ResendDelayBias.",
      &net_ResendPingMultiplier
    };

    TConVar<int32_t> sNetResendDelayBiasConVar{
      "net_ResendDelayBias",
      "The resend delay is ping*new_ResendPingMultiplier+net_ResendDelayBias.",
      &net_ResendDelayBias
    };

    bool sNetConVarsRegistered = false;

    /**
     * Address bundle:
     * - 0x00BEFAF0 (sub_BEFAF0)
     * - 0x00BEFB20 (sub_BEFB20)
     * - 0x00BEFB50 (sub_BEFB50)
     * - 0x00BEFB80 (sub_BEFB80)
     * - 0x00BEFBB0 (sub_BEFBB0)
     * - 0x00BEFBE0 (sub_BEFBE0)
     * - 0x00BEFC10 (sub_BEFC10)
     * - 0x00BEFC40 (sub_BEFC40)
     * - 0x00BEFC70 (sub_BEFC70)
     * - 0x00BEFCA0 (sub_BEFCA0)
     * - 0x00BEFCD0 (sub_BEFCD0)
     * - 0x00BEFD00 (sub_BEFD00)
     *
     * What it does:
     * Unregisters net convars from the console chain.
     */
    void UnregisterNetConVars()
    {
      if (!sNetConVarsRegistered) {
        return;
      }

      // Reverse registration order (equivalent final state to per-convar atexit hooks).
      UnregisterConCommand(sNetResendDelayBiasConVar);
      UnregisterConCommand(sNetResendPingMultiplierConVar);
      UnregisterConCommand(sNetCompressionMethodConVar);
      UnregisterConCommand(sNetMaxBacklogConVar);
      UnregisterConCommand(sNetMaxSendRateConVar);
      UnregisterConCommand(sNetMaxResendDelayConVar);
      UnregisterConCommand(sNetMinResendDelayConVar);
      UnregisterConCommand(sNetLogPacketsConVar);
      UnregisterConCommand(sNetSendDelayConVar);
      UnregisterConCommand(sNetAckDelayConVar);
      UnregisterConCommand(sNetDebugLevelConVar);
      UnregisterConCommand(sNetDebugCrashConVar);

      sNetConVarsRegistered = false;
    }
  } // namespace

  /**
   * Address bundle:
   * - 0x00BC4E70 (register_net_DebugCrash_ConVarDef)
   * - 0x00BC4EB0 (register_net_DebugLevel_ConVarDef)
   * - 0x00BC4EF0 (register_net_AckDelay_ConVarDef)
   * - 0x00BC4F30 (register_net_SendDelay_ConVarDef)
   * - 0x00BC4F70 (register_net_LogPackets_ConVarDef)
   * - 0x00BC4FB0 (register_net_MinResendDelay_ConVarDef)
   * - 0x00BC4FF0 (register_net_MaxResendDelay_ConVarDef)
   * - 0x00BC5030 (register_net_MaxSendRate_ConVarDef)
   * - 0x00BC5070 (register_net_MaxBacklog_ConVarDef)
   * - 0x00BC50B0 (register_net_CompressionMethod_ConVarDef)
   * - 0x00BC50F0 (register_net_ResendPingMultiplier_ConVarDef)
   * - 0x00BC5130 (register_net_ResendDelayBias_ConVarDef)
   *
   * What it does:
   * Registers net convar definitions once and wires one teardown callback for process shutdown.
   */
  void NET_RegisterConVarDefinitions()
  {
    if (sNetConVarsRegistered) {
      return;
    }

    RegisterConCommand(sNetDebugCrashConVar);
    RegisterConCommand(sNetDebugLevelConVar);
    RegisterConCommand(sNetAckDelayConVar);
    RegisterConCommand(sNetSendDelayConVar);
    RegisterConCommand(sNetLogPacketsConVar);
    RegisterConCommand(sNetMinResendDelayConVar);
    RegisterConCommand(sNetMaxResendDelayConVar);
    RegisterConCommand(sNetMaxSendRateConVar);
    RegisterConCommand(sNetMaxBacklogConVar);
    RegisterConCommand(sNetCompressionMethodConVar);
    RegisterConCommand(sNetResendPingMultiplierConVar);
    RegisterConCommand(sNetResendDelayBiasConVar);

    sNetConVarsRegistered = true;
    std::atexit(&UnregisterNetConVars);
  }
} // namespace moho
