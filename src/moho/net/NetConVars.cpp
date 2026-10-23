#include "moho/net/NetConVars.h"

#include <cstdint>

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
    /**
     * Address: 0x00BC4E70 (FUN_00BC4E70, dynamic initializer for `gTConVar_net_DebugCrash`)
     * Address: 0x00BEFAF0 (FUN_00BEFAF0, dynamic atexit destructor for `gTConVar_net_DebugCrash`)
     */
    TConVar<bool> gTConVar_net_DebugCrash("net_DebugCrash", "If true, crash.", &net_DebugCrash);

    /**
     * Address: 0x00BC4EB0 (FUN_00BC4EB0, dynamic initializer for `gTConVar_net_DebugLevel`)
     * Address: 0x00BEFB20 (FUN_00BEFB20, dynamic atexit destructor for `gTConVar_net_DebugLevel`)
     */
    TConVar<int32_t> gTConVar_net_DebugLevel("net_DebugLevel", "Amount of network debug spew", &net_DebugLevel);

    /**
     * Address: 0x00BC4EF0 (FUN_00BC4EF0, dynamic initializer for `gTConVar_net_AckDelay`)
     * Address: 0x00BEFB50 (FUN_00BEFB50, dynamic atexit destructor for `gTConVar_net_AckDelay`)
     */
    TConVar<int32_t> gTConVar_net_AckDelay("net_AckDelay", "Number of milliseconds to delay before sending ACKs", &net_AckDelay);

    /**
     * Address: 0x00BC4F30 (FUN_00BC4F30, dynamic initializer for `gTConVar_net_SendDelay`)
     * Address: 0x00BEFB80 (FUN_00BEFB80, dynamic atexit destructor for `gTConVar_net_SendDelay`)
     */
    TConVar<int32_t> gTConVar_net_SendDelay("net_SendDelay", "Number of milliseconds to delay before sending Data", &net_SendDelay);

    /**
     * Address: 0x00BC4F70 (FUN_00BC4F70, dynamic initializer for `gTConVar_net_LogPackets`)
     * Address: 0x00BEFBB0 (FUN_00BEFBB0, dynamic atexit destructor for `gTConVar_net_LogPackets`)
     */
    TConVar<bool> gTConVar_net_LogPackets("net_LogPackets", "Log all incomming/outgoing packets.", &net_LogPackets);

    /**
     * Address: 0x00BC4FB0 (FUN_00BC4FB0, dynamic initializer for `gTConVar_net_MinResendDelay`)
     * Address: 0x00BEFBE0 (FUN_00BEFBE0, dynamic atexit destructor for `gTConVar_net_MinResendDelay`)
     */
    TConVar<int32_t> gTConVar_net_MinResendDelay("net_MinResendDelay", "Minimum number of milliseconds to delay before resending a packet.", &net_MinResendDelay);

    /**
     * Address: 0x00BC4FF0 (FUN_00BC4FF0, dynamic initializer for `gTConVar_net_MaxResendDelay`)
     * Address: 0x00BEFC10 (FUN_00BEFC10, dynamic atexit destructor for `gTConVar_net_MaxResendDelay`)
     */
    TConVar<int32_t> gTConVar_net_MaxResendDelay("net_MaxResendDelay", "Maximum number of milliseconds to delay before resending a packet.", &net_MaxResendDelay);

    /**
     * Address: 0x00BC5030 (FUN_00BC5030, dynamic initializer for `gTConVar_net_MaxSendRate`)
     * Address: 0x00BEFC40 (FUN_00BEFC40, dynamic atexit destructor for `gTConVar_net_MaxSendRate`)
     */
    TConVar<int32_t> gTConVar_net_MaxSendRate("net_MaxSendRate", "Maximum number of bytes to send per second to any one client.", &net_MaxSendRate);

    /**
     * Address: 0x00BC5070 (FUN_00BC5070, dynamic initializer for `gTConVar_net_MaxBacklog`)
     * Address: 0x00BEFC70 (FUN_00BEFC70, dynamic atexit destructor for `gTConVar_net_MaxBacklog`)
     */
    TConVar<int32_t> gTConVar_net_MaxBacklog("net_MaxBacklog", "Maximum number of bytes to backlog to any one client.", &net_MaxBacklog);

    /**
     * Address: 0x00BC50B0 (FUN_00BC50B0, dynamic initializer for `gTConVar_net_CompressionMethod`)
     * Address: 0x00BEFCA0 (FUN_00BEFCA0, dynamic atexit destructor for `gTConVar_net_CompressionMethod`)
     */
    TConVar<int32_t> gTConVar_net_CompressionMethod("net_CompressionMethod", "Compression method, 0=none, 1=deflate.  Only takes effect when connections are first established.", &net_CompressionMethod);

    /**
     * Address: 0x00BC50F0 (FUN_00BC50F0, dynamic initializer for `gTConVar_net_ResendPingMultiplier`)
     * Address: 0x00BEFCD0 (FUN_00BEFCD0, dynamic atexit destructor for `gTConVar_net_ResendPingMultiplier`)
     */
    TConVar<float> gTConVar_net_ResendPingMultiplier("net_ResendPingMultiplier", "The resend delay is ping*new_ResendPingMultiplier+net_ResendDelayBias.", &net_ResendPingMultiplier);

    /**
     * Address: 0x00BC5130 (FUN_00BC5130, dynamic initializer for `gTConVar_net_ResendDelayBias`)
     * Address: 0x00BEFD00 (FUN_00BEFD00, dynamic atexit destructor for `gTConVar_net_ResendDelayBias`)
     */
    TConVar<int32_t> gTConVar_net_ResendDelayBias("net_ResendDelayBias", "The resend delay is ping*new_ResendPingMultiplier+net_ResendDelayBias.", &net_ResendDelayBias);
  } // namespace
} // namespace moho
