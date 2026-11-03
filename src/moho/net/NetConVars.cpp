#include "moho/net/NetConVars.h"

#include <atomic>
#include <cstdint>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"

namespace moho
{
  bool net_DebugCrash = false;                     // 0x010A6380
  bool net_LogPackets = false;                     // 0x010A6381
  int32_t net_DebugLevel = 0;                      // 0x010A6384
  // Initial values are the .data words at those addresses in the shipped PE.
  int32_t net_AckDelay = 25;                       // 0x00F58DE0
  int32_t net_SendDelay = 25;                      // 0x00F58DE4
  int32_t net_MinResendDelay = 100;                // 0x00F58DE8
  int32_t net_MaxResendDelay = 1000;               // 0x00F58DEC
  int32_t net_MaxSendRate = 2048;                  // 0x00F58DF0
  int32_t net_MaxBacklog = 2048;                   // 0x00F58DF4
  int32_t net_CompressionMethod = NETCOMP_Deflate; // 0x00F58DF8
  float net_ResendPingMultiplier = 1.0f;           // 0x00F58DFC
  int32_t net_ResendDelayBias = 25;                // 0x00F58E00

  // Engine additions, not in the binary. Read when a game's client manager is
  // made (`net_CheckOrderStreams`) or for every message sent
  // (`net_DebugAlterOrdersTo`).
  int32_t net_CheckOrderStreams = 1;
  // Read as a game finishes loading (issue #285).
  int32_t net_PeerFeatures = 0;
  int32_t net_DebugAlterOrdersTo = -1;
  // Read when a game's UDP socket is made (NET_MakeUDPConnector); 0 keeps the
  // system's buffer size, as the binary does (issue #236).
  int32_t net_SocketRecvBuffer = 0;
  int32_t net_SocketSendBuffer = 0;
  // Issue #233: 1 runs the peer links in the game when the adapter is
  // faf-netbridge (NetlinkPeers.cpp); 0 leaves them to the adapter, as the
  // binary does. Read when the game reports Idle.
  int32_t net_InEngineLinks = 0;
  // Issue #237: 1 resends a packet early once the peer has 3 later ones
  // (CNetUDPConnection::FastRetransmitFromMask); 0 waits for the resend
  // timer, as the binary does. Live.
  int32_t net_FastRetransmit = 0;
  // Issue #237: with net_FastRetransmit, a packet's first resend is due this
  // many round trips after its send, under net_MinResendDelay and
  // net_ResendDelayBias. The game sends too few packets for acknowledgements to
  // show a loss sooner. Live.
  float net_FastResendPings = 1.15f;
  // Issue #237: with net_FastRetransmit, a received packet is acknowledged within
  // this many ms, if net_AckDelay is longer. The peer's ping includes the wait,
  // so its timer can't go under the time an acknowledgement takes without it. Live.
  int32_t net_FastAckDelay = 5;
  // Issue #274: 1 makes the game run every peer link itself with the launcher
  // talking to it directly, no ICE adapter (NetlinkPeers.cpp,
  // docs/LAUNCHER_NATIVE_NETWORK.md); 0 is the adapter path. Read when the
  // game reports Idle.
  int32_t net_NativeNet = 0;
  // Issue #274: in native mode, 1 offers a WebRTC data channel to peers that are
  // our builds too (#239). Read when a link starts.
  int32_t net_NativeNetWebRtc = 0;
  // Issue #240: in native mode, with peers running our build, game datagrams go
  // on a redundant lane that repeats each up to this many times until acked;
  // 0 sends them plainly. Read when a link starts.
  int32_t net_NativeNetRedundancy = 2;
  // Issue #236, diagnostics: log every beat that became available this many ms
  // or more after the one before it (waiting on a peer's data); 0 logs nothing.
  // Live.
  int32_t net_LogBeatWaitMs = 0;
  // Diagnostics: every this many beats log the UDP connections' totals: packets,
  // bytes, resends, acks and mean ping; 0 logs nothing. Live.
  int32_t net_LogTraffic = 0;
  // Diagnostics: log a beat the main thread took this many ms or more after the one
  // before it, which is the pause a player sees; 0 logs nothing. Live.
  int32_t net_LogShownBeatMs = 0;
  NetTrafficTotals gNetTraffic;
  // Issue #236, test only: once beat net_TestBurstBeat is available, this game
  // sends net_TestBurstBytes incompressible filler bytes to every peer on the
  // ordered stream, the way a large order burst occupies it; peers drop it.
  // -1 / 0 (the defaults) send nothing.
  int32_t net_TestBurstBeat = -1;
  int32_t net_TestBurstBytes = 0;

  namespace
  {
    TConVar<int32_t> gTConVar_net_FastRetransmit(
      "net_FastRetransmit",
      "1: resend a packet once the peer has received 3 later ones or after net_FastResendPings round trips, and acknowledge within net_FastAckDelay; 0 (default) is as shipped.",
      &net_FastRetransmit
    );

    TConVar<float> gTConVar_net_FastResendPings(
      "net_FastResendPings",
      "With net_FastRetransmit, a packet's first resend is due this many round trips after its send (default 1.15).",
      &net_FastResendPings
    );

    TConVar<int32_t> gTConVar_net_FastAckDelay(
      "net_FastAckDelay",
      "With net_FastRetransmit, acknowledge a received packet within this many ms, if net_AckDelay is longer (default 5).",
      &net_FastAckDelay
    );

    TConVar<int32_t> gTConVar_net_NativeNet(
      "net_NativeNet",
      "1: the game runs every peer link and the launcher talks to it directly (/nativenet); 0 (default) uses the launcher's ICE adapter.",
      &net_NativeNet
    );

    TConVar<int32_t> gTConVar_net_NativeNetWebRtc(
      "net_NativeNetWebRtc",
      "In native mode, 1: move game datagrams onto a WebRTC data channel with peers running our build; 0 (default): ICE only.",
      &net_NativeNetWebRtc
    );

    TConVar<int32_t> gTConVar_net_LogBeatWaitMs(
      "net_LogBeatWaitMs",
      "Log each beat that became available this many ms or more after the previous one; 0 (default) logs nothing.",
      &net_LogBeatWaitMs
    );

    TConVar<int32_t> gTConVar_net_LogShownBeatMs(
      "net_LogShownBeatMs",
      "Logs a beat the main thread took this many ms or more after the one before it; 0 (default) logs nothing.",
      &net_LogShownBeatMs
    );

    TConVar<int32_t> gTConVar_net_LogTraffic(
      "net_LogTraffic",
      "Every this many beats log the UDP connections' packets, bytes, resends, acks and mean ping; 0 (default) logs nothing.",
      &net_LogTraffic
    );

    TConVar<int32_t> gTConVar_net_TestBurstBeat(
      "net_TestBurstBeat",
      "Test only: at this beat send net_TestBurstBytes filler bytes to every peer; -1 (default) never.",
      &net_TestBurstBeat
    );

    TConVar<int32_t> gTConVar_net_TestBurstBytes(
      "net_TestBurstBytes",
      "Test only: size of the net_TestBurstBeat burst in bytes (incompressible); 0 (default) sends nothing.",
      &net_TestBurstBytes
    );

    TConVar<int32_t> gTConVar_net_NativeNetRedundancy(
      "net_NativeNetRedundancy",
      "In native mode, repeat each game datagram to peers running our build up to this many times until acked (default 2); 0 sends them plainly.",
      &net_NativeNetRedundancy
    );

    TConVar<int32_t> gTConVar_net_InEngineLinks(
      "net_InEngineLinks",
      "1: run the peer links in the game when the ICE adapter is faf-netbridge; 0 (default) leaves them to the adapter.",
      &net_InEngineLinks
    );

    TConVar<int32_t> gTConVar_net_PeerFeatures(
      "net_PeerFeatures",
      "1: tell every other player what this engine supports as the game finishes loading (docs/PEER_FEATURES.md); "
      "0 (default): send nothing, as the original game. Next game.",
      &net_PeerFeatures
    );

    TConVar<int32_t> gTConVar_net_CheckOrderStreams(
      "net_CheckOrderStreams",
      "Check that each player's orders reached every player alike (CommandStreamCheck): 0 off, 1 report who "
      "(default), 2 report and stop the game. Next game.",
      &net_CheckOrderStreams
    );

    TConVar<int32_t> gTConVar_net_SocketRecvBuffer(
      "net_SocketRecvBuffer",
      "Receive buffer of the game's UDP socket in bytes (SO_RCVBUF); 0 keeps the system default. Next game.",
      &net_SocketRecvBuffer
    );

    TConVar<int32_t> gTConVar_net_SocketSendBuffer(
      "net_SocketSendBuffer",
      "Send buffer of the game's UDP socket in bytes (SO_SNDBUF); 0 keeps the system default. Next game.",
      &net_SocketSendBuffer
    );

    TConVar<int32_t> gTConVar_net_DebugAlterOrdersTo(
      "net_DebugAlterOrdersTo",
      "Test only: alter this client's checksum reports sent to the player with this client index (-1 off).",
      &net_DebugAlterOrdersTo
    );

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

  bool NET_FastRetransmitEnabled()
  {
    // The command line is read once; the console variable stays live.
    static const bool sFromCommandLine = CFG_GetArgOption("/fastretransmit", 0u, nullptr);
    return net_FastRetransmit != 0 || sFromCommandLine;
  }

  void NET_CountFastRetransmits(const int count)
  {
    static std::atomic<std::uint64_t> sTotal{0};
    if (count <= 0) {
      return;
    }
    const std::uint64_t before = sTotal.fetch_add(static_cast<std::uint64_t>(count));
    const std::uint64_t after = before + static_cast<std::uint64_t>(count);
    if (before == 0 || before / 1000 != after / 1000) {
      gpg::Logf("NET: %llu packets resent early so far (net_FastRetransmit)", static_cast<unsigned long long>(after));
    }
  }
} // namespace moho
