#pragma once

#include <cstdint>

#include "legacy/containers/String.h"

namespace moho
{
  enum ENetConnectionState
  {
    kNetStatePending = 0,
    kNetStateConnecting = 1,
    kNetStateAnswering = 2,
    kNetStateEstablishing = 3,
    kNetStateTimedOut = 4,
    kNetStateErrored = 5,
  };

  enum EPacketType : uint8_t
  {
    /**
     * Handshake from initiator.
     *
     * Binary evidence:
     * - FA 0x0048A288 (CNetUDPConnector::ReceiveData -> state 0 -> ProcessConnect)
     */
    PT_Connect = 0,

    /**
     * Handshake reply.
     *
     * Binary evidence:
     * - FA 0x0048A288 (state 1 -> ProcessAnswer)
     */
    PT_Answer = 1,

    /**
     * Reserved/legacy control packet (recognized but not implemented in current FA path).
     *
     * Binary evidence:
     * - FA 0x0048A288 (state < 9 accepted; non-switched values hit "unimplemented packet")
     */
    PT_ResetSerial = 2,

    /**
     * Reserved/legacy control packet (recognized but not implemented in current FA path).
     *
     * Binary evidence:
     * - FA 0x0048A288 (state < 9 accepted; non-switched values hit "unimplemented packet")
     */
    PT_SerialReset = 3,

    /**
     * Reliable payload data frame.
     *
     * Binary evidence:
     * - FA 0x0048A288 (state 4 -> ProcessData)
     */
    PT_Data = 4,

    /**
     * Ack-only frame.
     *
     * Binary evidence:
     * - FA 0x00488300 (SendData emits type 5 for ack flush path)
     * - FA 0x0048A288 (state 5 -> handler at 0x00487310)
     */
    PT_Ack = 5,

    /**
     * Keep-alive/liveness frame.
     *
     * Binary evidence:
     * - FA 0x00488300 (SendData emits type 6 on keep-alive cadence)
     * - FA 0x0048A288 (state 6 -> handler at 0x00487340)
     */
    PT_KeepAlive = 6,

    /**
     * Shutdown/goodbye frame.
     *
     * Binary evidence:
     * - FA 0x00488AA0 (NextPacket_7 sets state=7)
     * - FA 0x0048A288 (state 7 -> handler at 0x00487370)
     */
    PT_Goodbye = 7,

    /**
     * NAT traversal helper frame.
     *
     * Binary evidence:
     * - FA 0x0048A288 (explicit state == 8 NAT traversal provider handling)
     */
    PT_NATTraversal = 8,

    PT_NumTypes
  };

  void NetPacketTypeToStr(EPacketType state, msvc8::string& out);
  const char* NetConnectionStateToStr(ENetConnectionState state);

  enum ENetCompressionMethod : uint8_t
  {
    NETCOMP_None = 0,
    NETCOMP_Deflate = 1,
  };

  enum class ENetProtocolType : int32_t
  {
    kNone = 0,
    kTcp = 1,
    kUdp = 2
  };
} // namespace moho
