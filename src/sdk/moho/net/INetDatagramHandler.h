#pragma once

#include "platform/Platform.h"

namespace moho
{
  class INetDatagramSocket;
  struct CMessage;

  /**
   * VFTABLE: 0x00E3EC88
   * COL:     0x00E97764
   */
  class INetDatagramHandler
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * Implementer evidence:
     * - FA: 0x007C5840 (CLobby datagram handler), 0x007BFB70 (CDiscoveryService datagram handler)
     * - MohoEngine: 0x1038DA40 (?OnDatagram@CLobby@Moho@@...), 0x10388200 (CDiscoveryService datagram handler)
     *
     * What it does:
     * Dispatch point for one received UDP datagram with sender endpoint.
     */
    virtual void OnDatagram(CMessage* msg, INetDatagramSocket* socket, u_long address, u_short port) = 0;
  };
  static_assert(sizeof(INetDatagramHandler) == 0x4, "INetDatagramHandler size should be 0x4");
} // namespace moho
