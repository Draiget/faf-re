#pragma once

#include <cstddef>

#include "CMessage.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E060C8
   * COL:		0x00E60E9C
   */
  class INetNATTraversalHandler
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * Implementer evidence:
     * - FA 0x0048BA80 (Moho::CNetUDPConnector::Func1, mapped as `PrepareTraversalMessage`)
     * - MohoEngine 0x10085450 (sub_10085450)
     *
     * What it does:
     * Initializes a NAT traversal message by resetting payload and writing
     * packet-type byte `PT_NATTraversal` (8).
     */
    virtual void PrepareTraversalMessage(CMessage* msg) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * Implementer evidence:
     * - FA 0x0048BAE0 (Moho::CNetUDPConnector::ReceivePacket)
     * - MohoEngine 0x100854B0 (sub_100854B0)
     *
     * What it does:
     * Queues raw NAT traversal payload for UDP send toward (`addr`,`port`).
     */
    virtual void ReceivePacket(u_long addr, u_short port, const char* dat, size_t size) = 0;
  };

  static_assert(sizeof(INetNATTraversalHandler) == 0x4, "INetNATTraversalHandler size must be 0x4");
} // namespace moho
