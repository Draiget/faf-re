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

  protected:
    /**
     * Address: 0x00485A10 (FUN_00485A10)
     *
     * What it does:
     * Restores the interface vftable (0x00E060C8). Non-virtual: the vftable
     * holds only the two pure slots above. User-provided rather than
     * `= default` because the binary keeps the vptr reset: `~CNetUDPConnector`
     * inlines it on the base subobject at +0x04 (0x00489CBA), and the
     * out-of-line copy is reached only from CNetUDPConnector's ctor/dtor EH
     * unwind funclets (`mov eax,[ebp+4]; add eax,4; jmp 0x00485A10` at
     * 0x00BB33D8, and 0x00B8999A). Unwind funclets only ever run destructors,
     * so this is not the constructor; the constructor is implicit and
     * inlined at every construction site.
     */
    ~INetNATTraversalHandler() {}
  };

  static_assert(sizeof(INetNATTraversalHandler) == 0x4, "INetNATTraversalHandler size must be 0x4");
} // namespace moho
