#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "INetNATTraversalHandler.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E3D740
   * COL:		0x00E969A4
   */
  class INetNATTraversalProvider
  {
  public:
    static gpg::RType* sType;

    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * Implementer evidence:
     * - FA 0x007B9070 (Moho::CGpgNetInterface::Func1, mapped as `SetTraversalHandler`)
     * - MohoEngine 0x10381F80 (sub_10381F80)
     *
     * What it does:
     * Registers or clears NAT traversal send handler for a local UDP port.
     */
    virtual void SetTraversalHandler(int port, boost::shared_ptr<INetNATTraversalHandler>* handler) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * Implementer evidence:
     * - FA 0x007B9160 (Moho::CGpgNetInterface::ReceivePacket)
     * - MohoEngine 0x10382070 (sub_10382070)
     *
     * What it does:
     * Forwards received NAT payload from connector layer into GPGNet command
     * channel (`ProcessNatPacket`).
     */
    virtual void ReceivePacket(u_long address, u_short port, const char* dat, size_t size) = 0;

  protected:
    /**
     * Address: 0x007B64F0 (FUN_007B64F0)
     *
     * What it does:
     * Restores the interface vftable (0x00E3D740). Non-virtual: the vftable
     * holds only the two pure slots above. User-provided rather than
     * `= default` because the binary keeps the vptr reset: `~CGpgNetInterface`
     * inlines it on the base subobject at +0x18 (0x007B69FC), and the
     * out-of-line copy is reached only from CGpgNetInterface's ctor/dtor EH
     * unwind funclets (`mov eax,[ebp+4]; add eax,18h; jmp 0x007B64F0` at
     * 0x00BB44C8, and 0x00BB008A). Unwind funclets only ever run
     * destructors, so this is not the constructor; the constructor is
     * implicit and inlined at every construction site (0x007B6829).
     */
    ~INetNATTraversalProvider() {}
  };

  static_assert(sizeof(INetNATTraversalProvider) == 0x4, "INetNATTraversalProvider size must be 0x4");
} // namespace moho
