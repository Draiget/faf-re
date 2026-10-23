#pragma once

#include "platform/Platform.h"

namespace moho
{
  class INetTCPSocket;

  /**
   * VFTABLE: 0x00E0451C
   * COL:		0x00E60A88
   */
  class INetTCPServer
  {
  public:
    /**
     * Address: 0x00482750 (FUN_00482750)
     * Address: 0x1007C560 (sub_1007C560)
     * Slot: 0
     *
     * What it does:
     * Base deleting-destructor entry for TCP server interface.
     */
    virtual ~INetTCPServer();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     */
    virtual u_short GetLocalPort() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     */
    virtual INetTCPSocket* Accept() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     */
    virtual void CloseSocket() = 0;

    /**
     * Address: 0x00482740 (FUN_00482740)
     * Address: 0x00483260 (FUN_00483260, ctor alias lane)
     *
     * What it does:
     * Initializes interface vtable for TCP server instances.
     */
    INetTCPServer();

    INetTCPServer(const INetTCPServer&) = delete;
    INetTCPServer& operator=(const INetTCPServer&) = delete;
  };
  static_assert(sizeof(INetTCPServer) == 0x4, "INetTCPServer size must be 0x4");

  /**
   * Address: 0x00483390 (FUN_00483390)
   * Address: 0x1007D1A0 (sub_1007D1A0)
   *
   * What it does:
   * Creates a listening TCP server socket bound to `hostAddress:port`.
   */
  INetTCPServer* NET_CreateTCPServer(u_long hostAddress, u_short port);
} // namespace moho
