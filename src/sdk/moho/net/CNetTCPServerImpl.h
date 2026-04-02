#pragma once

#include "INetTCPServer.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E04568
   * COL:     0x00E609E8
   *
   * Log/code strings:
   *  - CNetTCPServerImpl::Accept(): accept() failed: %s
   */
  class CNetTCPServerImpl : public INetTCPServer
  {
  public:
    /**
     * Address: 0x00483220 (FUN_00483220)
     * Address: 0x1007CFF0 (sub_1007CFF0)
     * Slot: 0
     *
     * What it does:
     * Closes active listening socket and tears down server object.
     */
    ~CNetTCPServerImpl() override;

    /**
     * Address: 0x004832A0 (FUN_004832A0)
     * Address: 0x1007D0B0 (sub_1007D0B0)
     * Slot: 1
     *
     * What it does:
     * Returns listening socket's local port.
     */
    u_short GetLocalPort() override;

    /**
     * Address: 0x004832D0 (FUN_004832D0)
     * Address: 0x1007D0E0 (sub_1007D0E0)
     * Slot: 2
     *
     * What it does:
     * Accepts next inbound client and wraps it into CNetTCPBuf.
     */
    INetTCPSocket* Accept() override;

    /**
     * Address: 0x00483370 (FUN_00483370)
     * Address: 0x1007D180 (sub_1007D180)
     * Slot: 3
     *
     * What it does:
     * Closes listening socket and marks it invalid.
     */
    void CloseSocket() override;

    /**
     * Address: 0x00483210 (FUN_00483210)
     *
     * What it does:
     * Initializes CNetTCPServerImpl around already-open listening socket.
     */
    explicit CNetTCPServerImpl(SOCKET socket) noexcept;

  private:
    SOCKET mSocket{INVALID_SOCKET}; // +0x04
  };
  static_assert(sizeof(CNetTCPServerImpl) == 0x8, "CNetTCPServerImpl size must be 0x8");
} // namespace moho
