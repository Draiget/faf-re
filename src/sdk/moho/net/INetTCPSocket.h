#pragma once

#include "gpg/core/streams/Stream.h"
#include "platform/Platform.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E044E4
   * COL:		0x00E60AD0
   */
  class INetTCPSocket : public gpg::Stream
  {
  public:
    /**
     * Address: 0x00482800 (FUN_00482800)
     * Address: 0x1007C4A0 (sub_1007C4A0)
     * Slot: 0
     *
     * What it does:
     * Base deleting-destructor entry for TCP stream sockets.
     */
    ~INetTCPSocket() override;

    /**
     * Slot: 10
     * Address: 0x00A82547 (_purecall)
     */
    virtual u_short GetPort() = 0;

    /**
     * Slot: 11
     * Address: 0x00A82547 (_purecall)
     */
    virtual u_long GetPeerAddr() = 0;

    /**
     * Slot: 12
     * Address: 0x00A82547 (_purecall)
     */
    virtual u_short GetPeerPort() = 0;

    /**
     * Address: 0x004827E0 (FUN_004827E0)
     *
     * What it does:
     * Initializes stream base and installs INetTCPSocket vtable.
     */
    INetTCPSocket();

    INetTCPSocket(const INetTCPSocket&) = delete;
    INetTCPSocket& operator=(const INetTCPSocket&) = delete;
  };
  static_assert(sizeof(INetTCPSocket) == 0x1C, "INetTCPSocket size must be 0x1C");

  /**
   * Address: 0x004830A0 (FUN_004830A0)
   * Address: 0x1007CE00 (sub_1007CE00)
   *
   * What it does:
   * Opens and connects a TCP stream socket to `address:port`.
   */
  INetTCPSocket* NET_TCPConnect(u_long address, u_short port);
} // namespace moho
