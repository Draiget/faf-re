#pragma once

#include "platform/Platform.h"

namespace moho
{
  class INetDatagramHandler;
  struct CMessage;

  /**
   * VFTABLE: 0x00E03ED0
   * COL:  0x00E60900
   */
  class INetDatagramSocket
  {
  public:
    /**
     * Address: 0x0047EF40 (FUN_0047EF40)
     * Address: 0x10079520 (sub_10079520)
     * Slot: 0
     *
     * Demangled: public: __thiscall Moho::INetDatagramSocket::~INetDatagramSocket()
     *
     * What it does:
     * Base deleting-destructor slot entry for datagram socket interface.
     */
    virtual ~INetDatagramSocket();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     */
    virtual void SendDefault(CMessage* message, u_short) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     */
    virtual void Send(CMessage*, u_long address, u_short port) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     */
    virtual void Pull() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     */
    virtual HANDLE CreateEvent() = 0;
  };
  static_assert(sizeof(INetDatagramSocket) == 0x4, "INetDatagramSocket size must be 0x4");

  /**
   * Address: 0x0047F360 (FUN_0047F360)
   * Address: 0x10079940 (Moho::NET_OpenDatagramSocket)
   *
   * What it does:
   * Opens/configures non-blocking broadcast UDP socket, binds it to `port`,
   * and returns datagram-socket implementation bound to `handler`.
   * On allocation failure, returns null without closing the socket (matches
   * FA/Moho behavior).
   * The `CNetDatagramSocketImpl` field initialization sequence is inlined in
   * this function in both FA and MohoEngine.
   */
  INetDatagramSocket* NET_OpenDatagramSocket(u_short port, INetDatagramHandler* handler);

} // namespace moho
