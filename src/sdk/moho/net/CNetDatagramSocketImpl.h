#pragma once
#include "INetDatagramSocket.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E03EE8
   * COL:     0x00E608B4
   *
   * Log/code strings:
   *  - CNetDatagramSocketImpl::Send: send() failed: %s
   *  - CNetBroadcastSocketImpl::Pull: recv() failed: %s
   *
   * Layout evidence:
   * - FA 0x0047F360 (FUN_0047F360, NET_OpenDatagramSocket), inlined init
   * - MohoEngine 0x10079940 (Moho::NET_OpenDatagramSocket), inlined init
   */
  class CNetDatagramSocketImpl : public INetDatagramSocket
  {
  public:
    /**
     * Address: 0x0047F050 (FUN_0047F050)
     * Address: 0x10079630 (sub_10079630)
     * Slot: 0
     *
     * CNetDatagramSocketImpl
     *
     * IDA signature (FA):
     * Moho::CNetDatagramSocketImpl *__thiscall Moho::CNetDatagramSocketImpl::~CNetDatagramSocketImpl(
     *   Moho::CNetDatagramSocketImpl *this, char a2
     * );
     *
     * IDA signature (MohoEngine):
     * void *__thiscall sub_10079630(void *this, char a2);
     *
     * What it does:
     * Closes UDP socket/event resources and tears down datagram socket object.
     */
    ~CNetDatagramSocketImpl() override;

    /**
     * Address: 0x0047F0D0 (FUN_0047F0D0)
     * Address: 0x100796B0 (sub_100796B0)
     * Slot: 1
     *
     * CMessage *, u_short
     *
     * IDA signature (FA):
     * void __thiscall Moho::CNetDatagramSocketImpl::SendDefault(
     *   Moho::CNetDatagramSocketImpl *this, gpg::fastvector_n64_char *dat, int port
     * );
     *
     * IDA signature (MohoEngine):
     * int __thiscall sub_100796B0(void *this, int a2, int a3);
     *
     * What it does:
     * Broadcast helper that forwards to `Send(..., -1, port)`.
     */
    void SendDefault(CMessage* msg, u_short port) override;

    /**
     * Address: 0x0047F0F0 (FUN_0047F0F0)
     * Address: 0x100796D0 (sub_100796D0)
     * Slot: 2
     *
     * CMessage *, u_long, u_short
     *
     * IDA signature (FA):
     * void __thiscall Moho::CNetDatagramSocketImpl::Send(
     *   Moho::CNetDatagramSocketImpl *this, gpg::fastvector_n64_char *dat, u_long addr, u_short port
     * );
     *
     * IDA signature (MohoEngine):
     * void __thiscall sub_100796D0(SOCKET *this, int a2, u_long hostlong, u_short hostshort);
     *
     * What it does:
     * Sends one datagram packet to target IPv4 address/port and logs
     * truncation or Winsock send failures.
     */
    void Send(CMessage* msg, u_long address, u_short port) override;

    /**
     * Address: 0x0047F190 (FUN_0047F190)
     * Address: 0x10079770 (sub_10079770)
     * Slot: 3
     *
     * void ()
     *
     * IDA signature (FA):
     * void __thiscall Moho::CNetDatagramSocketImpl::Pull(Moho::CNetDatagramSocketImpl *this);
     *
     * IDA signature (MohoEngine):
     * void __thiscall sub_10079770(int this);
     *
     * What it does:
     * Drains non-blocking UDP receive queue and dispatches each datagram to
     * `INetDatagramHandler`.
     */
    void Pull() override;

    /**
     * Address: 0x0047F330 (FUN_0047F330)
     * Address: 0x10079910 (sub_10079910)
     * Slot: 4
     *
     * HANDLE ()
     *
     * IDA signature (FA):
     * HANDLE __thiscall Moho::CNetDatagramSocketImpl::CreateEvent(Moho::CNetDatagramSocketImpl *this);
     *
     * IDA signature (MohoEngine):
     * SOCKET __thiscall sub_10079910(SOCKET *this);
     *
     * What it does:
     * Lazily creates/socket-binds a WSA event object for `FD_READ`.
     */
    HANDLE CreateEvent() override;

    /**
     * Address: <synthetic host-build wrapper>
     *
     * Binary evidence:
     * - 0x0047F360 (FUN_0047F360, NET_OpenDatagramSocket)
     * - 0x0047F44E (inlined allocation/init block inside FUN_0047F360)
     * - 0x10079940 (Moho::NET_OpenDatagramSocket)
     *
     * INetDatagramHandler *, SOCKET
     *
     * IDA signature (FA, inlined in open):
     * Moho::CNetDatagramSocketImpl *__cdecl Moho::NET_OpenDatagramSocket(
     *   u_short hostshort, Moho::INetDatagramHandler *datagramHandler
     * );
     *
     * IDA signature (MohoEngine, inlined in open):
     * struct Moho::INetDatagramSocket *__cdecl Moho::NET_OpenDatagramSocket(Moho *this, int a2);
     *
     * What it does:
     * Initializes handler/socket/event fields for datagram-socket objects.
     * In FA/Moho binaries this initialization is inlined in
     * `NET_OpenDatagramSocket`.
     */
    CNetDatagramSocketImpl(INetDatagramHandler* handler, SOCKET sock);

  private:
    INetDatagramHandler* mDatagramHandler{nullptr}; // +0x04
    SOCKET mSocket{INVALID_SOCKET};                 // +0x08
    HANDLE mEvent{nullptr};                         // +0x0C
  };
  static_assert(sizeof(CNetDatagramSocketImpl) == 0x10, "CNetDatagramSocketImpl must be 0x10");
} // namespace moho
