#include "CNetDatagramSocketImpl.h"

#include <cstring>

#include "CMessage.h"
#include "Common.h"
#include "gpg/core/utils/Logging.h"
#include "INetDatagramHandler.h"
using namespace moho;

/**
 * Address: 0x0047F050 (FUN_0047F050)
 * Address: 0x10079630 (sub_10079630)
 *
 * What it does:
 * Releases datagram socket handle and optional WSA event.
 */
CNetDatagramSocketImpl::~CNetDatagramSocketImpl()
{
  closesocket(mSocket);
  if (mEvent != nullptr) {
    WSACloseEvent(mEvent);
  }
}

/**
 * Address: 0x0047F0D0 (FUN_0047F0D0)
 * Address: 0x100796B0 (sub_100796B0)
 *
 * What it does:
 * Broadcast helper that forwards to `Send(..., -1, port)`.
 */
void CNetDatagramSocketImpl::SendDefault(CMessage* msg, const u_short port)
{
  Send(msg, static_cast<u_long>(-1), port);
}

/**
 * Address: 0x0047F0F0 (FUN_0047F0F0)
 * Address: 0x100796D0 (sub_100796D0)
 *
 * What it does:
 * Sends one UDP datagram and logs truncation/errors.
 */
void CNetDatagramSocketImpl::Send(CMessage* msg, const u_long address, const u_short port)
{
  sockaddr_in to{};
  to.sin_family = AF_INET;
  to.sin_port = htons(port);
  to.sin_addr.s_addr = htonl(address);

  const char* const payloadStart = msg->mBuff.start_;
  const int payloadSize = static_cast<int>(msg->mBuff.end_ - payloadStart);

  const int sent =
    sendto(mSocket, payloadStart, payloadSize, 0, reinterpret_cast<const sockaddr*>(&to), static_cast<int>(sizeof(to)));
  if (sent >= 0) {
    if (sent < payloadSize) {
      gpg::Logf("CNetDatagramSocketImpl::Send: msg truncated, only %d of %d bytes sent.", sent, payloadSize);
    }
  } else {
    gpg::Logf("CNetDatagramSocketImpl::Send: send() failed: %s", NET_GetWinsockErrorString());
  }
}

/**
 * Address: 0x0047F190 (FUN_0047F190)
 * Address: 0x10079770 (sub_10079770)
 *
 * What it does:
 * Drains datagrams in non-blocking mode and dispatches each payload to the
 * bound datagram handler.
 */
void CNetDatagramSocketImpl::Pull()
{
  if (mEvent != nullptr) {
    WSAResetEvent(mEvent);
  }

  static constexpr int kRecvCapacity = static_cast<int>(kNetIoBufferSize);
  char recvBuffer[kNetIoBufferSize];

  sockaddr_in from{};
  int fromLen = static_cast<int>(sizeof(from));
  int bytesRead = recvfrom(mSocket, recvBuffer, kRecvCapacity, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);

  if (bytesRead >= 0) {
    CMessage msg{};
    do {
      msg.mBuff.Resize(bytesRead, 0);
      std::memcpy(msg.mBuff.start_, recvBuffer, static_cast<size_t>(bytesRead));

      const u_short peerPort = ntohs(from.sin_port);
      const u_long peerAddress = ntohl(from.sin_addr.s_addr);
      mDatagramHandler->OnDatagram(&msg, this, peerAddress, peerPort);

      msg.Clear();

      std::memset(&from, 0, sizeof(from));
      fromLen = static_cast<int>(sizeof(from));
      bytesRead = recvfrom(mSocket, recvBuffer, kRecvCapacity, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
    } while (bytesRead >= 0);
  }

  if (WSAGetLastError() != WSAEWOULDBLOCK) {
    gpg::Logf("CNetBroadcastSocketImpl::Pull: recv() failed: %s", NET_GetWinsockErrorString());
  }
}

/**
 * Address: 0x0047F330 (FUN_0047F330)
 * Address: 0x10079910 (sub_10079910)
 *
 * What it does:
 * Lazily allocates WSA event and subscribes socket to `FD_READ`.
 */
HANDLE CNetDatagramSocketImpl::CreateEvent()
{
  if (mEvent == nullptr) {
    const HANDLE h = WSACreateEvent();
    mEvent = h;
    WSAEventSelect(mSocket, h, FD_READ);
  }
  return mEvent;
}

/**
 * Address: 0x0047F030 (FUN_0047F030)
 *
 * Binary evidence:
 * - 0x0047F030 (FUN_0047F030, object-init lane)
 * - 0x0047F360 (FUN_0047F360, NET_OpenDatagramSocket)
 * - 0x0047F44E (inlined object-init block inside FUN_0047F360)
 * - 0x10079940 (Moho::NET_OpenDatagramSocket)
 *
 * What it does:
 * Initializes datagram socket object fields; this same field-init lane is also
 * emitted inline inside `NET_OpenDatagramSocket`.
 */
CNetDatagramSocketImpl::CNetDatagramSocketImpl(INetDatagramHandler* handler, const SOCKET sock)
  : mDatagramHandler(handler)
  , mSocket(sock)
  , mEvent(nullptr)
{}
