#include "CNetDatagramSocketImpl.h"
#include <algorithm>
#include <cstring>
#include <exception>

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
  platform::net::CloseSocket(mSocket);
  if (mEvent != nullptr) {
    platform::net::CloseSocketEvent(mEvent);
  }
}

/**
 * Address: 0x0047F0D0 (FUN_0047F0D0)
 * Address: 0x100796B0 (sub_100796B0)
 *
 * What it does:
 * Broadcast helper that forwards to `Send(..., -1, port)`.
 */
void CNetDatagramSocketImpl::SendDefault(
  CMessage* msg,
  const u_short port
)
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
void CNetDatagramSocketImpl::Send(
  CMessage* msg,
  const u_long address,
  const u_short port
)
{
  sockaddr_in to{};
  to.sin_family = AF_INET;
  to.sin_port = htons(port);
  to.sin_addr.s_addr = htonl(address);

  const char* const payloadStart = msg->mBuff.start_;
  const int payloadSize = static_cast<int>(msg->mBuff.end_ - payloadStart);

  const int sent = platform::net::SendTo(mSocket, payloadStart, payloadSize, to);
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
    platform::net::ResetSocketEvent(mEvent);
  }

  static constexpr int kRecvCapacity = static_cast<int>(kNetIoBufferSize);
  char recvBuffer[kNetIoBufferSize];

  sockaddr_in from{};
  int bytesRead = platform::net::RecvFrom(mSocket, recvBuffer, kRecvCapacity, &from);

  // The socket is open to anyone on the network. Handling a datagram runs
  // script, so stop after a batch rather than chase a flood: the rest stays
  // queued, and the next `recvfrom` re-arms the read event for it.
  constexpr int kMaxDatagramsPerPull = 64;
  int datagramsHandled = 0;

  if (bytesRead >= 0) {
    CMessage msg{};
    do {
      msg.mBuff.Resize(bytesRead, 0);
      // Raw datagram receive blob into the message buffer.
      std::copy_n(recvBuffer, static_cast<size_t>(bytesRead), msg.mBuff.start_);

      const u_short peerPort = ntohs(from.sin_port);
      const u_long peerAddress = ntohl(from.sin_addr.s_addr);

      // A sender always transmits one whole message, so its header's
      // wire-size is the datagram length. Handlers read the payload by that
      // header size: anything else would read past the datagram.
      if (bytesRead >= 3 && msg.GetSize() == static_cast<unsigned>(bytesRead)) {
        try {
          mDatagramHandler->OnDatagram(&msg, this, peerAddress, peerPort);
        } catch (const std::exception& e) {
          // A short payload ends in `BinaryReader::PrematureEOF`; unhandled,
          // it would abort the task thread that owns this socket.
          static int sMalformedLogged = 0;
          if (sMalformedLogged < 16) {
            ++sMalformedLogged;
            gpg::Logf(
              "CNetDatagramSocketImpl::Pull: dropping malformed datagram from %s:%d: %s",
              NET_GetDottedOctetFromUInt32(peerAddress).c_str(),
              static_cast<int>(peerPort),
              e.what()
            );
          }
        }
      }

      msg.Clear();

      if (++datagramsHandled >= kMaxDatagramsPerPull) {
        return;
      }

      std::memset(&from, 0, sizeof(from));
      bytesRead = platform::net::RecvFrom(mSocket, recvBuffer, kRecvCapacity, &from);
    } while (bytesRead >= 0);
  }

  if (platform::net::LastError() != platform::net::error::kWouldBlock) {
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
    const HANDLE h = platform::net::CreateSocketEvent();
    mEvent = h;
    platform::net::SelectSocketEvents(mSocket, h, platform::net::kEventRead);
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
CNetDatagramSocketImpl::CNetDatagramSocketImpl(
  INetDatagramHandler* handler,
  const platform::net::Socket sock
)
  : mDatagramHandler(handler)
  , mSocket(sock)
  , mEvent(nullptr)
{}
