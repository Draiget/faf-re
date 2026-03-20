#include "INetDatagramSocket.h"

#include <new>

#include "CNetDatagramSocketImpl.h"
#include "Common.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

/**
 * Address: 0x0047EF40 (FUN_0047EF40)
 * Address: 0x10079520 (sub_10079520)
 *
 * What it does:
 * Base vtable destructor entry for datagram-socket interface.
 */
INetDatagramSocket::~INetDatagramSocket() = default;

/**
 * Address: 0x0047F360 (FUN_0047F360)
 * Address: 0x10079940 (Moho::NET_OpenDatagramSocket)
 *
 * What it does:
 * Opens/configures non-blocking broadcast UDP socket, binds it to `port`,
 * and returns datagram-socket implementation bound to `handler`.
 */
INetDatagramSocket* moho::NET_OpenDatagramSocket(const u_short port, INetDatagramHandler* handler)
{
  if (!NET_Init()) {
    return nullptr;
  }

  const SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) {
    gpg::Logf("NET_OpenDatagramSocket: socket() failed: %s", NET_GetWinsockErrorString());
    return nullptr;
  }

  {
    BOOL on = TRUE;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&on), sizeof(on)) == SOCKET_ERROR) {
      gpg::Logf("NET_OpenDatagramSocket: setsockopt(SO_BROADCAST) failed : %s", NET_GetWinsockErrorString());
      closesocket(sock);
      return nullptr;
    }
  }

  {
    u_long nonBlocking = 1;
    if (ioctlsocket(sock, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
      gpg::Logf("NET_OpenDatagramSocket: ioctlsocket(FIONBIO) failed: %s", NET_GetWinsockErrorString());
      closesocket(sock);
      return nullptr;
    }
  }

  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = htons(port);
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, reinterpret_cast<const sockaddr*>(&name), static_cast<int>(sizeof(name))) == SOCKET_ERROR) {
    gpg::Logf("NET_OpenDatagramSocket: bind() failed: %s", NET_GetWinsockErrorString());
    closesocket(sock);
    return nullptr;
  }

  const auto impl = new (std::nothrow) CNetDatagramSocketImpl(handler, sock);
  if (!impl) {
    // FA/Moho behavior: allocation failure returns null without closing `sock`.
    return nullptr;
  }
  return impl;
}
