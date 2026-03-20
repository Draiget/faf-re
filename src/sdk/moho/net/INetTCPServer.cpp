#include "INetTCPServer.h"

#include <new>

#include "CNetTCPServerImpl.h"
#include "Common.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x00482750 (FUN_00482750)
 * Address: 0x1007C560 (sub_1007C560)
 *
 * What it does:
 * Base deleting-destructor entry for TCP server interface.
 */
INetTCPServer::~INetTCPServer() = default;

/**
 * Address: 0x00482740 (FUN_00482740)
 *
 * What it does:
 * Initializes interface vtable for TCP server instances.
 */
INetTCPServer::INetTCPServer() = default;

/**
 * Address: 0x00483390 (FUN_00483390)
 * Address: 0x1007D1A0 (sub_1007D1A0)
 *
 * What it does:
 * Creates a listening TCP server socket bound to `hostAddress:port`.
 */
INetTCPServer* moho::NET_CreateTCPServer(const u_long hostAddress, const u_short port)
{
  if (!NET_Init()) {
    return nullptr;
  }

  const SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    gpg::Logf("NET_CreateTCPServer(%d): socket() failed: %s", static_cast<int>(port), NET_GetWinsockErrorString());
    return nullptr;
  }

  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = htons(port);
  name.sin_addr.s_addr = htonl(hostAddress);

  if (bind(sock, reinterpret_cast<const sockaddr*>(&name), static_cast<int>(sizeof(name))) == SOCKET_ERROR) {
    gpg::Logf("NET_CreateTCPServer(%d): bind() failed: %s", static_cast<int>(port), NET_GetWinsockErrorString());
    closesocket(sock);
    return nullptr;
  }

  if (listen(sock, 5) == SOCKET_ERROR) {
    gpg::Logf("NET_CreateTCPServer(%d): listen() failed: %s", static_cast<int>(port), NET_GetWinsockErrorString());
    closesocket(sock);
    return nullptr;
  }

  const auto impl = new (std::nothrow) CNetTCPServerImpl(sock);
  if (!impl) {
    // FA/Moho behavior: allocation failure returns null without closing `sock`.
    return nullptr;
  }
  return impl;
}
