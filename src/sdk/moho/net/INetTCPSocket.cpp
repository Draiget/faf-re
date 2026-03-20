#include "INetTCPSocket.h"

#include <new>

#include "CNetTCPBuf.h"
#include "Common.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x00482800 (FUN_00482800)
 * Address: 0x1007C4A0 (sub_1007C4A0)
 *
 * What it does:
 * Base deleting-destructor entry for TCP stream sockets.
 */
INetTCPSocket::~INetTCPSocket() = default;

/**
 * Address: 0x004827E0 (FUN_004827E0)
 *
 * What it does:
 * Initializes stream base and installs INetTCPSocket vtable.
 */
INetTCPSocket::INetTCPSocket() = default;

/**
 * Address: 0x004830A0 (FUN_004830A0)
 * Address: 0x1007CE00 (sub_1007CE00)
 *
 * What it does:
 * Opens and connects a TCP stream socket to `address:port`.
 */
INetTCPSocket* moho::NET_TCPConnect(const u_long address, const u_short port)
{
  if (!NET_Init()) {
    return nullptr;
  }

  const SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    const msvc8::string hostName = NET_GetHostName(address);
    gpg::Logf(
      "NET_TCPConnect(%s:%d): socket() failed: %s",
      hostName.c_str(),
      static_cast<int>(port),
      NET_GetWinsockErrorString()
    );
    return nullptr;
  }

  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = htons(port);
  name.sin_addr.s_addr = htonl(address);

  if (connect(sock, reinterpret_cast<const sockaddr*>(&name), static_cast<int>(sizeof(name))) == SOCKET_ERROR) {
    const msvc8::string hostName = NET_GetHostName(address);
    gpg::Logf(
      "NET_TCPConnect(%s:%d): connect() failed: %s",
      hostName.c_str(),
      static_cast<int>(port),
      NET_GetWinsockErrorString()
    );
    closesocket(sock);
    return nullptr;
  }

  const auto stream = new (std::nothrow) CNetTCPBuf(sock);
  if (!stream) {
    // FA/Moho behavior: allocation failure returns null without closing `sock`.
    return nullptr;
  }
  return stream;
}
