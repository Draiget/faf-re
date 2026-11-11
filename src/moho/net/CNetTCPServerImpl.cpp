#include "CNetTCPServerImpl.h"

#include <new>

#include "CNetTCPBuf.h"
#include "Common.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x00483220 (FUN_00483220)
 * Address: 0x1007CFF0 (sub_1007CFF0)
 *
 * What it does:
 * Closes active listening socket and tears down server object.
 */
CNetTCPServerImpl::~CNetTCPServerImpl()
{
  if (mSocket != platform::net::kInvalidSocket) {
    platform::net::CloseSocket(mSocket);
    mSocket = platform::net::kInvalidSocket;
  }
}

/**
 * Address: 0x004832A0 (FUN_004832A0)
 * Address: 0x1007D0B0 (sub_1007D0B0)
 *
 * What it does:
 * Returns listening socket's local port.
 */
u_short CNetTCPServerImpl::GetLocalPort()
{
  sockaddr_in name{};
  platform::net::GetLocalAddress(mSocket, &name);
  return ntohs(name.sin_port);
}

/**
 * Address: 0x004832D0 (FUN_004832D0)
 * Address: 0x1007D0E0 (sub_1007D0E0)
 *
 * What it does:
 * Accepts next inbound client and wraps it into CNetTCPBuf.
 */
INetTCPSocket* CNetTCPServerImpl::Accept()
{
  sockaddr_in addr{};
  const platform::net::Socket acceptedSocket = platform::net::Accept(mSocket, &addr);
  if (acceptedSocket == platform::net::kInvalidSocket) {
    gpg::Logf("CNetTCPServerImpl::Accept(): accept() failed: %s", NET_GetWinsockErrorString());
    return nullptr;
  }

  const auto stream = new (std::nothrow) CNetTCPBuf(acceptedSocket);
  if (!stream) {
    // FA/Moho behavior: allocation failure returns null without closing accepted socket.
    return nullptr;
  }
  return stream;
}

/**
 * Address: 0x00483370 (FUN_00483370)
 * Address: 0x1007D180 (sub_1007D180)
 *
 * What it does:
 * Closes listening socket and marks it invalid.
 */
void CNetTCPServerImpl::CloseSocket()
{
  if (mSocket != platform::net::kInvalidSocket) {
    platform::net::CloseSocket(mSocket);
    mSocket = platform::net::kInvalidSocket;
  }
}

/**
 * Address: 0x00483210 (FUN_00483210)
 *
 * What it does:
 * Initializes CNetTCPServerImpl around already-open listening socket.
 */
CNetTCPServerImpl::CNetTCPServerImpl(
  const platform::net::Socket socket
) noexcept
  : mSocket(socket)
{}
