#pragma once

// Thin BSD-socket wrapper for faf-netbridge (Winsock on Windows, POSIX
// elsewhere). Engine addition, not recovered code.

#include <cstdint>
#include <string>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <cerrno>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace faf::netbridge
{
#ifdef _WIN32
  using SocketHandle = SOCKET;
  constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
  using SocketHandle = int;
  constexpr SocketHandle kInvalidSocket = -1;
#endif

  inline bool SocketsInit()
  {
#ifdef _WIN32
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
  }

  inline void CloseSocket(SocketHandle& s)
  {
    if (s == kInvalidSocket) {
      return;
    }
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    s = kInvalidSocket;
  }

  inline int LastSocketError()
  {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
  }

  inline bool WouldBlock(const int err)
  {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EWOULDBLOCK || err == EAGAIN;
#endif
  }

  // On Windows a UDP socket reports WSAECONNRESET after an ICMP port
  // unreachable for an earlier send; that is no reason to stop reading.
  inline bool IsTransientUdpError(const int err)
  {
#ifdef _WIN32
    return err == WSAECONNRESET || err == WSAEWOULDBLOCK || err == WSAEMSGSIZE;
#else
    return err == ECONNREFUSED || err == EWOULDBLOCK || err == EAGAIN;
#endif
  }

  inline void SetNonBlocking(const SocketHandle s)
  {
#ifdef _WIN32
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
#else
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
  }

  inline sockaddr_in MakeAddress(const char* ip, const std::uint16_t port)
  {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
  }

  inline std::uint16_t LocalPort(const SocketHandle s)
  {
    sockaddr_in a{};
    socklen_t len = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
      return 0;
    }
    return ntohs(a.sin_port);
  }

  // A TCP listener on ip:port (port 0: any).
  inline SocketHandle ListenTcp(const char* ip, const std::uint16_t port)
  {
    SocketHandle s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) {
      return s;
    }
#ifndef _WIN32
    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    const sockaddr_in a = MakeAddress(ip, port);
    if (bind(s, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) != 0 || listen(s, 4) != 0) {
      CloseSocket(s);
      return kInvalidSocket;
    }
    return s;
  }

  // A UDP socket on ip:port (port 0: any).
  inline SocketHandle BindUdp(const char* ip, const std::uint16_t port)
  {
    SocketHandle s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kInvalidSocket) {
      return s;
    }
    const sockaddr_in a = MakeAddress(ip, port);
    if (bind(s, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) != 0) {
      CloseSocket(s);
      return kInvalidSocket;
    }
#ifdef _WIN32
    // Don't let an ICMP port unreachable turn into WSAECONNRESET on recvfrom.
    BOOL off = FALSE;
    DWORD bytes = 0;
    WSAIoctl(s, _WSAIOW(IOC_VENDOR, 12) /* SIO_UDP_CONNRESET */, &off, sizeof(off), nullptr, 0, &bytes, nullptr,
             nullptr);
#endif
    return s;
  }

  inline bool SendAll(const SocketHandle s, const char* data, std::size_t size)
  {
    while (size > 0) {
      const int n = send(s, data, static_cast<int>(size), 0);
      if (n <= 0) {
        return false;
      }
      data += n;
      size -= static_cast<std::size_t>(n);
    }
    return true;
  }
} // namespace faf::netbridge
