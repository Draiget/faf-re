#pragma once

#include "platform/PlatformDefines.h"

// Thin BSD-socket wrapper for faf-netbridge (Winsock on Windows, POSIX
// elsewhere). Engine addition, not recovered code.

#include <cstdint>
#include <string>

#if FAFRE_PLATFORM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace faf::netbridge
{
#if FAFRE_PLATFORM_WINDOWS
  using SocketHandle = SOCKET;
  constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
  using SocketHandle = int;
  constexpr SocketHandle kInvalidSocket = -1;
#endif

  inline bool SocketsInit()
  {
#if FAFRE_PLATFORM_WINDOWS
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
  }

  inline void CloseSocket(
    SocketHandle& s
  )
  {
    if (s == kInvalidSocket) {
      return;
    }
#if FAFRE_PLATFORM_WINDOWS
    closesocket(s);
#else
    close(s);
#endif
    s = kInvalidSocket;
  }

  inline int LastSocketError()
  {
#if FAFRE_PLATFORM_WINDOWS
    return WSAGetLastError();
#else
    return errno;
#endif
  }

  inline bool WouldBlock(
    const int err
  )
  {
#if FAFRE_PLATFORM_WINDOWS
    return err == WSAEWOULDBLOCK;
#else
    return err == EWOULDBLOCK || err == EAGAIN;
#endif
  }

  // On Windows a UDP socket reports WSAECONNRESET after an ICMP port
  // unreachable for an earlier send; that is no reason to stop reading.
  inline bool IsTransientUdpError(
    const int err
  )
  {
#if FAFRE_PLATFORM_WINDOWS
    return err == WSAECONNRESET || err == WSAEWOULDBLOCK || err == WSAEMSGSIZE;
#else
    return err == ECONNREFUSED || err == EWOULDBLOCK || err == EAGAIN;
#endif
  }

  inline void SetNonBlocking(
    const SocketHandle s
  )
  {
#if FAFRE_PLATFORM_WINDOWS
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
#else
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
  }

  inline sockaddr_in MakeAddress(
    const char* ip,
    const std::uint16_t port
  )
  {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
  }

  inline std::uint16_t LocalPort(
    const SocketHandle s
  )
  {
    sockaddr_in a{};
    socklen_t len = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
      return 0;
    }
    return ntohs(a.sin_port);
  }

  // A TCP listener on ip:port (port 0: any).
  inline SocketHandle ListenTcp(
    const char* ip,
    const std::uint16_t port
  )
  {
    SocketHandle s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) {
      return s;
    }
#if !FAFRE_PLATFORM_WINDOWS
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
  inline SocketHandle BindUdp(
    const char* ip,
    const std::uint16_t port
  )
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
#if FAFRE_PLATFORM_WINDOWS
    // Don't let an ICMP port unreachable turn into WSAECONNRESET on recvfrom.
    BOOL off = FALSE;
    DWORD bytes = 0;
    WSAIoctl(
      s, _WSAIOW(IOC_VENDOR, 12) /* SIO_UDP_CONNRESET */, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr
    );
#endif
    return s;
  }

  inline void SetSocketBuffers(
    const SocketHandle s,
    const int bytes
  )
  {
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bytes), sizeof(bytes));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bytes), sizeof(bytes));
  }

  // A send to a closed connection fails instead of raising SIGPIPE, which would end the program (as
  // src/platform/posix/NetPosix.cpp does it): a send flag on Linux, a socket option on macOS (NoSigPipe).
  constexpr int kSendFlags =
#if FAFRE_PLATFORM_LINUX // MSG_NOSIGNAL; macOS has no such send flag
    MSG_NOSIGNAL;
#else
    0;
#endif

  /** macOS: no SIGPIPE from this socket (SO_NOSIGPIPE). Call it on every socket made or accepted. */
  inline void NoSigPipe(
    [[maybe_unused]] const SocketHandle s
  )
  {
#if FAFRE_PLATFORM_MACOS // SO_NOSIGPIPE, the socket option only macOS has
    const int on = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
  }

  /**
   * Waits up to `ms` for `s` to have data, or a connection to accept: 1 when it has, 0 after the wait, -1 on an error
   * (the socket closed). A thread that must stop waits in these slices: closing a socket from another thread wakes a
   * blocked accept or recv on Windows, but not on Linux or macOS.
   */
  inline int WaitReadable(
    const SocketHandle s,
    const int ms
  )
  {
    if (s == kInvalidSocket) {
      return -1;
    }
    fd_set read;
    FD_ZERO(&read);
    FD_SET(s, &read);
    timeval timeout{ms / 1000, (ms % 1000) * 1000};
#if FAFRE_PLATFORM_WINDOWS
    const int ready = select(0, &read, nullptr, nullptr, &timeout);
#else
    const int ready = select(s + 1, &read, nullptr, nullptr, &timeout);
#endif
    return ready > 0 ? 1 : (ready == 0 ? 0 : -1);
  }

  inline bool SendAll(
    const SocketHandle s,
    const char* data,
    std::size_t size
  )
  {
    while (size > 0) {
      const int n = static_cast<int>(send(s, data, static_cast<int>(size), kSendFlags));
      if (n <= 0) {
        return false;
      }
      data += n;
      size -= static_cast<std::size_t>(n);
    }
    return true;
  }
} // namespace faf::netbridge
