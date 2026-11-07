#include "remote/net/UdpSocket.h"

#include <charconv>
#include <cstring>

#if defined(_WIN32)
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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace faf::remote::net
{
  namespace
  {
    constexpr int kBufferBytes = 1024 * 1024;

#if defined(_WIN32)
    using SocketHandle = SOCKET;
    [[nodiscard]] int LastError() noexcept { return WSAGetLastError(); }

    [[nodiscard]] bool StartSockets() noexcept
    {
      static const bool started = [] {
        WSADATA data{};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
      }();
      return started;
    }

    void CloseSocket(const SocketHandle handle) noexcept { (void)closesocket(handle); }

    [[nodiscard]] bool MakeNonBlocking(const SocketHandle handle) noexcept
    {
      u_long enabled = 1;
      return ioctlsocket(handle, FIONBIO, &enabled) == 0;
    }

    /** An ICMP reply to something sent earlier shows up on the next receive here; the datagrams behind it are fine. */
    [[nodiscard]] bool WorthRetry(const int error) noexcept { return error == WSAECONNRESET || error == WSAEMSGSIZE; }
#else
    using SocketHandle = int;
    constexpr SocketHandle INVALID_SOCKET = -1;
    [[nodiscard]] int LastError() noexcept { return errno; }
    [[nodiscard]] bool StartSockets() noexcept { return true; }
    void CloseSocket(const SocketHandle handle) noexcept { (void)::close(handle); }

    [[nodiscard]] bool MakeNonBlocking(const SocketHandle handle) noexcept
    {
      const int flags = fcntl(handle, F_GETFL, 0);
      return flags >= 0 && fcntl(handle, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    [[nodiscard]] bool WorthRetry(const int error) noexcept { return error == EINTR || error == ECONNREFUSED; }
#endif

    [[nodiscard]] sockaddr_in ToAddress(const SEndpoint& endpoint) noexcept
    {
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl(endpoint.ip);
      address.sin_port = htons(endpoint.port);
      return address;
    }
  } // namespace

  std::string SEndpoint::Text() const
  {
    return std::to_string((ip >> 24) & 0xFFu) + "." + std::to_string((ip >> 16) & 0xFFu) + "." + std::to_string((ip >> 8) & 0xFFu) + "."
         + std::to_string(ip & 0xFFu) + ":" + std::to_string(port);
  }

  bool ParseEndpoint(const std::string_view text, SEndpoint& out)
  {
    const char* cursor = text.data();
    const char* const end = text.data() + text.size();
    std::uint32_t ip = 0;
    for (int part = 0; part < 4; ++part) {
      unsigned value = 0;
      const auto parsed = std::from_chars(cursor, end, value);
      if (parsed.ec != std::errc{} || value > 255u || parsed.ptr == end || *parsed.ptr != (part < 3 ? '.' : ':')) {
        return false;
      }
      ip = (ip << 8) | value;
      cursor = parsed.ptr + 1;
    }
    unsigned port = 0;
    const auto parsed = std::from_chars(cursor, end, port);
    if (parsed.ec != std::errc{} || parsed.ptr != end || port == 0u || port > 65535u) {
      return false;
    }
    out.ip = ip;
    out.port = static_cast<std::uint16_t>(port);
    return true;
  }

  CUdpSocket::~CUdpSocket()
  {
    Close();
  }

  bool CUdpSocket::Open(const SEndpoint& local, std::string& error)
  {
    Close();
    if (!StartSockets()) {
      error = "the socket library didn't start";
      return false;
    }
    const SocketHandle handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (handle == INVALID_SOCKET) {
      error = "no socket: error " + std::to_string(LastError());
      return false;
    }
    const sockaddr_in address = ToAddress(local);
    if (bind(handle, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      error = "can't bind " + local.Text() + ": error " + std::to_string(LastError());
      CloseSocket(handle);
      return false;
    }
    if (!MakeNonBlocking(handle)) {
      error = "can't make the socket non-blocking: error " + std::to_string(LastError());
      CloseSocket(handle);
      return false;
    }
    // A game's burst shouldn't overflow the system's queue between two passes. Best effort.
    (void)setsockopt(handle, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&kBufferBytes), sizeof(kBufferBytes));
    (void)setsockopt(handle, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&kBufferBytes), sizeof(kBufferBytes));

    sockaddr_in bound{};
#if defined(_WIN32)
    int boundSize = sizeof(bound);
#else
    socklen_t boundSize = sizeof(bound);
#endif
    mLocal = local;
    if (getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &boundSize) == 0) {
      mLocal.port = ntohs(bound.sin_port);
    }
    mSocket = static_cast<std::intptr_t>(handle);
    return true;
  }

  void CUdpSocket::Close() noexcept
  {
    if (mSocket != -1) {
      CloseSocket(static_cast<SocketHandle>(mSocket));
      mSocket = -1;
    }
  }

  bool CUdpSocket::SendTo(const void* const data, const std::size_t size, const SEndpoint& to) noexcept
  {
    if (mSocket == -1) {
      return false;
    }
    const sockaddr_in address = ToAddress(to);
#if defined(_WIN32)
    const int sent = sendto(static_cast<SocketHandle>(mSocket), static_cast<const char*>(data), static_cast<int>(size), 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
#else
    const auto sent = sendto(static_cast<SocketHandle>(mSocket), data, size, 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
#endif
    return sent == static_cast<decltype(sent)>(size);
  }

  int CUdpSocket::ReceiveFrom(void* const out, const std::size_t capacity, SEndpoint& from) noexcept
  {
    if (mSocket == -1) {
      return -1;
    }
    for (;;) {
      sockaddr_in address{};
#if defined(_WIN32)
      int addressSize = sizeof(address);
      const int received = recvfrom(static_cast<SocketHandle>(mSocket), static_cast<char*>(out), static_cast<int>(capacity), 0, reinterpret_cast<sockaddr*>(&address), &addressSize);
#else
      socklen_t addressSize = sizeof(address);
      const auto received = recvfrom(static_cast<SocketHandle>(mSocket), out, capacity, 0, reinterpret_cast<sockaddr*>(&address), &addressSize);
#endif
      if (received >= 0) {
        from.ip = ntohl(address.sin_addr.s_addr);
        from.port = ntohs(address.sin_port);
        return static_cast<int>(received);
      }
      if (!WorthRetry(LastError())) {
        return -1;
      }
    }
  }

  void CUdpSocket::Wait(const int milliseconds) noexcept
  {
    if (mSocket == -1) {
      return;
    }
#if defined(_WIN32)
    WSAPOLLFD entry{};
    entry.fd = static_cast<SocketHandle>(mSocket);
    entry.events = POLLRDNORM;
    (void)WSAPoll(&entry, 1, milliseconds);
#else
    pollfd entry{};
    entry.fd = static_cast<SocketHandle>(mSocket);
    entry.events = POLLIN;
    (void)poll(&entry, 1, milliseconds);
#endif
  }
} // namespace faf::remote::net
