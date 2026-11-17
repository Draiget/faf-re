#include "platform/PlatformDefines.h"
#include "remote/net/UdpSocket.h"

#include <charconv>
#include <cstring>

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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

namespace faf::remote::net
{
  namespace
  {
    constexpr int kBufferBytes = 1024 * 1024;

#if FAFRE_PLATFORM_WINDOWS
    using SocketHandle = SOCKET;
    using AddressLength = int;
    [[nodiscard]] int LastError() noexcept
    {
      return WSAGetLastError();
    }

    [[nodiscard]] bool StartSockets() noexcept
    {
      static const bool started = [] {
        WSADATA data{};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
      }();
      return started;
    }

    void CloseSocket(
      const SocketHandle handle
    ) noexcept
    {
      (void)closesocket(handle);
    }

    [[nodiscard]] bool MakeNonBlocking(
      const SocketHandle handle
    ) noexcept
    {
      u_long enabled = 1;
      return ioctlsocket(handle, FIONBIO, &enabled) == 0;
    }

    /** An ICMP reply to something sent earlier shows up on the next receive here; the datagrams behind it are fine. */
    [[nodiscard]] bool WorthRetry(
      const int error
    ) noexcept
    {
      return error == WSAECONNRESET || error == WSAEMSGSIZE;
    }
#else
    using SocketHandle = int;
    using AddressLength = socklen_t;
    constexpr SocketHandle INVALID_SOCKET = -1;
    [[nodiscard]] int LastError() noexcept
    {
      return errno;
    }
    [[nodiscard]] bool StartSockets() noexcept
    {
      return true;
    }
    void CloseSocket(
      const SocketHandle handle
    ) noexcept
    {
      (void)::close(handle);
    }

    [[nodiscard]] bool MakeNonBlocking(
      const SocketHandle handle
    ) noexcept
    {
      const int flags = fcntl(handle, F_GETFL, 0);
      return flags >= 0 && fcntl(handle, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    [[nodiscard]] bool WorthRetry(
      const int error
    ) noexcept
    {
      return error == EINTR || error == ECONNREFUSED;
    }
#endif

    /**
     * `endpoint` as the socket's family takes it: an IPv4 socket takes IPv4 endpoints only, a dual-stack one takes
     * both (IPv4 as ::ffff:a.b.c.d). False when the socket can't reach it.
     */
    [[nodiscard]] bool ToAddress(
      const SEndpoint& endpoint,
      const bool dualStack,
      sockaddr_storage& out,
      AddressLength& length
    ) noexcept
    {
      std::memset(&out, 0, sizeof(out));
      if (!dualStack) {
        if (!endpoint.IsIpv4() && !IsAnyAddress(endpoint.address)) {
          return false;
        }
        auto& v4 = reinterpret_cast<sockaddr_in&>(out);
        v4.sin_family = AF_INET;
        v4.sin_addr.s_addr = htonl(endpoint.Ipv4());
        v4.sin_port = htons(endpoint.port);
        length = static_cast<AddressLength>(sizeof(sockaddr_in));
        return true;
      }
      auto& v6 = reinterpret_cast<sockaddr_in6&>(out);
      v6.sin6_family = AF_INET6;
      std::memcpy(&v6.sin6_addr, endpoint.address.data(), endpoint.address.size());
      v6.sin6_port = htons(endpoint.port);
      length = static_cast<AddressLength>(sizeof(sockaddr_in6));
      return true;
    }

    [[nodiscard]] bool FromAddress(
      const sockaddr_storage& address,
      SEndpoint& out
    ) noexcept
    {
      if (address.ss_family == AF_INET) {
        const auto& v4 = reinterpret_cast<const sockaddr_in&>(address);
        out = SEndpoint(ntohl(v4.sin_addr.s_addr), ntohs(v4.sin_port));
        return true;
      }
      if (address.ss_family == AF_INET6) {
        const auto& v6 = reinterpret_cast<const sockaddr_in6&>(address);
        std::memcpy(out.address.data(), &v6.sin6_addr, out.address.size());
        out.port = ntohs(v6.sin6_port);
        return true;
      }
      return false;
    }

    /** One group of IPv6 text: 1 to 4 hex digits. */
    [[nodiscard]] bool ParseGroup(
      const std::string_view text,
      std::uint16_t& out
    ) noexcept
    {
      if (text.empty() || text.size() > 4u) {
        return false;
      }
      unsigned value = 0;
      const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
      if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return false;
      }
      out = static_cast<std::uint16_t>(value);
      return true;
    }

    /** a.b.c.d exactly, host order. */
    [[nodiscard]] bool ParseIpv4(
      const std::string_view text,
      std::uint32_t& out
    ) noexcept
    {
      const char* cursor = text.data();
      const char* const end = text.data() + text.size();
      std::uint32_t ip = 0;
      for (int part = 0; part < 4; ++part) {
        unsigned value = 0;
        const auto parsed = std::from_chars(cursor, end, value);
        if (parsed.ec != std::errc{} || value > 255u || parsed.ptr - cursor > 3) {
          return false;
        }
        ip = (ip << 8) | value;
        if (part < 3) {
          if (parsed.ptr == end || *parsed.ptr != '.') {
            return false;
          }
          cursor = parsed.ptr + 1;
        } else if (parsed.ptr != end) {
          return false;
        }
      }
      out = ip;
      return true;
    }

    /**
     * The groups of one side of a `::` (or of a whole address without one), into `groups` from `count` on. `ipv4Tail`:
     * its last piece may be a.b.c.d, two groups.
     */
    [[nodiscard]] bool ParseGroups(
      std::string_view text,
      const bool ipv4Tail,
      std::array<std::uint16_t, 8>& groups,
      int& count
    ) noexcept
    {
      if (text.empty()) {
        return true;
      }
      for (;;) {
        const std::size_t colon = text.find(':');
        const std::string_view piece = text.substr(0, colon);
        if (colon == std::string_view::npos && ipv4Tail && piece.contains('.')) {
          std::uint32_t ip = 0;
          if (count > 6 || !ParseIpv4(piece, ip)) {
            return false;
          }
          groups[static_cast<std::size_t>(count++)] = static_cast<std::uint16_t>(ip >> 16);
          groups[static_cast<std::size_t>(count++)] = static_cast<std::uint16_t>(ip);
          return true;
        }
        std::uint16_t group = 0;
        if (count >= 8 || !ParseGroup(piece, group)) {
          return false;
        }
        groups[static_cast<std::size_t>(count++)] = group;
        if (colon == std::string_view::npos) {
          return true;
        }
        text.remove_prefix(colon + 1);
        if (text.empty()) {
          return false; // a trailing ':'
        }
      }
    }

    [[nodiscard]] bool ParseIpv6(
      std::string_view text,
      IpAddress& out
    ) noexcept
    {
      if (text.size() >= 2u && text.front() == '[' && text.back() == ']') {
        text = text.substr(1, text.size() - 2u);
      }
      if (text.empty() || text.contains('%')) {
        return false;
      }
      std::array<std::uint16_t, 8> head{};
      std::array<std::uint16_t, 8> tail{};
      int headCount = 0;
      int tailCount = 0;
      const std::size_t gap = text.find("::");
      if (gap == std::string_view::npos) {
        if (!ParseGroups(text, true, head, headCount) || headCount != 8) {
          return false;
        }
      } else {
        if (text.find("::", gap + 1) != std::string_view::npos) {
          return false;
        }
        if (
          !ParseGroups(text.substr(0, gap), false, head, headCount) ||
          !ParseGroups(text.substr(gap + 2), true, tail, tailCount) || headCount + tailCount > 7
        ) {
          return false;
        }
      }
      std::array<std::uint16_t, 8> groups{};
      for (int i = 0; i < headCount; ++i) {
        groups[static_cast<std::size_t>(i)] = head[static_cast<std::size_t>(i)];
      }
      for (int i = 0; i < tailCount; ++i) {
        groups[static_cast<std::size_t>(8 - tailCount + i)] = tail[static_cast<std::size_t>(i)];
      }
      for (std::size_t i = 0; i < 8u; ++i) {
        out[2u * i] = static_cast<std::uint8_t>(groups[i] >> 8);
        out[2u * i + 1u] = static_cast<std::uint8_t>(groups[i]);
      }
      return true;
    }

    [[nodiscard]] std::uint64_t Fnv1a(
      const std::uint8_t* const bytes,
      const std::size_t size,
      std::uint64_t hash = 0xCBF29CE484222325ull
    ) noexcept
    {
      for (std::size_t i = 0; i < size; ++i) {
        hash = (hash ^ bytes[i]) * 0x100000001B3ull;
      }
      return hash;
    }
  } // namespace

  bool IsIpv4(
    const IpAddress& address
  ) noexcept
  {
    for (std::size_t i = 0; i < 10u; ++i) {
      if (address[i] != 0u) {
        return false;
      }
    }
    return address[10] == 0xFFu && address[11] == 0xFFu;
  }

  std::uint32_t Ipv4Of(
    const IpAddress& address
  ) noexcept
  {
    if (!IsIpv4(address)) {
      return 0;
    }
    return (static_cast<std::uint32_t>(address[12]) << 24) | (static_cast<std::uint32_t>(address[13]) << 16) |
      (static_cast<std::uint32_t>(address[14]) << 8) | static_cast<std::uint32_t>(address[15]);
  }

  bool IsAnyAddress(
    const IpAddress& address
  ) noexcept
  {
    return address == IpAddress{} || address == MapIpv4(0u);
  }

  IpAddress AddressPrefix(
    const IpAddress& address
  ) noexcept
  {
    if (IsIpv4(address)) {
      return address;
    }
    IpAddress prefix{};
    for (std::size_t i = 0; i < 8u; ++i) {
      prefix[i] = address[i];
    }
    return prefix;
  }

  std::string AddressText(
    const IpAddress& address
  )
  {
    if (IsIpv4(address)) {
      return std::to_string(address[12]) + "." + std::to_string(address[13]) + "." + std::to_string(address[14]) + "." +
        std::to_string(address[15]);
    }
    std::array<unsigned, 8> groups{};
    for (std::size_t i = 0; i < 8u; ++i) {
      groups[i] = (static_cast<unsigned>(address[2u * i]) << 8) | address[2u * i + 1u];
    }
    // RFC 5952 4.2: the longest run of two or more zero groups becomes ::, the first of equal ones.
    int bestStart = -1;
    int bestLength = 1;
    for (int i = 0; i < 8;) {
      if (groups[static_cast<std::size_t>(i)] != 0u) {
        ++i;
        continue;
      }
      int end = i;
      while (end < 8 && groups[static_cast<std::size_t>(end)] == 0u) {
        ++end;
      }
      if (end - i > bestLength) {
        bestStart = i;
        bestLength = end - i;
      }
      i = end;
    }
    std::string out;
    char hex[8];
    for (int i = 0; i < 8; ++i) {
      if (i == bestStart) {
        out += "::";
        i += bestLength - 1;
        continue;
      }
      if (!out.empty() && out.back() != ':') {
        out += ':';
      }
      const auto written = std::to_chars(hex, hex + sizeof(hex), groups[static_cast<std::size_t>(i)], 16);
      out.append(hex, written.ptr);
    }
    return out;
  }

  bool ParseAddress(
    const std::string_view text,
    IpAddress& out
  )
  {
    if (text.contains(':') || text.contains('[')) {
      return ParseIpv6(text, out);
    }
    std::uint32_t ip = 0;
    if (!ParseIpv4(text, ip)) {
      return false;
    }
    out = MapIpv4(ip);
    return true;
  }

  std::size_t IpAddressHash::operator()(
    const IpAddress& address
  ) noexcept
  {
    return static_cast<std::size_t>(Fnv1a(address.data(), address.size()));
  }

  std::size_t SEndpointHash::operator()(
    const SEndpoint& endpoint
  ) noexcept
  {
    const std::array<std::uint8_t, 18> key = endpoint.Key();
    return static_cast<std::size_t>(Fnv1a(key.data(), key.size()));
  }

  std::array<std::uint8_t, 18> SEndpoint::Key() const noexcept
  {
    std::array<std::uint8_t, 18> key{};
    std::memcpy(key.data(), address.data(), address.size());
    key[16] = static_cast<std::uint8_t>(port >> 8);
    key[17] = static_cast<std::uint8_t>(port);
    return key;
  }

  std::string SEndpoint::Text() const
  {
    const std::string host = AddressText(address);
    return (IsIpv4() ? host : "[" + host + "]") + ":" + std::to_string(port);
  }

  bool ParseEndpoint(
    const std::string_view text,
    SEndpoint& out
  )
  {
    std::string_view host;
    std::string_view portText;
    if (!text.empty() && text.front() == '[') {
      const std::size_t close = text.find("]:");
      if (close == std::string_view::npos) {
        return false;
      }
      host = text.substr(0, close + 1u);
      portText = text.substr(close + 2u);
    } else {
      const std::size_t colon = text.find(':');
      // An IPv6 address without brackets would leave the port ambiguous.
      if (colon == std::string_view::npos || text.find(':', colon + 1u) != std::string_view::npos) {
        return false;
      }
      host = text.substr(0, colon);
      portText = text.substr(colon + 1u);
    }
    IpAddress address{};
    if (!ParseAddress(host, address)) {
      return false;
    }
    unsigned port = 0;
    const auto parsed = std::from_chars(portText.data(), portText.data() + portText.size(), port);
    if (parsed.ec != std::errc{} || parsed.ptr != portText.data() + portText.size() || port == 0u || port > 65535u) {
      return false;
    }
    out.address = address;
    out.port = static_cast<std::uint16_t>(port);
    return true;
  }

  CUdpSocket::~CUdpSocket()
  {
    Close();
  }

  std::expected<void, std::string> CUdpSocket::Open(
    const SEndpoint& local
  )
  {
    Close();
    if (!StartSockets()) {
      return std::unexpected("the socket library didn't start");
    }
    const bool any = IsAnyAddress(local.address);
    bool dualStack = !local.IsIpv4();
    SocketHandle handle = socket(dualStack ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (handle == INVALID_SOCKET && dualStack && any) {
      // A system without IPv6 (a container with it turned off): `::` means any IPv4 address then.
      dualStack = false;
      handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    if (handle == INVALID_SOCKET) {
      return std::unexpected("no socket: error " + std::to_string(LastError()));
    }
    if (dualStack) {
      // IPv4 peers too, as ::ffff:a.b.c.d (the default differs: IPv6 only on Windows, a sysctl on Linux). A socket that
      // stays IPv6 only would reach no IPv4 server: on `::` take an IPv4 socket then, elsewhere fail.
      const int v6Only = 0;
      if (setsockopt(handle, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6Only), sizeof(v6Only)) != 0) {
        const int failure = LastError();
        CloseSocket(handle);
        handle = INVALID_SOCKET;
        if (any) {
          dualStack = false;
          handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        }
        if (handle == INVALID_SOCKET) {
          return std::unexpected("no dual-stack socket: error " + std::to_string(failure));
        }
      }
    }
    sockaddr_storage address{};
    AddressLength addressLength = 0;
    SEndpoint bindAt = local;
    if (!dualStack && !local.IsIpv4()) {
      bindAt = SEndpoint(0u, local.port); // `::` on a system without IPv6
    }
    if (
      !ToAddress(bindAt, dualStack, address, addressLength) ||
      bind(handle, reinterpret_cast<const sockaddr*>(&address), addressLength) != 0
    ) {
      std::string error = "can't bind " + local.Text() + ": error " + std::to_string(LastError());
      CloseSocket(handle);
      return std::unexpected(std::move(error));
    }
    if (!MakeNonBlocking(handle)) {
      std::string error = "can't make the socket non-blocking: error " + std::to_string(LastError());
      CloseSocket(handle);
      return std::unexpected(std::move(error));
    }
    // A game's burst shouldn't overflow the system's queue between two passes. Best effort.
    (void)setsockopt(handle, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&kBufferBytes), sizeof(kBufferBytes));
    (void)setsockopt(handle, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&kBufferBytes), sizeof(kBufferBytes));

    mPacketInfo = false;
#if !FAFRE_PLATFORM_WINDOWS
    // Bound to any address: learn where each datagram went, so its answer leaves from there.
    if (any) {
      const int on = 1;
      if (dualStack) {
#if defined(IPV6_RECVPKTINFO)
        mPacketInfo = setsockopt(handle, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == 0;
#endif
      } else {
#if defined(IP_PKTINFO)
        mPacketInfo = setsockopt(handle, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0;
#endif
      }
    }
#endif

    sockaddr_storage bound{};
    AddressLength boundSize = sizeof(bound);
    mLocal = bindAt;
    if (getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &boundSize) == 0) {
      SEndpoint named;
      if (FromAddress(bound, named)) {
        mLocal.port = named.port;
      }
    }
    mDualStack = dualStack;
    mSocket = static_cast<std::intptr_t>(handle);
    return {};
  }

  void CUdpSocket::Close() noexcept
  {
    if (mSocket != -1) {
      CloseSocket(static_cast<SocketHandle>(mSocket));
      mSocket = -1;
    }
    mDualStack = false;
    mPacketInfo = false;
  }

  bool CUdpSocket::SendTo(
    const void* const data,
    const std::size_t size,
    const SEndpoint& to,
    const IpAddress* const source
  ) noexcept
  {
    if (mSocket == -1) {
      return false;
    }
    sockaddr_storage address{};
    AddressLength addressLength = 0;
    if (!ToAddress(to, mDualStack, address, addressLength)) {
      return false; // an IPv6 peer for an IPv4 socket
    }
#if FAFRE_PLATFORM_WINDOWS
    (void)source;
    const int sent = sendto(
      static_cast<SocketHandle>(mSocket),
      static_cast<const char*>(data),
      static_cast<int>(size),
      0,
      reinterpret_cast<const sockaddr*>(&address),
      addressLength
    );
#else
    if (mPacketInfo && source != nullptr && !IsAnyAddress(*source)) {
      iovec part{const_cast<void*>(data), size};
      msghdr message{};
      message.msg_name = &address;
      message.msg_namelen = addressLength;
      message.msg_iov = &part;
      message.msg_iovlen = 1;
      alignas(cmsghdr) unsigned char control[CMSG_SPACE(sizeof(in6_pktinfo))]{};
      message.msg_control = control;
      bool written = false;
      if (mDualStack) {
#if defined(IPV6_PKTINFO)
        // An IPv4 source goes as ::ffff:a.b.c.d too: Linux sends an IPv4 datagram from it.
        message.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
        cmsghdr* const header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = IPPROTO_IPV6;
        header->cmsg_type = IPV6_PKTINFO;
        header->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        in6_pktinfo info{};
        std::memcpy(&info.ipi6_addr, source->data(), source->size());
        std::memcpy(CMSG_DATA(header), &info, sizeof(info));
        written = true;
#endif
      } else if (IsIpv4(*source)) {
#if defined(IP_PKTINFO)
        message.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
        cmsghdr* const header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = IPPROTO_IP;
        header->cmsg_type = IP_PKTINFO;
        header->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
        in_pktinfo info{};
        info.ipi_spec_dst.s_addr = htonl(Ipv4Of(*source));
        std::memcpy(CMSG_DATA(header), &info, sizeof(info));
        written = true;
#endif
      }
      if (written) {
        const auto sent = sendmsg(static_cast<SocketHandle>(mSocket), &message, 0);
        if (sent == static_cast<decltype(sent)>(size)) {
          return true;
        }
        if (LastError() != EINVAL) {
          return false;
        }
        // A source the system won't send from (the address went away): the system picks one, as before.
      }
    }
    const auto sent = sendto(
      static_cast<SocketHandle>(mSocket), data, size, 0, reinterpret_cast<const sockaddr*>(&address), addressLength
    );
#endif
    return sent == static_cast<decltype(sent)>(size);
  }

  int CUdpSocket::ReceiveFrom(
    void* const out,
    const std::size_t capacity,
    SEndpoint& from,
    IpAddress* const to
  ) noexcept
  {
    if (mSocket == -1) {
      return -1;
    }
    for (;;) {
      sockaddr_storage address{};
#if FAFRE_PLATFORM_WINDOWS
      AddressLength addressSize = sizeof(address);
      const int received = recvfrom(
        static_cast<SocketHandle>(mSocket),
        static_cast<char*>(out),
        static_cast<int>(capacity),
        0,
        reinterpret_cast<sockaddr*>(&address),
        &addressSize
      );
      IpAddress local = mLocal.address;
#else
      iovec part{out, capacity};
      msghdr message{};
      message.msg_name = &address;
      message.msg_namelen = sizeof(address);
      message.msg_iov = &part;
      message.msg_iovlen = 1;
      alignas(cmsghdr) unsigned char control[256]{};
      if (mPacketInfo) {
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
      }
      const auto received = recvmsg(static_cast<SocketHandle>(mSocket), &message, 0);
      IpAddress local = mLocal.address;
      if (received >= 0 && mPacketInfo) {
        for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header)) {
#if defined(IPV6_PKTINFO)
          if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_PKTINFO) {
            in6_pktinfo info{};
            std::memcpy(&info, CMSG_DATA(header), sizeof(info));
            std::memcpy(local.data(), &info.ipi6_addr, local.size());
          }
#endif
#if defined(IP_PKTINFO)
          if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO) {
            in_pktinfo info{};
            std::memcpy(&info, CMSG_DATA(header), sizeof(info));
            local = MapIpv4(ntohl(info.ipi_addr.s_addr));
          }
#endif
        }
      }
#endif
      if (received >= 0) {
        if (!FromAddress(address, from)) {
          continue; // a family this socket can't have
        }
        if (to != nullptr) {
          *to = local;
        }
        return static_cast<int>(received);
      }
      if (!WorthRetry(LastError())) {
        return -1;
      }
    }
  }

  void CUdpSocket::Wait(
    const int milliseconds
  ) noexcept
  {
    if (mSocket == -1) {
      return;
    }
#if FAFRE_PLATFORM_WINDOWS
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
