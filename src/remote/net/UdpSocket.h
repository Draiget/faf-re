#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

// Engine addition, net channel (plan WP10.1): the UDP socket under a channel. BSD sockets on Linux,
// Winsock on Windows, non-blocking. One socket serves a whole game, so `Wait` polls that one
// socket; epoll would add nothing with a single descriptor.
//
// Plan WPR.45 (issue #160): IPv4 and IPv6. An address is always 16 bytes, an IPv4 one in its IPv4-mapped form
// (::ffff:a.b.c.d, the IPv4-mapped form of RFC 4291), which is also how a dual-stack socket reports an IPv4 peer: one
// compare, one hash, one text form for both. A socket on an IPv4 address is an IPv4 socket as before; one on an IPv6
// address, or on `::`, is a dual-stack socket that also speaks IPv4 (an IPv4 socket when the system has no IPv6).

namespace faf::remote::net
{
  /** An IPv6 address, or an IPv4 one as ::ffff:a.b.c.d. Network byte order. */
  using IpAddress = std::array<std::uint8_t, 16>;

  [[nodiscard]] constexpr IpAddress MapIpv4(
    const std::uint32_t ip // host order
  ) noexcept
  {
    IpAddress out{};
    out[10] = 0xFF;
    out[11] = 0xFF;
    out[12] = static_cast<std::uint8_t>(ip >> 24);
    out[13] = static_cast<std::uint8_t>(ip >> 16);
    out[14] = static_cast<std::uint8_t>(ip >> 8);
    out[15] = static_cast<std::uint8_t>(ip);
    return out;
  }

  /** An IPv4 address (::ffff:a.b.c.d). */
  [[nodiscard]] bool IsIpv4(const IpAddress& address) noexcept;
  /** The IPv4 address in host order; 0 for an IPv6 one. */
  [[nodiscard]] std::uint32_t Ipv4Of(const IpAddress& address) noexcept;
  /** `::` or 0.0.0.0: any of the machine's addresses. */
  [[nodiscard]] bool IsAnyAddress(const IpAddress& address) noexcept;
  /**
   * What an allowlist entry and a per-address handshake budget match: an IPv4 address itself; an IPv6 address's /64,
   * the rest zeroed. An IPv6 host picks new temporary addresses in its /64 (RFC 8981), so the one FAF saw may not be
   * the one its game comes from, and anyone with one IPv6 address has the whole /64 to send from.
   */
  [[nodiscard]] IpAddress AddressPrefix(const IpAddress& address) noexcept;
  /** a.b.c.d for IPv4; RFC 5952 text for IPv6 (lower case, the longest run of zero groups as ::). */
  [[nodiscard]] std::string AddressText(const IpAddress& address);
  /** a.b.c.d, or IPv6 text (with or without [ ]), an embedded IPv4 tail included; no zone (%eth0). */
  [[nodiscard]] bool ParseAddress(std::string_view text, IpAddress& out);

  struct IpAddressHash
  {
    [[nodiscard]] static std::size_t operator()(const IpAddress& address) noexcept;
  };

  struct SEndpoint
  {
    IpAddress address{}; // `::` until set
    std::uint16_t port = 0;

    constexpr SEndpoint() = default;
    constexpr SEndpoint(
      const std::uint32_t ipv4, // host order
      const std::uint16_t endpointPort
    ) noexcept
      : address(MapIpv4(ipv4))
      , port(endpointPort)
    {}
    constexpr SEndpoint(
      const IpAddress& ip,
      const std::uint16_t endpointPort
    ) noexcept
      : address(ip)
      , port(endpointPort)
    {}

    [[nodiscard]] bool IsIpv4() const noexcept
    {
      return net::IsIpv4(address);
    }
    /** Host order; 0 for an IPv6 endpoint. */
    [[nodiscard]] std::uint32_t Ipv4() const noexcept
    {
      return Ipv4Of(address);
    }
    [[nodiscard]] bool operator==(
      const SEndpoint& other
    ) const noexcept
    {
      return address == other.address && port == other.port;
    }
    /** The address and the port, as the handshake's cookies are bound to them. */
    [[nodiscard]] std::array<std::uint8_t, 18> Key() const noexcept;
    /** a.b.c.d:port, or [ipv6]:port. */
    [[nodiscard]] std::string Text() const;
  };

  struct SEndpointHash
  {
    [[nodiscard]] static std::size_t operator()(const SEndpoint& endpoint) noexcept;
  };

  /** "a.b.c.d:port" or "[ipv6]:port"; false for anything else, a port of 0 included. */
  [[nodiscard]] bool ParseEndpoint(std::string_view text, SEndpoint& out);

  class CUdpSocket
  {
  public:
    CUdpSocket() = default;
    ~CUdpSocket();
    CUdpSocket(const CUdpSocket&) = delete;
    CUdpSocket& operator=(const CUdpSocket&) = delete;

    /** Binds to `local`; a port of 0 takes any free one, which `Local` then names. */
    [[nodiscard]] std::expected<void, std::string> Open(const SEndpoint& local);
    void Close() noexcept;

    /**
     * False when the system refused it; a full queue counts, as on any lossy path. `source`: the local address it
     * leaves from, on a socket bound to any address (`ReceiveFrom`'s `to` for the datagram it answers); ignored
     * otherwise, and on Windows.
     */
    bool SendTo(const void* data, std::size_t size, const SEndpoint& to, const IpAddress* source = nullptr) noexcept;
    /**
     * The size of the next datagram, moved to `out`; -1 when none is waiting. `to`: the local address it was sent
     * to. On a socket bound to any address that is the one an answer must leave from, as a machine with several
     * addresses otherwise answers from its default one, which the peer's NAT drops (POSIX only; elsewhere, and on a
     * socket bound to one address, the bound address).
     */
    [[nodiscard]] int ReceiveFrom(void* out, std::size_t capacity, SEndpoint& from, IpAddress* to = nullptr) noexcept;
    /** Until a datagram is waiting, for at most `milliseconds`. */
    void Wait(int milliseconds) noexcept;

    [[nodiscard]] SEndpoint Local() const noexcept
    {
      return mLocal;
    }
    /** An IPv6 socket, which reaches IPv4 peers too; false for an IPv4 one. */
    [[nodiscard]] bool DualStack() const noexcept
    {
      return mDualStack;
    }

  private:
    std::intptr_t mSocket = -1;
    SEndpoint mLocal;
    bool mDualStack = false;
    bool mPacketInfo = false; // bound to any address, and the system reports where each datagram went
  };
} // namespace faf::remote::net
