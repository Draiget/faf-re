#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

// Engine addition, net channel (plan WP10.1): the UDP socket under a channel. BSD sockets on Linux,
// Winsock on Windows, IPv4, non-blocking. One socket serves a whole game, so `Wait` polls that one
// socket; epoll would add nothing with a single descriptor.

namespace faf::remote::net
{
  struct SEndpoint
  {
    std::uint32_t ip = 0; // host order
    std::uint16_t port = 0;

    [[nodiscard]] bool operator==(const SEndpoint& other) const noexcept { return ip == other.ip && port == other.port; }
    [[nodiscard]] std::uint64_t Key() const noexcept { return (static_cast<std::uint64_t>(ip) << 16) | port; }
    [[nodiscard]] std::string Text() const;
  };

  /** "a.b.c.d:port"; false for anything else, a port of 0 included. */
  [[nodiscard]] bool ParseEndpoint(std::string_view text, SEndpoint& out);

  class CUdpSocket
  {
  public:
    CUdpSocket() = default;
    ~CUdpSocket();
    CUdpSocket(const CUdpSocket&) = delete;
    CUdpSocket& operator=(const CUdpSocket&) = delete;

    /** Binds to `local`; a port of 0 takes any free one, which `Local` then names. */
    [[nodiscard]] bool Open(const SEndpoint& local, std::string& error);
    void Close() noexcept;

    /** False when the system refused it; a full queue counts, as on any lossy path. */
    bool SendTo(const void* data, std::size_t size, const SEndpoint& to) noexcept;
    /** The size of the next datagram, moved to `out`; -1 when none is waiting. */
    [[nodiscard]] int ReceiveFrom(void* out, std::size_t capacity, SEndpoint& from) noexcept;
    /** Until a datagram is waiting, for at most `milliseconds`. */
    void Wait(int milliseconds) noexcept;

    [[nodiscard]] SEndpoint Local() const noexcept { return mLocal; }

  private:
    std::intptr_t mSocket = -1;
    SEndpoint mLocal;
  };
} // namespace faf::remote::net
