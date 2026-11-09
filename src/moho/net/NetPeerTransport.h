#pragma once

// Engine addition (issue #232), not in the binary: per-address in-process
// transports for the game's UDP connector. A datagram the game sends to an
// address in a connector's table goes to that address's transport instead of
// the socket, and a transport hands the datagrams it receives to the same
// receive path as if they had come from that address over the socket.
// CLobby, CNetUDPConnection and the packet format stay as they are.
//
// The table lives beside the connector, not in it: CNetUDPConnector keeps the
// binary's layout (sizeof 0x18090). With no transport registered anywhere the
// send path costs one atomic load and nothing else changes.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace moho
{
  class CNetUDPConnector;

  class INetPeerTransport
  {
  public:
    virtual ~INetPeerTransport() = default;
    // One datagram the game addressed to this transport's peer. Called on
    // the connector's thread with the connector's lock held; must not block.
    virtual void SendDatagram(const void* data, std::size_t size) = 0;
  };

  // Number of transports registered in all connectors (the fast-path check).
  extern std::atomic<int> gNetPeerTransports;

  inline bool NET_PeerTransportsActive() noexcept
  {
    return gNetPeerTransports.load(std::memory_order_relaxed) != 0;
  }

  // Registers (or, with null, removes) the transport for addrHost:portHost
  // (host byte order) on one connector. A null connector registers it for
  // every connector (issue #233: the links run before the lobby's connector
  // exists); the connector that sends to the address first receives from it.
  void NET_SetPeerTransport(
    CNetUDPConnector* connector, std::uint32_t addrHost, std::uint16_t portHost,
    std::shared_ptr<INetPeerTransport> transport
  );

  // Sends through the transport for addrHost:portHost; false when there is
  // none and the caller sends on the socket.
  bool NET_SendThroughPeerTransport(
    const CNetUDPConnector* connector, std::uint32_t addrHost, std::uint16_t portHost, const void* data,
    std::size_t size
  );

  // A transport received a datagram from its peer: queue it for the
  // connector's receive loop and wake the connector. Any thread. A null
  // connector means the one that sends to addrHost:portHost through a
  // transport registered for every connector; until one has, up to 256
  // datagrams wait.
  void NET_DeliverFromPeerTransport(
    CNetUDPConnector* connector, std::uint32_t addrHost, std::uint16_t portHost, const void* data,
    std::size_t size
  );

  struct SNetDeliveredDatagram
  {
    std::uint32_t addrHost = 0;
    std::uint16_t portHost = 0;
    std::vector<unsigned char> bytes;
  };

  // Takes the datagrams queued for a connector (its receive loop).
  void NET_TakeDeliveredDatagrams(const CNetUDPConnector* connector, std::vector<SNetDeliveredDatagram>& out);

  // Drops a connector's table and queue (its destructor).
  void NET_ForgetPeerTransports(const CNetUDPConnector* connector);
} // namespace moho
