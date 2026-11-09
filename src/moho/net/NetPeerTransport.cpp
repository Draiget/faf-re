#include "moho/net/NetPeerTransport.h"

#include <cstring>
#include <map>
#include <mutex>
#include <utility>

#include "moho/net/CNetUDPConnector.h"

namespace moho
{
  std::atomic<int> gNetPeerTransports{0};

  namespace
  {
    using AddressKey = std::pair<std::uint32_t, std::uint16_t>;

    struct ConnectorEntry
    {
      std::map<AddressKey, std::shared_ptr<INetPeerTransport>> transports;
      std::vector<SNetDeliveredDatagram> delivered;
    };

    constexpr std::size_t kMaxDelivered = 4096; // like the socket's receive buffer
    constexpr std::size_t kMaxHeld = 256;

    std::mutex gMutex;
    // Key nullptr: transports for every connector.
    std::map<const CNetUDPConnector*, ConnectorEntry> gConnectors;
    // For those: the connector that sent to the address first, and what
    // arrived before it did.
    std::map<AddressKey, CNetUDPConnector*> gAnySender;
    std::map<AddressKey, std::vector<SNetDeliveredDatagram>> gHeld;

    // gMutex held. The connector's destructor forgets its entry first, so a
    // connector found in gConnectors is alive.
    void QueueLocked(CNetUDPConnector* connector, SNetDeliveredDatagram d)
    {
      const auto c = gConnectors.find(connector);
      if (c == gConnectors.end() || c->second.delivered.size() >= kMaxDelivered) {
        return;
      }
      c->second.delivered.push_back(std::move(d));
      connector->SignalPeerTransportDelivery();
    }
  } // namespace

  void NET_SetPeerTransport(
    CNetUDPConnector* connector, const std::uint32_t addrHost, const std::uint16_t portHost,
    std::shared_ptr<INetPeerTransport> transport
  )
  {
    std::lock_guard lock(gMutex);
    auto& transports = gConnectors[connector].transports;
    const AddressKey key = std::make_pair(addrHost, portHost);
    const auto it = transports.find(key);
    if (it != transports.end()) {
      transports.erase(it);
      gNetPeerTransports.fetch_sub(1);
    }
    if (connector == nullptr) {
      gAnySender.erase(key);
      gHeld.erase(key);
    }
    if (transport) {
      transports.emplace(key, std::move(transport));
      gNetPeerTransports.fetch_add(1);
    }
  }

  bool NET_SendThroughPeerTransport(
    const CNetUDPConnector* connector, const std::uint32_t addrHost, const std::uint16_t portHost, const void* data,
    const std::size_t size
  )
  {
    std::shared_ptr<INetPeerTransport> transport;
    {
      std::lock_guard lock(gMutex);
      const AddressKey key = std::make_pair(addrHost, portHost);
      const auto c = gConnectors.find(connector);
      if (c != gConnectors.end()) {
        const auto it = c->second.transports.find(key);
        if (it != c->second.transports.end()) {
          transport = it->second;
        }
      }
      if (!transport) {
        const auto any = gConnectors.find(nullptr);
        if (any == gConnectors.end()) {
          return false;
        }
        const auto it = any->second.transports.find(key);
        if (it == any->second.transports.end()) {
          return false;
        }
        transport = it->second;
        // The first connector to send here receives from here.
        auto* sender = const_cast<CNetUDPConnector*>(connector);
        if (gAnySender.emplace(key, sender).second) {
          gConnectors[sender];
          const auto held = gHeld.find(key);
          if (held != gHeld.end()) {
            for (SNetDeliveredDatagram& d : held->second) {
              QueueLocked(sender, std::move(d));
            }
            gHeld.erase(held);
          }
        }
      }
    }
    transport->SendDatagram(data, size);
    return true;
  }

  void NET_DeliverFromPeerTransport(
    CNetUDPConnector* connector, const std::uint32_t addrHost, const std::uint16_t portHost, const void* data,
    const std::size_t size
  )
  {
    SNetDeliveredDatagram d;
    d.addrHost = addrHost;
    d.portHost = portHost;
    d.bytes.assign(static_cast<const unsigned char*>(data), static_cast<const unsigned char*>(data) + size);

    std::lock_guard lock(gMutex);
    if (connector == nullptr) {
      const AddressKey key = std::make_pair(addrHost, portHost);
      const auto sender = gAnySender.find(key);
      if (sender == gAnySender.end()) {
        std::vector<SNetDeliveredDatagram>& held = gHeld[key];
        if (held.size() < kMaxHeld) {
          held.push_back(std::move(d));
        }
        return;
      }
      connector = sender->second;
    }
    QueueLocked(connector, std::move(d));
  }

  void NET_TakeDeliveredDatagrams(const CNetUDPConnector* connector, std::vector<SNetDeliveredDatagram>& out)
  {
    std::lock_guard lock(gMutex);
    const auto c = gConnectors.find(connector);
    if (c == gConnectors.end()) {
      return;
    }
    out.swap(c->second.delivered);
    c->second.delivered.clear();
  }

  void NET_ForgetPeerTransports(const CNetUDPConnector* connector)
  {
    std::lock_guard lock(gMutex);
    for (auto it = gAnySender.begin(); it != gAnySender.end();) {
      it = it->second == connector ? gAnySender.erase(it) : std::next(it);
    }
    const auto c = gConnectors.find(connector);
    if (c == gConnectors.end()) {
      return;
    }
    gNetPeerTransports.fetch_sub(static_cast<int>(c->second.transports.size()));
    gConnectors.erase(c);
  }
} // namespace moho
