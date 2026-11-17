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

    // Built on first use and never destroyed: a connector's thread may use
    // the table until it ends, and then deletes its connector, whose
    // destructor forgets it here; both can happen while the process exits
    // (the game's WinMain and the Linux client's main return without
    // waiting for connector threads).
    struct TransportTable
    {
      std::mutex lock;
      // Key nullptr: transports for every connector.
      std::map<const CNetUDPConnector*, ConnectorEntry> connectors;
      // For those: the connector that sent to the address first, and what
      // arrived before it did.
      std::map<AddressKey, CNetUDPConnector*> anySender;
      std::map<AddressKey, std::vector<SNetDeliveredDatagram>> held;
    };

    [[nodiscard]] TransportTable& Table()
    {
      static TransportTable* const table = new TransportTable();
      return *table;
    }

    // The table's lock held. The connector's destructor forgets its entry
    // first, so a connector found in the table is alive.
    void QueueLocked(
      TransportTable& table,
      CNetUDPConnector* connector,
      SNetDeliveredDatagram d
    )
    {
      const auto c = table.connectors.find(connector);
      if (c == table.connectors.end() || c->second.delivered.size() >= kMaxDelivered) {
        return;
      }
      c->second.delivered.push_back(std::move(d));
      connector->SignalPeerTransportDelivery();
    }
  } // namespace

  void NET_SetPeerTransport(
    CNetUDPConnector* connector,
    const std::uint32_t addrHost,
    const std::uint16_t portHost,
    std::shared_ptr<INetPeerTransport> transport
  )
  {
    TransportTable& table = Table();
    std::lock_guard lock(table.lock);
    auto& transports = table.connectors[connector].transports;
    const AddressKey key = std::make_pair(addrHost, portHost);
    const auto it = transports.find(key);
    if (it != transports.end()) {
      transports.erase(it);
      gNetPeerTransports.fetch_sub(1);
    }
    if (connector == nullptr) {
      table.anySender.erase(key);
      table.held.erase(key);
    }
    if (transport) {
      transports.emplace(key, std::move(transport));
      gNetPeerTransports.fetch_add(1);
    }
  }

  bool NET_PeerTransportOffersGameChannel(
    const CNetUDPConnector* connector,
    const std::uint32_t addrHost,
    const std::uint16_t portHost,
    faf::remote::net::ChannelKeys& keys,
    bool& keyed
  )
  {
    keyed = false;
    std::shared_ptr<INetPeerTransport> transport;
    {
      TransportTable& table = Table();
      std::lock_guard lock(table.lock);
      const AddressKey key = std::make_pair(addrHost, portHost);
      for (const CNetUDPConnector* owner : {connector, static_cast<const CNetUDPConnector*>(nullptr)}) {
        const auto c = table.connectors.find(owner);
        if (c == table.connectors.end()) {
          continue;
        }
        const auto it = c->second.transports.find(key);
        if (it != c->second.transports.end()) {
          transport = it->second;
          break;
        }
      }
    }
    return transport && transport->OffersGameChannel(keys, keyed);
  }

  bool NET_SendThroughPeerTransport(
    const CNetUDPConnector* connector,
    const std::uint32_t addrHost,
    const std::uint16_t portHost,
    const void* data,
    const std::size_t size
  )
  {
    std::shared_ptr<INetPeerTransport> transport;
    {
      TransportTable& table = Table();
      std::lock_guard lock(table.lock);
      const AddressKey key = std::make_pair(addrHost, portHost);
      const auto c = table.connectors.find(connector);
      if (c != table.connectors.end()) {
        const auto it = c->second.transports.find(key);
        if (it != c->second.transports.end()) {
          transport = it->second;
        }
      }
      if (!transport) {
        const auto any = table.connectors.find(nullptr);
        if (any == table.connectors.end()) {
          return false;
        }
        const auto it = any->second.transports.find(key);
        if (it == any->second.transports.end()) {
          return false;
        }
        transport = it->second;
        // The first connector to send here receives from here.
        auto* sender = const_cast<CNetUDPConnector*>(connector);
        if (table.anySender.emplace(key, sender).second) {
          table.connectors[sender];
          const auto held = table.held.find(key);
          if (held != table.held.end()) {
            for (SNetDeliveredDatagram& d : held->second) {
              QueueLocked(table, sender, std::move(d));
            }
            table.held.erase(held);
          }
        }
      }
    }
    transport->SendDatagram(data, size);
    return true;
  }

  void NET_DeliverFromPeerTransport(
    CNetUDPConnector* connector,
    const std::uint32_t addrHost,
    const std::uint16_t portHost,
    const void* data,
    const std::size_t size
  )
  {
    SNetDeliveredDatagram d;
    d.addrHost = addrHost;
    d.portHost = portHost;
    d.bytes.assign(static_cast<const unsigned char*>(data), static_cast<const unsigned char*>(data) + size);

    TransportTable& table = Table();
    std::lock_guard lock(table.lock);
    if (connector == nullptr) {
      const AddressKey key = std::make_pair(addrHost, portHost);
      const auto sender = table.anySender.find(key);
      if (sender == table.anySender.end()) {
        std::vector<SNetDeliveredDatagram>& held = table.held[key];
        if (held.size() < kMaxHeld) {
          held.push_back(std::move(d));
        }
        return;
      }
      connector = sender->second;
    }
    QueueLocked(table, connector, std::move(d));
  }

  void NET_TakeDeliveredDatagrams(
    const CNetUDPConnector* connector,
    std::vector<SNetDeliveredDatagram>& out
  )
  {
    TransportTable& table = Table();
    std::lock_guard lock(table.lock);
    const auto c = table.connectors.find(connector);
    if (c == table.connectors.end()) {
      return;
    }
    out.swap(c->second.delivered);
    c->second.delivered.clear();
  }

  void NET_ForgetPeerTransports(
    const CNetUDPConnector* connector
  )
  {
    TransportTable& table = Table();
    std::lock_guard lock(table.lock);
    for (auto it = table.anySender.begin(); it != table.anySender.end();) {
      it = it->second == connector ? table.anySender.erase(it) : std::next(it);
    }
    const auto c = table.connectors.find(connector);
    if (c == table.connectors.end()) {
      return;
    }
    gNetPeerTransports.fetch_sub(static_cast<int>(c->second.transports.size()));
    table.connectors.erase(c);
  }
} // namespace moho
