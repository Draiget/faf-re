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
    struct ConnectorEntry
    {
      std::map<std::pair<std::uint32_t, std::uint16_t>, std::shared_ptr<INetPeerTransport>> transports;
      std::vector<SNetDeliveredDatagram> delivered;
    };

    std::mutex gMutex;
    std::map<const CNetUDPConnector*, ConnectorEntry> gConnectors;
  } // namespace

  void NET_SetPeerTransport(
    CNetUDPConnector* connector, const std::uint32_t addrHost, const std::uint16_t portHost,
    std::shared_ptr<INetPeerTransport> transport
  )
  {
    std::lock_guard lock(gMutex);
    auto& transports = gConnectors[connector].transports;
    const auto key = std::make_pair(addrHost, portHost);
    const auto it = transports.find(key);
    if (it != transports.end()) {
      transports.erase(it);
      gNetPeerTransports.fetch_sub(1);
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
      const auto c = gConnectors.find(connector);
      if (c == gConnectors.end()) {
        return false;
      }
      const auto it = c->second.transports.find(std::make_pair(addrHost, portHost));
      if (it == c->second.transports.end()) {
        return false;
      }
      transport = it->second;
    }
    transport->SendDatagram(data, size);
    return true;
  }

  void NET_DeliverFromPeerTransport(
    CNetUDPConnector* connector, const std::uint32_t addrHost, const std::uint16_t portHost, const void* data,
    const std::size_t size
  )
  {
    {
      std::lock_guard lock(gMutex);
      const auto c = gConnectors.find(connector);
      if (c == gConnectors.end()) {
        return; // the connector is gone
      }
      // Bounded like the socket's receive buffer: a stalled connector drops.
      if (c->second.delivered.size() >= 4096) {
        return;
      }
      SNetDeliveredDatagram d;
      d.addrHost = addrHost;
      d.portHost = portHost;
      d.bytes.assign(static_cast<const unsigned char*>(data), static_cast<const unsigned char*>(data) + size);
      c->second.delivered.push_back(std::move(d));
      // Under the lock: the connector's destructor forgets its entry first,
      // so it is alive here.
      connector->SignalPeerTransportDelivery();
    }
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
    const auto c = gConnectors.find(connector);
    if (c == gConnectors.end()) {
      return;
    }
    gNetPeerTransports.fetch_sub(static_cast<int>(c->second.transports.size()));
    gConnectors.erase(c);
  }
} // namespace moho
