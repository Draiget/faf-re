// What the tests that run real UDP connectors in this process (tests/net) share: how to pump two connectors, when a
// connector is gone, and how to end two that are connected. A connector is deleted by its thread once Destroy has been
// called and its connections have said goodbye (CNetUDPConnector::Entry); a test's next connector may then take its
// memory and its port.
#pragma once

#include "moho/net/CNetUDPConnection.h"
#include "moho/net/CNetUDPConnector.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"

#include "legacy/thread/Mutex.h"
#include "platform/Net.h"

#include <chrono>
#include <cstdint>
#include <thread>

namespace net_test
{
  using Clock = std::chrono::steady_clock;

  /// A connection's goodbye takes a round trip; one that hears nothing gives up after 10 s.
  constexpr Clock::duration kConnectorGoneWithin = std::chrono::seconds(15);

  /// Pulls and pushes both connectors, as a lobby's frame does, until `done` holds or 5 s pass; whether it holds.
  template <class Done>
  bool Pump(
    moho::INetConnector* const a,
    moho::INetConnector* const b,
    Done done
  )
  {
    const Clock::time_point end = Clock::now() + std::chrono::seconds(5);
    while (!done()) {
      if (Clock::now() >= end) {
        return false;
      }
      a->Pull();
      b->Pull();
      a->Push();
      b->Push();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
  }

  /// Whether `port` can be bound as NET_MakeUDPConnector binds it, at once or before `wait` is over: the connector that
  /// held it is gone.
  inline bool PortFree(
    const std::uint16_t port,
    const Clock::duration wait = Clock::duration::zero()
  )
  {
    const Clock::time_point end = Clock::now() + wait;
    while (true) {
      const platform::net::Socket probe = platform::net::OpenSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      sockaddr_in name{};
      name.sin_family = AF_INET;
      name.sin_port = htons(port);
      name.sin_addr.s_addr = htonl(0);
      const bool bound = probe != platform::net::kInvalidSocket && platform::net::Bind(probe, name) == 0;
      if (probe != platform::net::kInvalidSocket) {
        platform::net::CloseSocket(probe);
      }
      if (bound || Clock::now() >= end) {
        return bound;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }

  /// Whether `connection`'s stream has gone out to its end and the other side has acknowledged all of it.
  inline bool StreamAcknowledged(
    moho::CNetUDPConnector* const connector,
    moho::INetConnection* const connection
  )
  {
    fa::recursive_mutex::scoped_lock lock{connector->lock_};
    const auto* const udp = static_cast<moho::CNetUDPConnection*>(connection);
    return udp->mSentShutdown && udp->mUnAckedPayloads.empty();
  }

  /// Ends two connectors joined by `ab` (a's) and `ba` (b's); true when both are gone. Both streams are closed and
  /// acknowledged first: a connection says goodbye once what it sent is acknowledged, its goodbye acknowledges
  /// nothing, and it sends it before an acknowledgement it still owes. Otherwise the side left can wait for an answer
  /// from the one gone until it gives up, 10 s, sending all the while.
  inline bool EndConnected(
    moho::CNetUDPConnector* const a,
    moho::INetConnection* const ab,
    moho::CNetUDPConnector* const b,
    moho::INetConnection* const ba
  )
  {
    ab->Close();
    ba->Close();
    (void)Pump(a, b, [&] {
      return StreamAcknowledged(a, ab) && StreamAcknowledged(b, ba);
    });
    const std::uint16_t portA = a->GetLocalPort();
    const std::uint16_t portB = b->GetLocalPort();
    a->Destroy();
    const bool aGone = PortFree(portA, kConnectorGoneWithin);
    b->Destroy();
    return PortFree(portB, kConnectorGoneWithin) && aGone;
  }
} // namespace net_test
