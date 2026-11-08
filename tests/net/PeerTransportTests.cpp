// Peer transports of the game's UDP connector (issue #232).
//
// Two real CNetUDPConnectors in this process. First over their sockets on
// 127.0.0.1 (or --host <ip>), as a game does; then a second pair connected to addresses that
// exist only in the transport tables (10.255.0.1:1 and 10.255.0.2:2), so
// every datagram goes through NET_SendThroughPeerTransport and
// NET_DeliverFromPeerTransport and none could have used the network. Both
// pairs exchange the same messages in both directions, in order.

#include "moho/net/CMessage.h"
#include "moho/net/CNetUDPConnector.h"
#include "moho/net/Common.h"
#include "moho/net/IMessageReceiver.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"
#include "moho/net/NetPeerTransport.h"

#include <WS2tcpip.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace moho;

namespace
{
  static u_long gSocketHost = 0x7F000001;

  void Check(const bool ok, const char* what)
  {
    EXPECT_TRUE(ok) << what;
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
  }

  // Any type outside 200..209: those are connection events the receiving
  // side makes up, and DispatchFromInput drops them from the stream.
  constexpr unsigned kMessageType = 100;
  constexpr int kMessages = 300;

  struct Collector final : IMessageReceiver
  {
    std::vector<std::string> got;

    void ReceiveMessage(CMessage* message, CMessageDispatcher* /*dispatcher*/) override
    {
      const unsigned size = message->GetSize();
      std::string payload;
      for (unsigned i = 3; i < size; ++i) {
        payload += static_cast<char>(message->mBuff[i]);
      }
      got.push_back(payload);
    }
  };

  // Hands every datagram to the other connector as if it came from `from`.
  struct Pipe final : INetPeerTransport
  {
    CNetUDPConnector* to = nullptr;
    std::uint32_t fromAddr = 0;
    std::uint16_t fromPort = 0;
    int datagrams = 0;

    void SendDatagram(const void* data, const std::size_t size) override
    {
      ++datagrams;
      NET_DeliverFromPeerTransport(to, fromAddr, fromPort, data, size);
    }
  };

  std::string Payload(const char* side, const int i)
  {
    return std::string(side) + " message " + std::to_string(i) + std::string(static_cast<std::size_t>(i % 200), 'x');
  }

  // Connects a (Connect) and b (Accept) at the given addresses and sends
  // kMessages each way.
  bool Exchange(
    CNetUDPConnector* a, CNetUDPConnector* b, const u_long bAddr, const u_short bPort, const u_long aAddr,
    const u_short aPort, const char* label
  )
  {
    INetConnection* ab = a->Connect(bAddr, bPort);
    INetConnection* ba = b->Accept(aAddr, aPort);
    if (ab == nullptr || ba == nullptr) {
      Check(false, label);
      return false;
    }
    Collector atA;
    Collector atB;
    ab->PushReceiver(kMessageType, kMessageType + 1, &atA);
    ba->PushReceiver(kMessageType, kMessageType + 1, &atB);

    for (int i = 0; i < kMessages; ++i) {
      const std::string pa = Payload("a", i);
      CMessage ma(MessageType(static_cast<std::uint8_t>(kMessageType)));
      ma.Append(pa.data(), pa.size());
      ab->Write(ma);
      const std::string pb = Payload("b", i);
      CMessage mb(MessageType(static_cast<std::uint8_t>(kMessageType)));
      mb.Append(pb.data(), pb.size());
      ba->Write(mb);
    }
    a->Push();
    b->Push();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while ((atA.got.size() < kMessages || atB.got.size() < kMessages) && std::chrono::steady_clock::now() < deadline) {
      a->Pull();
      b->Pull();
      a->Push();
      b->Push();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    bool inOrder = atA.got.size() == kMessages && atB.got.size() == kMessages;
    for (int i = 0; inOrder && i < kMessages; ++i) {
      inOrder = atA.got[static_cast<std::size_t>(i)] == Payload("b", i) &&
                atB.got[static_cast<std::size_t>(i)] == Payload("a", i);
    }
    std::printf("  %s: a got %zu, b got %zu\n", label, atA.got.size(), atB.got.size());
    Check(inOrder, label);
    ab->RemoveReceiver(kMessageType, kMessageType + 1, &atA);
    ba->RemoveReceiver(kMessageType, kMessageType + 1, &atB);
    ab->Close();
    ba->Close();
    return inOrder;
  }
} // namespace

TEST(Existing_PeerTransport, DirectSockets)
{
  ASSERT_TRUE(NET_Init()) << "NET_Init failed";
  auto* a = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
  auto* b = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
  Check(a != nullptr && b != nullptr, "two connectors bound");
  Check(!NET_PeerTransportsActive(), "no transport registered");
  Exchange(a, b, gSocketHost, b->GetLocalPort(), gSocketHost, a->GetLocalPort(), "socket path, both directions in order");
  a->Destroy();
  b->Destroy();
}

TEST(Existing_PeerTransport, VirtualTransports)
{
  ASSERT_TRUE(NET_Init()) << "NET_Init failed";
  auto* a = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
  auto* b = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
  constexpr std::uint32_t kAddrA = 0x0AFF0001; // 10.255.0.1
  constexpr std::uint32_t kAddrB = 0x0AFF0002; // 10.255.0.2
  auto toB = std::make_shared<Pipe>();
  toB->to = b;
  toB->fromAddr = kAddrA;
  toB->fromPort = 1;
  auto toA = std::make_shared<Pipe>();
  toA->to = a;
  toA->fromAddr = kAddrB;
  toA->fromPort = 2;
  NET_SetPeerTransport(a, kAddrB, 2, toB);
  NET_SetPeerTransport(b, kAddrA, 1, toA);
  Check(NET_PeerTransportsActive(), "two transports registered");
  Exchange(a, b, kAddrB, 2, kAddrA, 1, "transport path, both directions in order");
  std::printf("  datagrams through the transports: %d to b, %d to a\n", toB->datagrams, toA->datagrams);
  Check(toB->datagrams > 0 && toA->datagrams > 0, "every datagram went through a transport");
  a->Destroy();
  b->Destroy();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], "--host") == 0) {
      in_addr address{};
      if (::inet_pton(AF_INET, argv[i + 1], &address) != 1) {
        std::fprintf(stderr, "--host %s is not an IPv4 address\n", argv[i + 1]);
        return 2;
      }
      gSocketHost = ::ntohl(address.s_addr);
    }
  }
  return RUN_ALL_TESTS();
}
