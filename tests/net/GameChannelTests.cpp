// The game channel (net_GameChannel, src/moho/net/NetGameChannel.h): two real CNetUDPConnectors in this process,
// joined by peer transports that offer the channel and lose a share of what they carry. After the shipped handshake
// both connections carry their stream on the channel; every message written arrives once, intact and in order, and
// both ends close as shipped. With net_GameChannel 0 the same run uses the shipped DATA packets.
//
// Build: cmake --build --preset clang-x64-release --target faf_game_channel_tests
// Run:   build\clang-x64-release\tests\faf_game_channel_tests.exe   (exit code = failures)

#include "NetTestSupport.h"

#include "moho/net/CMessage.h"
#include "moho/net/CNetUDPConnection.h"
#include "moho/net/CNetUDPConnector.h"
#include "moho/net/Common.h"
#include "moho/net/IMessageReceiver.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"
#include "moho/net/NetConVars.h"
#include "moho/net/NetPeerTransport.h"
#include "remote/net/Datagram.h"
#include "remote/net/DatagramCipher.h"

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace moho;

namespace
{
  using Clock = std::chrono::steady_clock;

  constexpr unsigned kMessageType = 100;
  constexpr std::uint32_t kAddrA = 0xC6336401; // 198.51.100.1
  constexpr std::uint32_t kAddrB = 0xC6336402; // 198.51.100.2

  struct Arrivals final : IMessageReceiver
  {
    std::mutex mutex;
    std::vector<std::string> got;

    void ReceiveMessage(
      CMessage* message,
      CMessageDispatcher* /*dispatcher*/
    ) override
    {
      std::lock_guard lock(mutex);
      got.emplace_back(reinterpret_cast<const char*>(&message->mBuff[3]), message->GetSize() - 3);
    }

    std::size_t Count()
    {
      std::lock_guard lock(mutex);
      return got.size();
    }
  };

  // Passes datagrams to the other connector, losing `loss` of the game channel's (never the handshake's: the shipped
  // handshake repeats itself every second, which would only slow the test).
  struct Pipe final : INetPeerTransport
  {
    CNetUDPConnector* to = nullptr;
    std::uint32_t fromAddr = 0;
    std::uint16_t fromPort = 0;
    bool offer = true;
    bool initiator = false;
    double loss = 0.0;
    std::mt19937 rng{7};
    std::atomic<int> channelDatagrams{0};
    std::atomic<int> dataPackets{0};

    void SendDatagram(
      const void* data,
      const std::size_t size
    ) override
    {
      const auto* bytes = static_cast<const std::uint8_t*>(data);
      if (size > 0 && bytes[0] == faf::remote::net::kDatagramTag) {
        ++channelDatagrams;
        if (std::uniform_real_distribution<double>(0.0, 1.0)(rng) < loss) {
          return;
        }
      } else if (size > 0 && bytes[0] == PT_Data) {
        ++dataPackets;
      }
      NET_DeliverFromPeerTransport(to, fromAddr, fromPort, data, size);
    }

    [[nodiscard]] bool OffersGameChannel(
      faf::remote::net::ChannelKeys& keys,
      bool& keyed
    ) const override
    {
      keyed = false;
      if (!offer) {
        return false;
      }
      for (std::size_t i = 0; i < keys.send.size(); ++i) {
        keys.send[i] = static_cast<std::uint8_t>(initiator ? i : 0x80 + i);
        keys.receive[i] = static_cast<std::uint8_t>(initiator ? 0x80 + i : i);
      }
      keyed = true;
      return true;
    }
  };

  struct Result
  {
    bool allInOrder = false;
    bool aOnChannel = false;
    bool bOnChannel = false;
    int channelDatagrams = 0;
    int dataPackets = 0;
    bool ended = false;
  };

  Result RunChannel(
    const bool channel,
    const double loss,
    const int count
  )
  {
    net_GameChannel = channel ? 1 : 0;
    Result r;
    auto* a = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
    auto* b = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
    if (a == nullptr || b == nullptr) {
      return r;
    }
    auto toB = std::make_shared<Pipe>();
    toB->to = b;
    toB->fromAddr = kAddrA;
    toB->fromPort = 1;
    toB->initiator = true;
    toB->loss = loss;
    auto toA = std::make_shared<Pipe>();
    toA->to = a;
    toA->fromAddr = kAddrB;
    toA->fromPort = 2;
    toA->loss = loss;
    NET_SetPeerTransport(a, kAddrB, 2, toB);
    NET_SetPeerTransport(b, kAddrA, 1, toA);

    INetConnection* ab = a->Connect(kAddrB, 2);
    INetConnection* ba = b->Accept(kAddrA, 1);
    Arrivals atB;
    Arrivals atA;
    ba->PushReceiver(kMessageType, kMessageType + 1, &atB);
    ab->PushReceiver(kMessageType, kMessageType + 1, &atA);

    std::mt19937 rng(11);
    std::vector<std::string> sentAB;
    std::vector<std::string> sentBA;
    auto write = [&](INetConnection* c, std::vector<std::string>& sent) {
      std::string body(4 + rng() % 300, '\0');
      for (char& ch : body) {
        ch = static_cast<char>('a' + rng() % 26);
      }
      CMessage m(MessageType(static_cast<std::uint8_t>(kMessageType)));
      m.Append(body.data(), body.size());
      c->Write(m);
      sent.push_back(body);
    };
    const Clock::time_point end = Clock::now() + std::chrono::seconds(30);
    int written = 0;
    while (Clock::now() < end &&
           (atB.Count() < static_cast<std::size_t>(count) || atA.Count() < static_cast<std::size_t>(count))) {
      if (written < count) {
        write(ab, sentAB);
        write(ba, sentBA);
        ++written;
        a->Push();
        b->Push();
      }
      a->Pull();
      b->Pull();
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    {
      fa::recursive_mutex::scoped_lock lockA{a->lock_};
      r.aOnChannel = static_cast<CNetUDPConnection*>(ab)->InGameChannel();
    }
    {
      fa::recursive_mutex::scoped_lock lockB{b->lock_};
      r.bOnChannel = static_cast<CNetUDPConnection*>(ba)->InGameChannel();
    }
    {
      std::lock_guard lockB(atB.mutex);
      std::lock_guard lockA(atA.mutex);
      r.allInOrder = atB.got == sentAB && atA.got == sentBA;
    }
    r.channelDatagrams = toB->channelDatagrams.load() + toA->channelDatagrams.load();
    r.dataPackets = toB->dataPackets.load() + toA->dataPackets.load();

    ba->RemoveReceiver(kMessageType, kMessageType + 1, &atB);
    ab->RemoveReceiver(kMessageType, kMessageType + 1, &atA);
    toA->loss = 0.0;
    toB->loss = 0.0;
    r.ended = net_test::EndConnected(a, ab, b, ba);
    net_GameChannel = 1;
    return r;
  }
} // namespace

TEST(
  Net_GameChannel,
  CarriesTheStreamInOrderOverLoss
)
{
  ASSERT_TRUE(NET_Init()) << "NET_Init failed";
  const Result r = RunChannel(true, 0.10, 400);
  std::printf(
    "  game channel, 10%% loss: in order %d, on channel %d/%d, %d channel datagrams, %d DATA packets, ended %d\n",
    r.allInOrder,
    r.aOnChannel,
    r.bOnChannel,
    r.channelDatagrams,
    r.dataPackets,
    r.ended
  );
  EXPECT_TRUE(r.allInOrder);
  EXPECT_TRUE(r.aOnChannel);
  EXPECT_TRUE(r.bOnChannel);
  EXPECT_GT(r.channelDatagrams, 0);
  EXPECT_EQ(r.dataPackets, 0); // the stream never went in shipped DATA packets
  EXPECT_TRUE(r.ended);
}

TEST(
  Net_GameChannel,
  OffSwitchKeepsShippedPackets
)
{
  ASSERT_TRUE(NET_Init()) << "NET_Init failed";
  const Result r = RunChannel(false, 0.0, 100);
  EXPECT_TRUE(r.allInOrder);
  EXPECT_FALSE(r.aOnChannel);
  EXPECT_FALSE(r.bOnChannel);
  EXPECT_EQ(r.channelDatagrams, 0);
  EXPECT_GT(r.dataPackets, 0);
  EXPECT_TRUE(r.ended);
}
