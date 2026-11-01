// net_FastRetransmit (issue #237): how long a lost DATA packet keeps the
// receiver waiting, with the switch off and on.
//
// Two real CNetUDPConnectors in this process, joined by peer transports
// (NetPeerTransport.h) that drop the first send of one DATA packet and pass
// everything else, the resend of that packet included. One side sends a stream
// of messages; the other records when each arrives. The longest wait is the
// lost packet's recovery: every message behind it waits for it, in order.
//
//   1. A fast sender (a message every 5 ms): with the switch on, the peer's
//      early mask shows 3 later packets soon after the loss, so the packet goes
//      out again before the 100 ms resend timer (net_MinResendDelay). Measured
//      on 2026-11-01, three runs each: resent 109-124 ms after the loss with
//      the switch off, 47-93 ms with it on; median wait 126.5 / 78.6 ms.
//   2. The game's rate (a message every 66 ms, about 15 DATA packets a second
//      as measured in game): 3 later packets take about 200 ms, so the timer
//      always comes first and the switch changes nothing (resent 102-125 ms
//      after the loss with it on). This is why no gain was measured in games.
//
// Build: cmake --build --preset clang-x64-release --target faf_fast_retransmit_tests
// Run:   build\clang-x64-release\tests\faf_fast_retransmit_tests.exe   (exit code = failures)

#include "moho/net/CMessage.h"
#include "moho/net/CNetUDPConnector.h"
#include "moho/net/Common.h"
#include "moho/net/IMessageReceiver.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"
#include "moho/net/NetConVars.h"
#include "moho/net/NetPeerTransport.h"
#include "moho/net/NetTransportEnums.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace moho;

namespace
{
  using Clock = std::chrono::steady_clock;

  int gFailures = 0;

  void Check(const bool ok, const char* what)
  {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) {
      ++gFailures;
    }
  }

  constexpr unsigned kMessageType = 100;
  constexpr std::size_t kSequenceOffset = 9; // SNetPacketHeader::mSequenceNumber
  constexpr int kArmAt = 20;

  struct Arrivals final : IMessageReceiver
  {
    std::vector<int> order;
    std::vector<Clock::time_point> at;

    void ReceiveMessage(CMessage* message, CMessageDispatcher* /*dispatcher*/) override
    {
      int index = -1;
      if (message->GetSize() >= 3 + sizeof(index)) {
        std::memcpy(&index, &message->mBuff[3], sizeof(index));
      }
      order.push_back(index);
      at.push_back(Clock::now());
    }
  };

  // Passes every datagram to the other connector, except the first send of
  // the first new DATA packet once `armed` is set (a sequence higher than any
  // sent before, so never a resend).
  struct LossyPipe final : INetPeerTransport
  {
    CNetUDPConnector* to = nullptr;
    std::uint32_t fromAddr = 0;
    std::uint16_t fromPort = 0;
    std::atomic<bool> armed{false};
    std::atomic<int> dropSequence{-1};
    std::atomic<int> dropped{0};
    std::atomic<int> resent{0};
    int highest = -1; // highest DATA sequence passed so far (the connector's thread only)
    Clock::time_point lostAt{};
    Clock::time_point resentAt{}; // its first resend

    void SendDatagram(const void* data, const std::size_t size) override
    {
      const auto* bytes = static_cast<const unsigned char*>(data);
      if (size > kSequenceOffset + 1 && bytes[0] == PT_Data && armed.load()) {
        std::uint16_t sequence = 0;
        std::memcpy(&sequence, bytes + kSequenceOffset, sizeof(sequence));
        if (dropSequence.load() < 0 && static_cast<int>(sequence) > highest) {
          dropSequence = sequence;
          dropped = 1;
          lostAt = Clock::now();
          return; // lost on the way
        }
        if (sequence == dropSequence.load() && resent.fetch_add(1) == 0) {
          resentAt = Clock::now();
        }
      }
      if (size > kSequenceOffset + 1 && bytes[0] == PT_Data) {
        std::uint16_t sequence = 0;
        std::memcpy(&sequence, bytes + kSequenceOffset, sizeof(sequence));
        highest = std::max(highest, static_cast<int>(sequence));
      }
      NET_DeliverFromPeerTransport(to, fromAddr, fromPort, data, size);
    }
  };

  void Write(INetConnection* c, const int index)
  {
    CMessage m(MessageType(static_cast<std::uint8_t>(kMessageType)));
    m.Append(reinterpret_cast<const char*>(&index), sizeof(index));
    const std::string filler(40, 'x');
    m.Append(filler.data(), filler.size());
    c->Write(m);
  }

  struct Result
  {
    bool inOrder = false;
    bool dropped = false;
    int resends = 0;
    double resendAfterMs = -1; // from the loss to the sender's first resend of that packet
    double longestWaitMs = 0;
  };

  // A sends `count` messages to B, one every `intervalMs`; the first new
  // packet after message kArmAt is lost once. Returns the longest time a
  // message written from kArmAt on waited from its send to its arrival (the
  // earlier ones include the connection handshake).
  Result Run(const int intervalMs, const int count, const bool fast)
  {
    net_FastRetransmit = fast ? 1 : 0;
    Result r;
    auto* a = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
    auto* b = static_cast<CNetUDPConnector*>(NET_MakeUDPConnector(0, {}));
    if (a == nullptr || b == nullptr) {
      return r;
    }
    constexpr std::uint32_t kAddrA = 0x0AFF0001; // 10.255.0.1
    constexpr std::uint32_t kAddrB = 0x0AFF0002; // 10.255.0.2
    auto toB = std::make_shared<LossyPipe>();
    toB->to = b;
    toB->fromAddr = kAddrA;
    toB->fromPort = 1;
    auto toA = std::make_shared<LossyPipe>();
    toA->to = a;
    toA->fromAddr = kAddrB;
    toA->fromPort = 2;
    NET_SetPeerTransport(a, kAddrB, 2, toB);
    NET_SetPeerTransport(b, kAddrA, 1, toA);

    INetConnection* ab = a->Connect(kAddrB, 2);
    INetConnection* ba = b->Accept(kAddrA, 1);
    Arrivals atB;
    ba->PushReceiver(kMessageType, kMessageType + 1, &atB);

    std::vector<Clock::time_point> sentAt(static_cast<std::size_t>(count));
    const Clock::time_point start = Clock::now();
    int next = 0;
    const auto deadline = start + std::chrono::milliseconds(intervalMs * count + 5000);
    while (static_cast<int>(atB.order.size()) < count && Clock::now() < deadline) {
      const Clock::time_point now = Clock::now();
      while (next < count && now >= start + std::chrono::milliseconds(intervalMs * next)) {
        if (next == kArmAt) {
          toB->armed = true; // the next DATA packet a sends is lost once
        }
        sentAt[static_cast<std::size_t>(next)] = Clock::now();
        Write(ab, next++);
        a->Push();
      }
      a->Pull();
      b->Pull();
      a->Push();
      b->Push();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    r.inOrder = static_cast<int>(atB.order.size()) == count;
    for (int i = 0; r.inOrder && i < count; ++i) {
      r.inOrder = atB.order[static_cast<std::size_t>(i)] == i;
    }
    if (r.inOrder) {
      for (int i = kArmAt; i < count; ++i) {
        const double ms =
          std::chrono::duration<double, std::milli>(atB.at[static_cast<std::size_t>(i)] - sentAt[static_cast<std::size_t>(i)])
            .count();
        r.longestWaitMs = std::max(r.longestWaitMs, ms);
      }
    }
    r.dropped = toB->dropped.load() == 1;
    r.resends = toB->resent.load();
    if (r.resends > 0) {
      r.resendAfterMs = std::chrono::duration<double, std::milli>(toB->resentAt - toB->lostAt).count();
    }

    ba->RemoveReceiver(kMessageType, kMessageType + 1, &atB);
    ab->Close();
    ba->Close();
    a->Destroy();
    b->Destroy();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    return r;
  }

  void Report(const char* label, const Result& r)
  {
    std::printf(
      "  %s: lost packet dropped %s, sent again %d time(s), first resend %.1f ms after the loss, longest wait %.1f ms\n",
      label, r.dropped ? "yes" : "no", r.resends, r.resendAfterMs, r.longestWaitMs
    );
    Check(r.dropped && r.inOrder, "every message arrived once and in order after the loss");
  }
} // namespace

int main()
{
  if (!NET_Init()) {
    std::printf("NET_Init failed\n");
    return 1;
  }

  // Each case three times; the median time from the loss to the sender's first
  // resend, which a busy machine disturbs less than the receiver's wait.
  auto median = [](const int intervalMs, const int count, const bool fast, const char* label) {
    double resends[3];
    for (double& w : resends) {
      const Result r = Run(intervalMs, count, fast);
      Report(label, r);
      w = r.resendAfterMs;
    }
    std::sort(resends, resends + 3);
    std::printf("  %s: median first resend %.1f ms after the loss\n", label, resends[1]);
    return resends[1];
  };

  // 1. A fast sender: the early mask fills before the resend timer.
  const double fastOff = median(5, 80, false, "message every 5 ms, net_FastRetransmit 0");
  const double fastOn = median(5, 80, true, "message every 5 ms, net_FastRetransmit 1");
  Check(fastOff >= 90, "switch off: the lost packet is resent by the timer (100 ms)");
  Check(fastOn >= 0 && fastOn + 20 <= fastOff, "switch on: it is resent at least 20 ms sooner");

  // 2. The game's rate: the timer always fires first, so the switch cannot help.
  const double gameOn = median(66, 40, true, "message every 66 ms, net_FastRetransmit 1");
  Check(gameOn >= 90, "game rate, switch on: still resent by the timer, no early resend possible");

  net_FastRetransmit = 0;
  std::printf("%s (%d failures)\n", gFailures == 0 ? "PASS" : "FAIL", gFailures);
  return gFailures == 0 ? 0 : 1;
}
