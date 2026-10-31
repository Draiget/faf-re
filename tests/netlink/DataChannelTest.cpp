// libdatachannel (issue #238): two peer connections in one process open the
// data channel layer 2 (#239) will use, unordered with no retransmissions,
// and exchange datagrams both ways. Signalling is handed over directly.
//
//   faf_datachannel_test [--bind <address>]
//
// --bind for hosts that drop inbound UDP to sockets bound to 0.0.0.0.

#include <rtc/rtc.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>

namespace
{
  int gFailures = 0;

  void Check(const bool ok, const char* what)
  {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) {
      ++gFailures;
    }
  }

  template <class Pred> bool WaitFor(Pred pred, const std::chrono::milliseconds limit)
  {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (!pred()) {
      if (std::chrono::steady_clock::now() > deadline) {
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
  }
} // namespace

int main(int argc, char** argv)
{
  rtc::Configuration config;
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], "--bind") == 0) {
      config.bindAddress = argv[i + 1];
    }
  }
  rtc::InitLogger(rtc::LogLevel::Warning);

  auto offerer = std::make_shared<rtc::PeerConnection>(config);
  auto answerer = std::make_shared<rtc::PeerConnection>(config);

  // Signalling: each side's description and candidates go straight to the other.
  offerer->onLocalDescription([answerer](rtc::Description d) { answerer->setRemoteDescription(d); });
  offerer->onLocalCandidate([answerer](rtc::Candidate c) { answerer->addRemoteCandidate(c); });
  answerer->onLocalDescription([offerer](rtc::Description d) { offerer->setRemoteDescription(d); });
  answerer->onLocalCandidate([offerer](rtc::Candidate c) { offerer->addRemoteCandidate(c); });

  constexpr int kDatagrams = 2000;
  std::atomic<int> atAnswerer{0};
  std::atomic<int> atOfferer{0};
  std::shared_ptr<rtc::DataChannel> remote;
  std::mutex remoteMutex;
  answerer->onDataChannel([&](std::shared_ptr<rtc::DataChannel> dc) {
    dc->onMessage([&, dc](rtc::message_variant m) {
      if (std::holds_alternative<rtc::binary>(m)) {
        ++atAnswerer;
        dc->send(std::get<rtc::binary>(m)); // echo
      }
    });
    std::lock_guard lock(remoteMutex);
    remote = dc;
  });

  rtc::DataChannelInit init;
  init.reliability.unordered = true;
  init.reliability.maxRetransmits = 0;
  auto channel = offerer->createDataChannel("game", init);
  std::atomic<bool> open{false};
  channel->onOpen([&] { open = true; });
  channel->onMessage([&](rtc::message_variant m) {
    if (std::holds_alternative<rtc::binary>(m)) {
      ++atOfferer;
    }
  });

  Check(WaitFor([&] { return open.load(); }, std::chrono::seconds(15)), "data channel open");
  if (open) {
    const rtc::Reliability r = channel->reliability();
    Check(r.unordered && r.maxRetransmits && *r.maxRetransmits == 0, "unordered, no retransmissions");
    rtc::binary payload(200, std::byte{0x5a});
    for (int i = 0; i < kDatagrams; ++i) {
      payload[0] = static_cast<std::byte>(i & 0xff);
      channel->send(payload);
      if (i % 100 == 99) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5)); // keep inside the SCTP buffer
      }
    }
    WaitFor([&] { return atOfferer.load() >= kDatagrams; }, std::chrono::seconds(10));
    std::printf("  sent %d, answerer got %d, echoes back %d\n", kDatagrams, atAnswerer.load(), atOfferer.load());
    // Unreliable on purpose; over loopback nothing should be lost.
    Check(atAnswerer.load() >= kDatagrams * 99 / 100, "answerer received the datagrams");
    Check(atOfferer.load() >= kDatagrams * 98 / 100, "offerer received the echoes");
  }

  channel->close();
  offerer->close();
  answerer->close();
  std::printf("%s (%d failures)\n", gFailures == 0 ? "PASS" : "FAIL", gFailures);
  return gFailures == 0 ? 0 : 1;
}
