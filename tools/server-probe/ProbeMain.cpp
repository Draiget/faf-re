// Engine addition, dedicated server: a stand-in for a player, to try a game server over a real socket
// without a game. It joins with a uid and token, says it has loaded, and at the given seconds sends
// commands, vanishes or leaves. Every view it receives is decoded, as a client would, and checked against
// the entity count the server sent with it. Prints one line per event, then what it saw.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_server_probe
// Exit code: 0 joined and saw beats, 1 refused, 2 never got in, saw no beats or a view that didn't decode,
// 3 bad arguments.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "remote/net/Datagram.h"
#include "remote/FrameWindow.h"
#include "remote/ViewLanes.h"
#include "remote/net/GameLinks.h"
#include "remote/wire/EntityFrame.h"

using namespace faf::remote::net;

namespace
{
  // moho/net/ECmdStreamOp.h.
  constexpr std::uint8_t kOpAdvance = 0;
  constexpr std::uint8_t kOpRequestPause = 4;
  constexpr std::uint8_t kOpResume = 5;
  constexpr std::uint8_t kOpEndGame = 23;

  struct SOptions
  {
    SEndpoint server;
    std::int32_t uid = 0;
    std::string token;
    double seconds = 30.0;
    double pauseAt = -1.0;
    double resumeAt = -1.0;
    double forgeAt = -1.0;
    double vanishAt = -1.0;
    double vanishFor = 0.0; // 0: for good
    double leaveAt = -1.0;
    bool noLoad = false;
  };

  [[nodiscard]] double Argument(const char* const text)
  {
    return std::atof(text);
  }

  [[nodiscard]] bool ReadOptions(const int argc, char** const argv, SOptions& out)
  {
    for (int i = 1; i < argc; ++i) {
      const std::string name = argv[i];
      if (name == "--no-load") {
        out.noLoad = true;
        continue;
      }
      if (i + 1 >= argc) {
        return false;
      }
      const char* const value = argv[++i];
      if (name == "--server") {
        if (!ParseEndpoint(value, out.server)) {
          return false;
        }
      } else if (name == "--uid") {
        out.uid = std::atoi(value);
      } else if (name == "--token") {
        out.token = value;
      } else if (name == "--seconds") {
        out.seconds = Argument(value);
      } else if (name == "--pause-at") {
        out.pauseAt = Argument(value);
      } else if (name == "--resume-at") {
        out.resumeAt = Argument(value);
      } else if (name == "--forge-at") {
        out.forgeAt = Argument(value);
      } else if (name == "--vanish-at") {
        out.vanishAt = Argument(value);
      } else if (name == "--vanish-for") {
        out.vanishFor = Argument(value);
      } else if (name == "--leave-at") {
        out.leaveAt = Argument(value);
      } else {
        return false;
      }
    }
    return out.server.port != 0u && !out.token.empty();
  }

  void SendCommand(CClientLink& link, const std::uint8_t op, const std::vector<std::uint8_t>& payload = {})
  {
    std::vector<std::uint8_t> message;
    const std::size_t whole = 3u + payload.size();
    message.push_back(static_cast<std::uint8_t>(ESeatMessage::Command));
    message.push_back(op);
    message.push_back(static_cast<std::uint8_t>(whole));
    message.push_back(static_cast<std::uint8_t>(whole >> 8));
    message.insert(message.end(), payload.begin(), payload.end());
    (void)link.SendReliable(message.data(), message.size());
  }

  /** What the player's game would do with its views, as far as a frame goes. */
  struct SViews
  {
    faf::remote::wire::SFrameCodec codec;
    faf::remote::CClientFrameWindow window;
    bool haveInfo = false;
    std::uint64_t views = 0;
    std::uint64_t failed = 0;
    std::uint64_t bytes = 0;
    std::uint64_t frameBytes = 0;
    std::uint64_t lastEntities = 0;
    std::uint64_t lastBeat = 0;
    std::uint64_t maxMessage = 0;
    double firstAt = -1.0;
    double lastAt = 0.0;
  };

  void TakeView(SViews& out, const std::vector<std::uint8_t>& message, const double elapsed)
  {
    if (message.empty()) {
      return;
    }
    if (message[0] == static_cast<std::uint8_t>(ESeatMessage::GameInfo) && message.size() == 1u + 2u * sizeof(float)) {
      float sizes[2] = {};
      std::memcpy(sizes, message.data() + 1, sizeof(sizes));
      out.codec = faf::remote::MakeViewCodec(sizes[0], sizes[1]);
      out.haveInfo = true;
      return;
    }
    if (message[0] != static_cast<std::uint8_t>(ESeatMessage::View)) {
      return;
    }
    ++out.views;
    out.bytes += message.size();
    out.maxMessage = std::max<std::uint64_t>(out.maxMessage, message.size());
    out.firstAt = out.firstAt < 0.0 ? elapsed : out.firstAt;
    out.lastAt = elapsed;

    ByteReader reader(message.data() + 1, message.size() - 1u);
    const std::uint64_t beat = reader.Varint();
    const std::uint64_t entities = reader.Varint();
    const std::uint64_t frameSize = reader.Varint();
    const std::uint8_t* const frame = reader.Bytes(frameSize);
    bool ok = reader.Ok() && out.haveInfo;
    // The other lanes' sizes must add up to the message, to its last byte.
    for (int lane = 0; lane < 3 && ok; ++lane) {
      const std::uint64_t size = reader.Varint();
      (void)reader.Bytes(size);
      ok = reader.Ok();
    }
    ok = ok && reader.AtEnd();
    if (ok) {
      faf::remote::wire::SViewFrame decoded;
      ok = out.window.Decode(std::span<const std::uint8_t>(frame, frameSize), out.codec, decoded) && decoded.entities.size() == entities;
      out.frameBytes += frameSize;
      out.lastEntities = entities;
      out.lastBeat = beat;
    }
    out.failed += ok ? 0u : 1u;
  }

  /** Each scheduled action once, when its time has come. */
  [[nodiscard]] bool Due(double& at, const double elapsed) noexcept
  {
    if (at < 0.0 || elapsed < at) {
      return false;
    }
    at = -1.0;
    return true;
  }
} // namespace

int main(const int argc, char** const argv)
{
  SOptions options;
  if (!ReadOptions(argc, argv, options)) {
    std::printf(
      "usage: faf_server_probe --server <ip:port> --uid <n> --token <t> [--seconds <s>] [--no-load] [--pause-at <s>] [--resume-at <s>] [--forge-at <s>] "
      "[--vanish-at <s> [--vanish-for <s>]] [--leave-at <s>]\n"
    );
    return 3;
  }

  CClientLink link(options.uid, MakeToken(options.token), options.server);
  std::string error;
  if (!link.Open(error)) {
    std::printf("probe %d: %s\n", options.uid, error.c_str());
    return 3;
  }

  const auto start = std::chrono::steady_clock::now();
  bool joined = false;
  bool refused = false;
  bool vanished = false;
  double returnAt = -1.0;
  std::uint64_t beatMessages = 0;
  std::uint64_t lastBeat = 0;
  std::uint64_t joins = 0;
  std::vector<std::uint8_t> message;
  SViews views;

  for (;;) {
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    if (elapsed >= options.seconds) {
      break;
    }
    const auto nowUs = static_cast<std::uint64_t>(elapsed * 1e6);

    if (Due(returnAt, elapsed)) {
      vanished = false;
      link.Reconnect();
      std::printf("probe %d: %.1f s: coming back\n", options.uid, elapsed);
    }
    if (vanished) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      // What arrives meanwhile stays in the socket, and fails as a stale channel's once back.
      continue;
    }

    link.Pump(nowUs);

    if (link.State() == CClientLink::EState::Refused) {
      std::printf("probe %d: %.1f s: refused, reason %d\n", options.uid, elapsed, link.Refusal() ? static_cast<int>(*link.Refusal()) : 0);
      refused = true;
      break;
    }
    if (link.State() == CClientLink::EState::Lost) {
      std::printf("probe %d: %.1f s: the link is lost\n", options.uid, elapsed);
      break;
    }
    if (link.State() == CClientLink::EState::Connected && !joined) {
      joined = true;
      ++joins;
      std::printf("probe %d: %.1f s: connected\n", options.uid, elapsed);
      if (!options.noLoad && joins == 1u) {
        const auto kind = static_cast<std::uint8_t>(ESeatMessage::Loaded);
        (void)link.SendReliable(&kind, 1u);
      }
    }
    while (link.TakeReliable(message)) {
      TakeView(views, message, elapsed);
    }
    while (link.TakeUnreliable(message)) {
      if (!message.empty() && message[0] == static_cast<std::uint8_t>(ESeatMessage::Beat)) {
        ByteReader reader(message.data() + 1, message.size() - 1u);
        const std::uint64_t beat = reader.Varint();
        if (reader.Ok()) {
          ++beatMessages;
          lastBeat = beat;
        }
      }
    }

    if (Due(options.pauseAt, elapsed)) {
      SendCommand(link, kOpRequestPause);
      std::printf("probe %d: %.1f s: asked to pause, at beat %llu\n", options.uid, elapsed, static_cast<unsigned long long>(lastBeat));
    }
    if (Due(options.resumeAt, elapsed)) {
      SendCommand(link, kOpResume);
      std::printf("probe %d: %.1f s: asked to resume, at beat %llu\n", options.uid, elapsed, static_cast<unsigned long long>(lastBeat));
    }
    if (Due(options.forgeAt, elapsed)) {
      const std::vector<std::uint8_t> manyBeats = {0xA0, 0x86, 0x01, 0x00};
      SendCommand(link, kOpAdvance, manyBeats);
      SendCommand(link, kOpEndGame);
      std::printf("probe %d: %.1f s: sent forged beats and a forged end of game\n", options.uid, elapsed);
    }
    if (Due(options.vanishAt, elapsed)) {
      std::printf("probe %d: %.1f s: vanishing, at beat %llu\n", options.uid, elapsed, static_cast<unsigned long long>(lastBeat));
      vanished = true;
      joined = false;
      if (options.vanishFor > 0.0) {
        returnAt = elapsed + options.vanishFor;
      }
      continue;
    }
    if (Due(options.leaveAt, elapsed)) {
      const auto kind = static_cast<std::uint8_t>(ESeatMessage::Leaving);
      (void)link.SendReliable(&kind, 1u);
      link.Pump(nowUs);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      link.Pump(nowUs + 200000u);
      std::printf("probe %d: %.1f s: left\n", options.uid, elapsed);
      break;
    }

    link.Wait(5);
  }

  std::printf("probe %d: joined %llu times, %llu beat messages, last beat %llu\n", options.uid, static_cast<unsigned long long>(joins), static_cast<unsigned long long>(beatMessages), static_cast<unsigned long long>(lastBeat));
  const double viewSeconds = views.lastAt - views.firstAt;
  std::printf(
    "probe %d: %llu views, %llu didn't decode, last at beat %llu with %llu entities, %.1f KB/s (frames %.1f), largest %llu bytes\n", options.uid,
    static_cast<unsigned long long>(views.views), static_cast<unsigned long long>(views.failed), static_cast<unsigned long long>(views.lastBeat),
    static_cast<unsigned long long>(views.lastEntities), viewSeconds > 0.0 ? static_cast<double>(views.bytes) / 1024.0 / viewSeconds : 0.0,
    viewSeconds > 0.0 ? static_cast<double>(views.frameBytes) / 1024.0 / viewSeconds : 0.0, static_cast<unsigned long long>(views.maxMessage)
  );
  if (refused) {
    return 1;
  }
  return joins > 0u && beatMessages > 0u && views.failed == 0u ? 0 : 2;
}
