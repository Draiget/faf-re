// Engine addition, dedicated server: a stand-in for a player, to try a game server over a real socket
// without a game. It joins with a uid and token, says it has loaded, and at the given seconds sends
// commands and orders, vanishes or leaves. Every view it receives is decoded, as a client would, and checked
// against the entity count the server sent with it. Prints one line per event, then what it saw.
//
// With `--loss`, `--latency-ms`, `--jitter-ms` or `--partition-at` its datagrams go through a bad network, in
// both directions, on a thread of its own here. `--beat-ms` then says how late the views came.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_server_probe
// Exit code: 0 joined and saw beats, 1 refused, 2 never got in, saw no beats or a view that didn't decode,
// 3 bad arguments.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <random>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "ProbeRebuild.h"
#include "lua/LuaObject.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/net/ECmdStreamOp.h"
#include "remote/net/Datagram.h"
#include "remote/FrameWindow.h"
#include "remote/ViewLanes.h"
#include "remote/net/GameLinks.h"
#include "remote/wire/EntityFrame.h"
#include "remote/net/LobbySignals.h"

using namespace faf::remote::net;

namespace
{
  // moho/net/ECmdStreamOp.h.
  constexpr std::uint8_t kOpAdvance = 0;
  constexpr std::uint8_t kOpRequestPause = 4;
  constexpr std::uint8_t kOpResume = 5;
  constexpr std::uint8_t kOpEndGame = 23;
  constexpr auto kOpIssueCommand = static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_IssueCommand);

  // A renumbered family's id no view is ever given: the serial runs out long before this.
  constexpr std::uint32_t kForgedBlipId = 0x3FFFFFFFu;
  constexpr std::uint32_t kGroundTarget = 0xFFFFFFFFu;

  [[nodiscard]] std::uint64_t SteadyUs() noexcept
  {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
  }

  /** A bad network between this player and the server. Latency is each way. */
  class CImpairedPath
  {
  public:
    struct SConfig
    {
      double lossPercent = 0.0;
      double latencyMs = 0.0;
      double jitterMs = 0.0;
      double partitionAt = -1.0;
      double partitionFor = 0.0;

      [[nodiscard]] bool Any() const noexcept { return lossPercent > 0.0 || latencyMs > 0.0 || jitterMs > 0.0 || partitionAt >= 0.0; }
    };

    ~CImpairedPath()
    {
      mStop.store(true, std::memory_order_relaxed);
      if (mThread.joinable()) {
        mThread.join();
      }
    }

    [[nodiscard]] bool Start(const SEndpoint& server, const SConfig& config, const std::uint32_t seed, std::string& error)
    {
      mServer = server;
      mConfig = config;
      mRandom.seed(seed);
      SEndpoint any;
      any.ip = 0x7F000001u;
      if (!mPlayerSide.Open(any, error) || !mServerSide.Open(any, error)) {
        return false;
      }
      mStartUs = SteadyUs();
      mThread = std::thread([this] { Run(); });
      return true;
    }

    [[nodiscard]] SEndpoint PlayerSide() const noexcept { return mPlayerSide.Local(); }
    [[nodiscard]] std::uint64_t Seen() const noexcept { return mSeen.load(std::memory_order_relaxed); }
    [[nodiscard]] std::uint64_t Lost() const noexcept { return mLost.load(std::memory_order_relaxed); }

  private:
    struct SHeld
    {
      bool toServer;
      std::vector<std::uint8_t> bytes;
    };

    void Take(const std::uint8_t* const data, const std::size_t size, const bool toServer, const std::uint64_t nowUs)
    {
      mSeen.fetch_add(1u, std::memory_order_relaxed);
      const double elapsed = static_cast<double>(nowUs - mStartUs) / 1e6;
      const bool cut = mConfig.partitionAt >= 0.0 && elapsed >= mConfig.partitionAt && elapsed < mConfig.partitionAt + mConfig.partitionFor;
      if (cut || std::uniform_real_distribution<double>(0.0, 100.0)(mRandom) < mConfig.lossPercent) {
        mLost.fetch_add(1u, std::memory_order_relaxed);
        return;
      }
      const double delayMs = mConfig.latencyMs + (mConfig.jitterMs > 0.0 ? std::uniform_real_distribution<double>(0.0, mConfig.jitterMs)(mRandom) : 0.0);
      mHeld.emplace(nowUs + static_cast<std::uint64_t>(delayMs * 1000.0), SHeld{toServer, std::vector<std::uint8_t>(data, data + size)});
    }

    void Run()
    {
      std::vector<std::uint8_t> buffer(2048u);
      SEndpoint player;
      SEndpoint from;
      while (!mStop.load(std::memory_order_relaxed)) {
        const std::uint64_t nowUs = SteadyUs();
        for (int size = mPlayerSide.ReceiveFrom(buffer.data(), buffer.size(), from); size >= 0; size = mPlayerSide.ReceiveFrom(buffer.data(), buffer.size(), from)) {
          player = from;
          Take(buffer.data(), static_cast<std::size_t>(size), true, nowUs);
        }
        for (int size = mServerSide.ReceiveFrom(buffer.data(), buffer.size(), from); size >= 0; size = mServerSide.ReceiveFrom(buffer.data(), buffer.size(), from)) {
          Take(buffer.data(), static_cast<std::size_t>(size), false, nowUs);
        }
        while (!mHeld.empty() && mHeld.begin()->first <= nowUs) {
          const SHeld& held = mHeld.begin()->second;
          if (held.toServer) {
            (void)mServerSide.SendTo(held.bytes.data(), held.bytes.size(), mServer);
          } else if (player.port != 0u) {
            (void)mPlayerSide.SendTo(held.bytes.data(), held.bytes.size(), player);
          }
          mHeld.erase(mHeld.begin());
        }
        mPlayerSide.Wait(1);
      }
    }

    SEndpoint mServer;
    SConfig mConfig;
    CUdpSocket mPlayerSide;
    CUdpSocket mServerSide;
    std::mt19937 mRandom;
    std::multimap<std::uint64_t, SHeld> mHeld;
    std::uint64_t mStartUs = 0;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<std::uint64_t> mSeen{0};
    std::atomic<std::uint64_t> mLost{0};
  };

  struct SOptions
  {
    SEndpoint server;
    std::int32_t uid = 0;
    std::string token;
    double seconds = 30.0;
    double pauseAt = -1.0;
    double resumeAt = -1.0;
    double pauseEvery = 0.0; // with `pauseAt`: asks to pause again this often, and to resume halfway between
    double forgeAt = -1.0;
    double vanishAt = -1.0;
    double vanishFor = 0.0; // 0: for good
    double leaveAt = -1.0;
    double orderAt = -1.0;
    double attackBlipAt = -1.0;
    double forgeIdAt = -1.0;
    double attackHiddenAt = -1.0;
    std::uint32_t hiddenId = 0u; // a unit of another army, as a cheat would guess it
    double fuzzAt = -1.0;
    double floodAt = -1.0;
    double breakAllianceAt = -1.0;
    double damageAt = -1.0; // changes a kept record on purpose (WPR.31), which the server's next check should catch
    std::int32_t breakWith = -1; // the army index to stop being allied with, as FAF's diplomacy screen asks

    double beatMs = 0.0; // the game's beat, to tell how late views come; 0: no telling
    bool noDecode = false; // the channel's limit alone, as decoding takes a while
    // Plan WP11 step 1: rebuild each beat's game data from the views alone, with this match file's rules.
    std::string rebuild;
    std::string saveViews; // every message from the server's views, each as a 32-bit size and its bytes, to measure compression
    int fuzzCount = 2000;
    CImpairedPath::SConfig path;
    bool noLoad = false;
    // Plan WP2.2, WP2.13: print the lobby signals the server sends (Host, Join, ConnectToPeer, DisconnectFromPeer), and send one direct script message
    // through the relay to another participant at a time.
    std::string lobbyName;
    std::int32_t lobbySayTo = 0;
    double lobbySayAt = -1.0;
    // Plan WP2.14: send the lobby's launch to the server at a time, with `MatchConfig` from a match file as the
    // configuration (the host's `CLobby::LaunchGame` sends what FAF's lobby built).
    std::string lobbyLaunch;
    double lobbyLaunchAt = -1.0;
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
      if (name == "--no-decode") {
        out.noDecode = true;
        continue;
      }
      if (!name.empty() && name[0] == '/') {
        // The engine's own switches (`/init <file>`, `/nosound`), which `--rebuild`'s engine reads itself.
        if (i + 1 < argc && argv[i + 1][0] != '-' && argv[i + 1][0] != '/') {
          ++i;
        }
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
      } else if (name == "--pause-every") {
        out.pauseEvery = Argument(value);
      } else if (name == "--damage-at") {
        out.damageAt = Argument(value);
      } else if (name == "--lobby-name") {
        out.lobbyName = value;
      } else if (name == "--lobby-say-to") {
        out.lobbySayTo = std::atoi(value);
      } else if (name == "--lobby-say-at") {
        out.lobbySayAt = Argument(value);
      } else if (name == "--lobby-launch") {
        out.lobbyLaunch = value;
      } else if (name == "--lobby-launch-at") {
        out.lobbyLaunchAt = Argument(value);
      } else if (name == "--save-views") {
        out.saveViews = value;
      } else if (name == "--break-alliance-at") {
        out.breakAllianceAt = Argument(value);
      } else if (name == "--break-with") {
        out.breakWith = std::atoi(value);
      } else if (name == "--forge-at") {
        out.forgeAt = Argument(value);
      } else if (name == "--vanish-at") {
        out.vanishAt = Argument(value);
      } else if (name == "--vanish-for") {
        out.vanishFor = Argument(value);
      } else if (name == "--leave-at") {
        out.leaveAt = Argument(value);
      } else if (name == "--order-at") {
        out.orderAt = Argument(value);
      } else if (name == "--attack-blip-at") {
        out.attackBlipAt = Argument(value);
      } else if (name == "--forge-id-at") {
        out.forgeIdAt = Argument(value);
      } else if (name == "--attack-hidden-at") {
        out.attackHiddenAt = Argument(value);
      } else if (name == "--hidden-id") {
        out.hiddenId = static_cast<std::uint32_t>(std::strtoul(value, nullptr, 0));
      } else if (name == "--fuzz-at") {
        out.fuzzAt = Argument(value);
      } else if (name == "--fuzz-count") {
        out.fuzzCount = std::atoi(value);
      } else if (name == "--flood-at") {
        out.floodAt = Argument(value);
      } else if (name == "--beat-ms") {
        out.beatMs = Argument(value);
      } else if (name == "--loss") {
        out.path.lossPercent = Argument(value);
      } else if (name == "--latency-ms") {
        out.path.latencyMs = Argument(value);
      } else if (name == "--jitter-ms") {
        out.path.jitterMs = Argument(value);
      } else if (name == "--partition-at") {
        out.path.partitionAt = Argument(value);
      } else if (name == "--partition-for") {
        out.path.partitionFor = Argument(value);
      } else if (name == "--rebuild") {
        out.rebuild = value;
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

  void PutU32(std::vector<std::uint8_t>& out, const std::uint32_t value)
  {
    for (int shift = 0; shift < 32; shift += 8) {
      out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
  }

  void PutFloat(std::vector<std::uint8_t>& out, const float value)
  {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    PutU32(out, bits);
  }

  /**
   * An order, in the bytes `CMarshaller::IssueCommand` writes: a unit, its command id, and either a target
   * entity (`targetId`) or the ground at `x`, `z`.
   */
  /**
   * `SimCallback({Func = 'BreakAlliance', Args = {From = army, To = other}})` as `CMarshaller::LuaSimCallback` writes it:
   * the name, the arguments in the Lua byte stream's tags (`LuaObject::ToByteStream`), no entities. Armies count from 1 there.
   */
  [[nodiscard]] std::vector<std::uint8_t> BreakAlliancePayload(const std::int32_t army, const std::int32_t other)
  {
    std::vector<std::uint8_t> out;
    const auto putString = [&out](const char* const text) {
      out.insert(out.end(), text, text + std::strlen(text) + 1u);
    };
    const auto putNumber = [&out](const float value) {
      out.push_back(0u); // number
      std::uint8_t bytes[sizeof(value)];
      std::memcpy(bytes, &value, sizeof(value));
      out.insert(out.end(), bytes, bytes + sizeof(value));
    };
    putString("BreakAlliance");
    out.push_back(4u); // a table
    out.push_back(1u); // string key
    putString("From");
    putNumber(static_cast<float>(army + 1));
    out.push_back(1u);
    putString("To");
    putNumber(static_cast<float>(other + 1));
    out.push_back(5u); // its end
    PutU32(out, 0u);   // no entities
    return out;
  }

  [[nodiscard]] std::vector<std::uint8_t> OrderPayload(
    const std::uint32_t unit, const std::uint32_t commandId, const moho::EUnitCommandType type, const std::uint32_t targetId, const float x, const float z
  )
  {
    std::vector<std::uint8_t> out;
    PutU32(out, 1u);
    PutU32(out, unit);
    PutU32(out, commandId);
    PutU32(out, 0xFFFFFFFFu);
    out.push_back(static_cast<std::uint8_t>(type));
    PutU32(out, 0xFFFFFFFFu);
    if (targetId != kGroundTarget) {
      out.push_back(1u); // AITARGET_Entity
      PutU32(out, targetId);
    } else {
      out.push_back(2u); // AITARGET_Ground
      PutFloat(out, x);
      PutFloat(out, 0.0f);
      PutFloat(out, z);
    }
    out.push_back(0u); // AITARGET_None
    PutU32(out, 0xFFFFFFFFu);
    out.push_back(0u); // no blueprint
    PutU32(out, 0u);   // no cells
    PutU32(out, 1u);
    PutU32(out, 1u);
    out.push_back(2u); // Lua nil
    out.push_back(1u); // clear the queue
    return out;
  }

  /** What the player's game would do with its views, as far as a frame goes. */
  struct SViews
  {
    faf::remote::wire::SFrameCodec codec;
    faf::remote::CClientFrameWindow window;
    faf::remote::CClientFrameWindow teamWindow;
    faf::remote::wire::SViewFrame frame;     // the newest of the player's own
    faf::remote::wire::SViewFrame teamFrame; // and of their team's; empty without one
    bool haveFrame = false;
    bool haveInfo = false;
    float mapX = 0.0f;
    float mapZ = 0.0f;
    std::int32_t army = -1;
    std::uint32_t source = 0;
    bool noDecode = false;
    faf::probe::CProbeRebuild* rebuild = nullptr; // `--rebuild`
    int uid = 0;
    std::uint64_t launchInfos = 0;
    std::uint64_t tableMessages = 0; // `SessionTables`
    double beatMs = 0.0;
    double lateBase = 0.0;      // the seconds at which beat 0 would have come
    bool haveLateBase = false;
    std::vector<float> lateMs;  // each view's
    std::uint64_t views = 0;
    std::uint64_t failed = 0;
    std::uint64_t bytes = 0;
    std::uint64_t frameBytes = 0;
    std::uint64_t lastEntities = 0;
    std::uint64_t lastBeat = 0;
    std::uint64_t maxMessage = 0;
    std::uint64_t whole = 0;       // views after the first whose frame came against nothing: after a reconnect
    std::uint64_t gameInfos = 0;
    std::uint64_t checks = 0;      // `ViewCheck`s compared
    std::uint64_t mismatches = 0;  // and of them that didn't match
    bool askedWhole = false;       // a `ViewMismatch` went, and no check has matched since
    double damagedAt = -1.0;       // `--damage-at`'s time, once done
    double firstAt = -1.0;
    double lastAt = 0.0;
  };

  void TakeView(SViews& out, const std::vector<std::uint8_t>& message, const double elapsed)
  {
    if (message.empty()) {
      return;
    }
    if (message[0] == static_cast<std::uint8_t>(ESeatMessage::GameInfo) && message.size() == 1u + 2u * sizeof(float) + 2u * sizeof(std::int32_t)) {
      float sizes[2] = {};
      std::memcpy(sizes, message.data() + 1, sizeof(sizes));
      std::memcpy(&out.army, message.data() + 1 + sizeof(sizes), sizeof(out.army));
      std::memcpy(&out.source, message.data() + 1 + sizeof(sizes) + sizeof(out.army), sizeof(out.source));
      out.codec = faf::remote::MakeViewCodec(sizes[0], sizes[1]);
      out.mapX = sizes[0];
      out.mapZ = sizes[1];
      out.haveInfo = true;
      if (out.rebuild != nullptr) {
        out.rebuild->OnGameInfo(sizes[0], sizes[1], out.army);
      }
      ++out.gameInfos;
      return;
    }
    if (message[0] == static_cast<std::uint8_t>(ESeatMessage::LaunchInfo)) {
      ++out.launchInfos;
      if (out.rebuild != nullptr && !out.rebuild->HasRules()) {
        std::string error;
        if (out.rebuild->OnLaunchInfo(std::span<const std::uint8_t>(message).subspan(1), out.uid, error)) {
          std::printf("probe %d: %.1f s: rebuild: rules from the server's launch info (%zu bytes)\n", out.uid, elapsed, message.size() - 1u);
        } else {
          std::printf("probe %d: %.1f s: rebuild: %s\n", out.uid, elapsed, error.c_str());
        }
      }
      return;
    }
    if (message[0] == static_cast<std::uint8_t>(ESeatMessage::SessionTables)) {
      ++out.tableMessages;
      if (out.rebuild != nullptr) {
        out.rebuild->OnTables(message);
      }
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
    const std::uint64_t teamEntities = reader.Varint();
    if (out.noDecode) {
      out.lastEntities = entities;
      out.lastBeat = beat;
      return;
    }
    const std::uint64_t frameSize = reader.Varint();
    const std::uint8_t* const frame = reader.Bytes(frameSize);
    const std::uint64_t teamSize = reader.Varint();
    const std::uint8_t* const team = reader.Bytes(teamSize);
    bool ok = reader.Ok() && out.haveInfo;
    // The other lanes' sizes must add up to the message, to its last byte: army, grid, Lua.
    std::span<const std::uint8_t> lanes[3];
    for (int lane = 0; lane < 3 && ok; ++lane) {
      const std::uint64_t size = reader.Varint();
      const std::uint8_t* const bytes = reader.Bytes(size);
      ok = reader.Ok();
      if (ok) {
        lanes[lane] = std::span<const std::uint8_t>(bytes, size);
      }
    }
    ok = ok && reader.AtEnd();
    if (ok && out.views > 1u && faf::remote::wire::PeekFrameBaseline(std::span<const std::uint8_t>(frame, frameSize)) == faf::remote::wire::kNoBaseline) {
      ++out.whole;
      std::printf("probe: %.1f s: a whole view at beat %llu, %llu + %llu entities\n", elapsed, static_cast<unsigned long long>(beat),
                  static_cast<unsigned long long>(entities), static_cast<unsigned long long>(teamEntities));
    }
    if (ok) {
      if (out.rebuild != nullptr) {
        out.rebuild->OnView(std::span<const std::uint8_t>(frame, frameSize), std::span<const std::uint8_t>(team, teamSize), lanes[0], lanes[1]);
      }
      faf::remote::wire::SViewFrame decoded;
      ok = out.window.Decode(std::span<const std::uint8_t>(frame, frameSize), out.codec, decoded) && decoded.entities.size() == entities;
      faf::remote::wire::SViewFrame teamDecoded;
      if (ok && teamSize != 0u) {
        ok = out.teamWindow.Decode(std::span<const std::uint8_t>(team, teamSize), out.codec, teamDecoded) && teamDecoded.entities.size() == teamEntities;
      }
      out.frameBytes += frameSize + teamSize;
      out.lastEntities = entities + teamEntities;
      out.lastBeat = beat;
      out.frame = std::move(decoded);
      out.teamFrame = std::move(teamDecoded);
      out.haveFrame = ok;
    }
    out.failed += ok ? 0u : 1u;

    // How late against the earliest any view has come, as this clock and the server's share no start.
    if (out.beatMs > 0.0) {
      const double due = static_cast<double>(beat) * out.beatMs / 1000.0;
      const double offset = elapsed - due;
      if (!out.haveLateBase || offset < out.lateBase) {
        out.lateBase = offset;
        out.haveLateBase = true;
      }
      out.lateMs.push_back(static_cast<float>((offset - out.lateBase) * 1000.0));
    }
  }

  /** What's being watched of an order: it reaches the unit's queue, and the unit moves. */
  struct SOrderWatch
  {
    std::uint32_t unit = 0;
    std::uint32_t commandId = 0;
    faf::remote::wire::QuantizedPosition from{};
    bool queued = false;
    bool moved = false;
    bool active = false;
  };

  [[nodiscard]] const faf::remote::wire::SEntityRecord* OwnUnit(const SViews& views)
  {
    // An entity id holds its family and its army's source byte (remote/ViewIdMap.h); units are family 0.
    for (const faf::remote::wire::SEntityRecord& record : views.frame.entities) {
      if (record.isUnit && (record.id >> 28u) == 0u && static_cast<std::int32_t>((record.id >> 20u) & 0xFFu) == views.army) {
        return &record;
      }
    }
    return nullptr;
  }

  [[nodiscard]] const faf::remote::wire::SEntityRecord* FindEntity(const SViews& views, const std::uint32_t id)
  {
    for (const faf::remote::wire::SViewFrame* const frame : {&views.frame, &views.teamFrame}) {
      for (const faf::remote::wire::SEntityRecord& record : frame->entities) {
        if (record.id == id) {
          return &record;
        }
      }
    }
    return nullptr;
  }

  [[nodiscard]] const char* AnswerText(const std::uint8_t answer) noexcept
  {
    switch (static_cast<ECommandAnswer>(answer)) {
    case ECommandAnswer::Applied:
      return "applied";
    case ECommandAnswer::Refused:
      return "refused";
    case ECommandAnswer::Dropped:
      return "dropped";
    }
    return "?";
  }

  /** Plan WP2.2, WP2.13: what the probe saw of the lobby. */
  struct SLobbySeen
  {
    std::uint64_t messages = 0;
    std::string role = "none";              // from the server's Host or Join signal
    std::int32_t hostUid = 0;
    bool welcomed = false;
    std::int32_t hostedTime = 0;
    std::vector<std::int32_t> peers;        // from ConnectToPeer signals, in order
    std::vector<std::int32_t> established;  // the last EstablishedPeers
    std::vector<std::int32_t> scriptFrom;   // senders of script data, as the relay wrote them
    std::vector<std::int32_t> deleted;      // from DisconnectFromPeer signals
    bool rejected = false;
  };

  /** One `Lobby` frame from the server: varint sender (0: the server's signal), then the message; printed and noted. */
  void TakeLobby(const int uid, const double elapsed, const std::vector<std::uint8_t>& frame, SLobbySeen& seen)
  {
    ByteReader reader(frame.data() + 1, frame.size() - 1u);
    const auto from = static_cast<std::int32_t>(reader.Varint());
    std::size_t at = 1u + faf::remote::net::VarintSize(static_cast<std::uint64_t>(from));
    if (from == 0 && reader.Ok() && at < frame.size()) {
      ++seen.messages;
      faf::remote::net::SLobbySignal signal;
      if (!faf::remote::net::DecodeLobbySignal(std::span<const std::uint8_t>(frame).subspan(at), signal)) {
        std::printf("probe %d: %.1f s: a malformed lobby signal\n", uid, elapsed);
        return;
      }
      using faf::remote::net::ELobbySignal;
      switch (signal.kind) {
      case ELobbySignal::Host:
        seen.role = "host";
        std::printf("probe %d: %.1f s: lobby: host it as \"%s\", map %s\n", uid, elapsed, signal.name.c_str(), signal.text.c_str());
        break;
      case ELobbySignal::Join:
        seen.role = "join";
        seen.hostUid = signal.uid;
        std::printf("probe %d: %.1f s: lobby: join host \"%s\" (uid %d) as \"%s\"\n", uid, elapsed, signal.text.c_str(), signal.uid, signal.name.c_str());
        break;
      case ELobbySignal::ConnectToPeer:
        seen.peers.push_back(signal.uid);
        std::printf("probe %d: %.1f s: lobby: connect to peer \"%s\" (uid %d)\n", uid, elapsed, signal.name.c_str(), signal.uid);
        break;
      case ELobbySignal::DisconnectFromPeer:
        seen.deleted.push_back(signal.uid);
        std::printf("probe %d: %.1f s: lobby: peer %d left\n", uid, elapsed, signal.uid);
        break;
      case ELobbySignal::LaunchRefused:
        std::printf("probe %d: %.1f s: lobby: launch refused: %s\n", uid, elapsed, signal.text.c_str());
        break;
      case ELobbySignal::Launching:
        std::printf("probe %d: %.1f s: lobby: the server is starting the match\n", uid, elapsed);
        break;
      }
      return;
    }
    if (!reader.Ok() || at + 3u > frame.size()) {
      std::printf("probe %d: %.1f s: a malformed lobby frame\n", uid, elapsed);
      return;
    }
    ++seen.messages;
    const std::uint8_t type = frame[at];
    const std::size_t end = frame.size();
    at += 3u;
    const auto string = [&] {
      std::string text;
      while (at < end && frame[at] != 0u) {
        text.push_back(static_cast<char>(frame[at++]));
      }
      ++at;
      return text;
    };
    const auto int32 = [&] {
      std::uint32_t bits = 0;
      for (std::size_t i = 0; i < 4u && at < end; ++i) {
        bits |= static_cast<std::uint32_t>(frame[at++]) << (8u * i);
      }
      return static_cast<std::int32_t>(bits);
    };
    switch (type) {
    case 102: { // Welcome
      const std::string hostName = string();
      const std::int32_t hostUid = int32();
      const std::int32_t assigned = int32();
      const std::string name = string();
      seen.hostedTime = int32();
      seen.welcomed = assigned == uid;
      std::printf("probe %d: %.1f s: lobby: welcome from host \"%s\" (uid %d): uid %d, name \"%s\", seed %d\n", uid, elapsed, hostName.c_str(), hostUid, assigned,
                  name.c_str(), seen.hostedTime);
      break;
    }
    case 101:
      seen.rejected = true;
      std::printf("probe %d: %.1f s: lobby: rejected, %s\n", uid, elapsed, string().c_str());
      break;
    case 103: { // NewPeer
      const std::string name = string();
      const auto address = static_cast<std::uint32_t>(int32());
      const std::uint16_t port = at + 2u <= end ? static_cast<std::uint16_t>(frame[at] | (frame[at + 1] << 8)) : 0u;
      at += 2u;
      const std::int32_t peer = int32();
      seen.peers.push_back(peer);
      std::printf("probe %d: %.1f s: lobby: new peer \"%s\" uid %d at %u.%u.%u.%u:%u\n", uid, elapsed, name.c_str(), peer, address >> 24, (address >> 16) & 0xFFu,
                  (address >> 8) & 0xFFu, address & 0xFFu, port);
      break;
    }
    case 104:
      seen.deleted.push_back(int32());
      std::printf("probe %d: %.1f s: lobby: peer %d left\n", uid, elapsed, seen.deleted.back());
      break;
    case 105: { // EstablishedPeers
      seen.established.clear();
      for (std::int32_t peer = int32(); peer != -1 && at <= end; peer = int32()) {
        seen.established.push_back(peer);
      }
      std::string list;
      for (const std::int32_t peer : seen.established) {
        list += (list.empty() ? "" : " ") + std::to_string(peer);
      }
      std::printf("probe %d: %.1f s: lobby: established %s\n", uid, elapsed, list.c_str());
      break;
    }
    case 106:
    case 107:
      seen.scriptFrom.push_back(from);
      std::printf("probe %d: %.1f s: lobby: script data from uid %d, %zu bytes\n", uid, elapsed, from, end - at);
      break;
    default:
      std::printf("probe %d: %.1f s: lobby: message %u from uid %d\n", uid, elapsed, type, from);
      break;
    }
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
      "usage: faf_server_probe --server <ip:port> --uid <n> --token <t> [--seconds <s>] [--no-load] [--pause-at <s> [--pause-every <s>]] [--resume-at <s>] [--forge-at <s>] "
      "[--vanish-at <s> [--vanish-for <s>]] [--leave-at <s>] [--order-at <s>] [--attack-blip-at <s>] [--forge-id-at <s>] [--attack-hidden-at <s> --hidden-id <id>] [--fuzz-at <s> [--fuzz-count <n>]] "
      "[--flood-at <s>] [--break-alliance-at <s> --break-with <army>] [--save-views <file>] [--damage-at <s>] [--lobby-name <name> [--lobby-say-to <uid> --lobby-say-at <s>] [--lobby-launch <match.lua> --lobby-launch-at <s>]] [--beat-ms <ms>] [--loss <percent>] [--latency-ms <ms>] [--jitter-ms <ms>] [--partition-at <s> --partition-for <s>] [--rebuild <match.lua> /init <init.lua>]\n"
    );
    return 3;
  }

  std::string error;
  faf::probe::CProbeRebuild rebuild;
  if (options.rebuild == "server") {
    // Plan WPR.55: no match file; the rules come with the server's LaunchInfo.
    if (!rebuild.Start(error)) {
      std::printf("probe %d: rebuild: %s\n", options.uid, error.c_str());
      return 3;
    }
  } else if (!options.rebuild.empty()) {
    if (!rebuild.Load(options.rebuild, options.uid, error)) {
      std::printf("probe %d: rebuild: %s\n", options.uid, error.c_str());
      return 3;
    }
    std::printf("probe %d: rebuild: rules of %s loaded\n", options.uid, options.rebuild.c_str());
  }
  CImpairedPath path;
  SEndpoint server = options.server;
  if (options.path.Any()) {
    if (!path.Start(options.server, options.path, static_cast<std::uint32_t>(options.uid) + 1u, error)) {
      std::printf("probe %d: %s\n", options.uid, error.c_str());
      return 3;
    }
    server = path.PlayerSide();
  }
  CClientLink link(options.uid, MakeToken(options.token), server);
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
  SLobbySeen lobby;
  std::vector<std::uint8_t> message;
  SViews views;
  views.beatMs = options.beatMs;
  views.noDecode = options.noDecode;
  views.rebuild = options.rebuild.empty() ? nullptr : &rebuild;
  views.uid = options.uid;
  // Left to the process's end to close.
  std::FILE* const saved = options.saveViews.empty() ? nullptr : std::fopen(options.saveViews.c_str(), "wb");
  std::deque<const char*> asked; // what each answer will be about, in order
  std::uint64_t answers[3] = {};
  std::uint32_t nextCommand = 1u;
  SOrderWatch watch;
  bool orderWanted = false;
  bool blipWanted = false;
  bool forgedWanted = false;
  bool hiddenWanted = false;
  bool orderAnswered = false;
  bool orderApplied = false;
  bool ordered = options.orderAt >= 0.0;
  std::uint32_t attackedBlip = 0u;
  int fuzzLeft = 0;
  bool flooding = false;
  std::uint64_t floodSent = 0;
  std::mt19937 fuzzRandom(static_cast<std::uint32_t>(options.uid) * 7919u + 1u);
  static constexpr moho::ECmdStreamOp kFuzzOps[] = {
    moho::ECmdStreamOp::CMDST_ProcessInfoPair,      moho::ECmdStreamOp::CMDST_IssueCommand,          moho::ECmdStreamOp::CMDST_IssueFactoryCommand,
    moho::ECmdStreamOp::CMDST_IncreaseCommandCount, moho::ECmdStreamOp::CMDST_DecreaseCommandCount,  moho::ECmdStreamOp::CMDST_SetCommandTarget,
    moho::ECmdStreamOp::CMDST_SetCommandType,       moho::ECmdStreamOp::CMDST_SetCommandCells,       moho::ECmdStreamOp::CMDST_RemoveCommandFromQueue,
    moho::ECmdStreamOp::CMDST_LuaSimCallback,
  };

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
    if (Due(options.lobbyLaunchAt, elapsed) && !options.lobbyLaunch.empty()) {
      static LuaPlus::LuaState sLaunchState(LuaPlus::LuaState::LIB_BASE);
      std::ifstream file(options.lobbyLaunch, std::ios::binary);
      std::stringstream text;
      text << file.rdbuf();
      LuaPlus::LuaObject config;
      if (file && moho::SCR_LuaDoString(text.str().c_str(), &sLaunchState)) {
        config = sLaunchState.GetGlobal("MatchConfig");
      }
      moho::CMessage request(moho::ELobbyMsg::LOBMSG_DirectScriptData);
      bool encoded = false;
      if (config.IsTable()) {
        moho::CMessageStream stream(request, moho::CMessageStream::Access::kReadWrite);
        encoded = config.ToByteStream(stream);
      }
      if (!encoded) {
        std::printf("probe %d: %.1f s: lobby: no MatchConfig in %s to launch\n", options.uid, elapsed, options.lobbyLaunch.c_str());
      } else {
        const auto* const bytes = reinterpret_cast<const std::uint8_t*>(request.mBuff.start_) + 3;
        const std::size_t size = request.mBuff.Size() - 3u;
        const std::vector<std::uint8_t> message = faf::remote::net::EncodeLaunchRequest(std::span<const std::uint8_t>(bytes, size));
        std::vector<std::uint8_t> frame;
        faf::remote::net::ByteWriter writer(frame);
        writer.Byte(static_cast<std::uint8_t>(ESeatMessage::Lobby));
        writer.Varint(0u);
        writer.Bytes(message.data(), message.size());
        (void)link.SendReliable(frame.data(), frame.size());
        std::printf("probe %d: %.1f s: lobby: launch sent from %s, %zu bytes\n", options.uid, elapsed, options.lobbyLaunch.c_str(), size);
      }
    }
    if (Due(options.lobbySayAt, elapsed) && options.lobbySayTo != 0) {
      // A direct script message (`LOBMSG_DirectScriptData`, 107) through the relay; its bytes needn't be a Lua value here.
      const std::string text = "hello from " + std::to_string(options.uid);
      std::vector<std::uint8_t> frame;
      faf::remote::net::ByteWriter writer(frame);
      writer.Byte(static_cast<std::uint8_t>(ESeatMessage::Lobby));
      writer.Varint(static_cast<std::uint64_t>(options.lobbySayTo));
      const std::size_t size = 3u + text.size();
      writer.Byte(107u);
      writer.Byte(static_cast<std::uint8_t>(size));
      writer.Byte(static_cast<std::uint8_t>(size >> 8));
      writer.Bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
      (void)link.SendReliable(frame.data(), frame.size());
      std::printf("probe %d: %.1f s: lobby: script data to uid %d\n", options.uid, elapsed, options.lobbySayTo);
    }
    while (link.TakeReliable(message)) {
      if (!message.empty() && message[0] == static_cast<std::uint8_t>(ESeatMessage::Lobby)) {
        TakeLobby(options.uid, elapsed, message, lobby);
        continue;
      }
      if (!message.empty() && message[0] == static_cast<std::uint8_t>(ESeatMessage::CommandAnswer)) {
        ByteReader reader(message.data() + 1, message.size() - 1u);
        const std::uint64_t beat = reader.Varint();
        const std::uint8_t answer = reader.Byte();
        if (reader.Ok() && answer <= 2u) {
          ++answers[answer];
          const char* const what = asked.empty() ? nullptr : asked.front();
          if (!asked.empty()) {
            asked.pop_front();
          }
          if (what != nullptr) {
            std::printf("probe %d: %.1f s: the %s: %s, beat %llu\n", options.uid, elapsed, what, AnswerText(answer), static_cast<unsigned long long>(beat));
            if (std::strcmp(what, "order") == 0) {
              orderAnswered = true;
              orderApplied = static_cast<ECommandAnswer>(answer) == ECommandAnswer::Applied;
            }
          }
        }
        continue;
      }
      if (message[0] == static_cast<std::uint8_t>(ESeatMessage::ViewCheck)) {
        // Plan WPR.30: what the server says this client holds, against what it decoded.
        ByteReader reader(message.data() + 1, message.size() - 1u);
        const std::uint64_t beat = reader.Varint();
        const std::uint8_t* const hashes = reader.Bytes(2u * sizeof(std::uint64_t));
        if (reader.Ok() && !views.noDecode && views.haveFrame) {
          std::uint64_t expected[2] = {};
          std::memcpy(expected, hashes, sizeof(expected));
          std::uint64_t held[2] = {};
          for (const auto& record : views.frame.entities) {
            held[0] += faf::remote::wire::HashRecord(record);
          }
          for (const auto& record : views.teamFrame.entities) {
            held[1] += faf::remote::wire::HashRecord(record);
          }
          ++views.checks;
          if (held[0] != expected[0] || held[1] != expected[1]) {
            ++views.mismatches;
            if (!views.askedWhole) {
              views.askedWhole = true;
              const auto kind = static_cast<std::uint8_t>(ESeatMessage::ViewMismatch);
              (void)link.SendReliable(&kind, 1u);
              std::printf("probe %d: %.1f s: its frames don't match the server's check at beat %llu; asked for them whole\n", options.uid, elapsed,
                          static_cast<unsigned long long>(beat));
            }
          } else if (views.askedWhole) {
            views.askedWhole = false;
            std::printf("probe %d: %.1f s: its frames match the server's check again at beat %llu, %.2f s after the damage\n", options.uid, elapsed,
                        static_cast<unsigned long long>(beat), views.damagedAt >= 0.0 ? elapsed - views.damagedAt : 0.0);
          }
        }
        continue;
      }
      if (saved != nullptr) {
        const auto size = static_cast<std::uint32_t>(message.size());
        std::fwrite(&size, sizeof(size), 1, saved);
        std::fwrite(message.data(), 1, message.size(), saved);
        std::fflush(saved); // a probe is often stopped by a signal
      }
      TakeView(views, message, elapsed);
      // A view takes a while to decode, and the link mustn't go quiet meanwhile.
      link.Pump(static_cast<std::uint64_t>(std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() * 1e6));
    }
    if (watch.active && views.haveFrame) {
      if (const auto* const record = FindEntity(views, watch.unit); record != nullptr) {
        const std::vector<std::int32_t>& commands = record->unit.detail->commands;
        if (!watch.queued && std::find(commands.begin(), commands.end(), static_cast<std::int32_t>(watch.commandId)) != commands.end()) {
          watch.queued = true;
          std::printf("probe %d: %.1f s: the order is on unit 0x%08x's queue at beat %u\n", options.uid, elapsed, watch.unit, views.frame.beat);
        }
        if (!watch.moved && !(record->position == watch.from)) {
          watch.moved = true;
          std::printf("probe %d: %.1f s: unit 0x%08x has moved at beat %u\n", options.uid, elapsed, watch.unit, views.frame.beat);
        }
      }
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
      if (options.pauseEvery > 0.0) {
        options.resumeAt = elapsed + options.pauseEvery / 2.0;
        options.pauseAt = elapsed + options.pauseEvery;
      }
    }
    if (Due(options.resumeAt, elapsed)) {
      SendCommand(link, kOpResume);
      std::printf("probe %d: %.1f s: asked to resume, at beat %llu\n", options.uid, elapsed, static_cast<unsigned long long>(lastBeat));
    }
    if (views.haveFrame && Due(options.damageAt, elapsed)) {
      // Plan WPR.31: a field that never changes, in the frame the next one decodes against, so the damage stays.
      if (faf::remote::wire::SViewFrame* const kept = views.window.NewestFrame(); kept != nullptr && !kept->entities.empty()) {
        ++kept->entities[0].tickCreated;
        if (!views.frame.entities.empty()) {
          ++views.frame.entities[0].tickCreated;
        }
        views.damagedAt = elapsed;
        std::printf("probe %d: %.1f s: damaged entity 0x%08x of its own frame\n", options.uid, elapsed, kept->entities[0].id);
      }
    }
    if (views.haveInfo && Due(options.breakAllianceAt, elapsed)) {
      SendCommand(link, static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_LuaSimCallback), BreakAlliancePayload(views.army, options.breakWith));
      std::printf("probe %d: %.1f s: broke the alliance of army %d with army %d, at beat %llu\n", options.uid, elapsed, views.army, options.breakWith,
                  static_cast<unsigned long long>(lastBeat));
    }
    if (Due(options.forgeAt, elapsed)) {
      const std::vector<std::uint8_t> manyBeats = {0xA0, 0x86, 0x01, 0x00};
      SendCommand(link, kOpAdvance, manyBeats);
      SendCommand(link, kOpEndGame);
      std::printf("probe %d: %.1f s: sent forged beats and a forged end of game\n", options.uid, elapsed);
    }
    orderWanted = Due(options.orderAt, elapsed) || orderWanted;
    if (orderWanted && views.haveFrame && views.haveInfo) {
      if (const auto* const unit = OwnUnit(views); unit != nullptr) {
        orderWanted = false;
        watch.unit = unit->id;
        watch.commandId = (views.source << 24u) | nextCommand++;
        watch.from = unit->position;
        watch.active = true;
        SendCommand(link, kOpIssueCommand, OrderPayload(watch.unit, watch.commandId, moho::EUnitCommandType::UNITCOMMAND_Move, kGroundTarget, views.mapX * 0.5f, views.mapZ * 0.5f));
        asked.push_back("order");
        std::printf("probe %d: %.1f s: ordered unit 0x%08x to the map's middle, command 0x%08x, at view beat %u\n", options.uid, elapsed, watch.unit, watch.commandId, views.frame.beat);
      }
    }
    blipWanted = Due(options.attackBlipAt, elapsed) || blipWanted;
    if (blipWanted && views.haveFrame && views.haveInfo) {
      const auto* const unit = OwnUnit(views);
      const auto isBlip = [&views](const faf::remote::wire::SEntityRecord& record) {
        // A blip of the player's own unit is theirs to leave out (remote/ViewPackets.h).
        return (record.id >> 28u) == 3u && static_cast<std::int32_t>((record.id >> 20u) & 0xFFu) != views.army;
      };
      const auto& blipFrame = views.teamFrame.entities.empty() ? views.frame : views.teamFrame;
      const auto blip = std::find_if(blipFrame.entities.begin(), blipFrame.entities.end(), isBlip);
      if (unit != nullptr && blip != blipFrame.entities.end()) {
        blipWanted = false;
        attackedBlip = blip->id;
        SendCommand(link, kOpIssueCommand, OrderPayload(unit->id, (views.source << 24u) | nextCommand++, moho::EUnitCommandType::UNITCOMMAND_Attack, attackedBlip, 0.0f, 0.0f));
        asked.push_back("attack on a blip");
        std::printf("probe %d: %.1f s: ordered unit 0x%08x to attack blip 0x%08x, as this view numbers it, at view beat %u\n", options.uid, elapsed, unit->id, attackedBlip, views.frame.beat);
      }
    }
    forgedWanted = Due(options.forgeIdAt, elapsed) || forgedWanted;
    if (forgedWanted && views.haveFrame && views.haveInfo) {
      if (const auto* const unit = OwnUnit(views); unit != nullptr) {
        forgedWanted = false;
        SendCommand(link, kOpIssueCommand, OrderPayload(unit->id, (views.source << 24u) | nextCommand++, moho::EUnitCommandType::UNITCOMMAND_Attack, kForgedBlipId, 0.0f, 0.0f));
        asked.push_back("attack on a blip it was never shown");
        std::printf("probe %d: %.1f s: ordered an attack on blip 0x%08x, which its view never had\n", options.uid, elapsed, kForgedBlipId);
      }
    }
    hiddenWanted = Due(options.attackHiddenAt, elapsed) || hiddenWanted;
    if (hiddenWanted && views.haveFrame && views.haveInfo) {
      if (const auto* const unit = OwnUnit(views); unit != nullptr) {
        hiddenWanted = false;
        watch.unit = unit->id;
        watch.commandId = (views.source << 24u) | nextCommand++;
        watch.from = unit->position;
        watch.active = true;
        SendCommand(link, kOpIssueCommand, OrderPayload(unit->id, watch.commandId, moho::EUnitCommandType::UNITCOMMAND_Attack, options.hiddenId, 0.0f, 0.0f));
        asked.push_back("attack on a unit it can't see");
        std::printf(
          "probe %d: %.1f s: ordered unit 0x%08x to attack unit 0x%08x, which its view %s, at view beat %u\n", options.uid, elapsed, unit->id, options.hiddenId,
          FindEntity(views, options.hiddenId) != nullptr ? "holds" : "doesn't hold", views.frame.beat
        );
      }
    }
    if (Due(options.fuzzAt, elapsed)) {
      fuzzLeft = options.fuzzCount;
      std::printf("probe %d: %.1f s: sending %d commands of random bytes\n", options.uid, elapsed, options.fuzzCount);
    }
    for (int burst = 0; burst < 8 && fuzzLeft > 0; ++burst, --fuzzLeft) {
      std::vector<std::uint8_t> payload(fuzzRandom() % 400u);
      for (std::uint8_t& byte : payload) {
        byte = static_cast<std::uint8_t>(fuzzRandom());
      }
      asked.push_back(nullptr);
      SendCommand(link, static_cast<std::uint8_t>(kFuzzOps[fuzzRandom() % std::size(kFuzzOps)]), payload);
    }
    if (Due(options.floodAt, elapsed)) {
      flooding = true;
      std::printf("probe %d: %.1f s: flooding the server with commands\n", options.uid, elapsed);
    }
    if (flooding) {
      for (int burst = 0; burst < 200; ++burst, ++floodSent) {
        SendCommand(link, kOpRequestPause);
      }
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
    "probe %d: %llu views, %llu didn't decode, %llu whole after the first, %llu game infos, %llu launch infos, %llu session-table messages, %llu checks (%llu didn't match), last at beat %llu with %llu entities, %.1f KB/s (frames %.1f), largest %llu bytes\n", options.uid,
    static_cast<unsigned long long>(views.views), static_cast<unsigned long long>(views.failed), static_cast<unsigned long long>(views.whole),
    static_cast<unsigned long long>(views.gameInfos), static_cast<unsigned long long>(views.launchInfos), static_cast<unsigned long long>(views.tableMessages), static_cast<unsigned long long>(views.checks), static_cast<unsigned long long>(views.mismatches),
    static_cast<unsigned long long>(views.lastBeat),
    static_cast<unsigned long long>(views.lastEntities), viewSeconds > 0.0 ? static_cast<double>(views.bytes) / 1024.0 / viewSeconds : 0.0,
    viewSeconds > 0.0 ? static_cast<double>(views.frameBytes) / 1024.0 / viewSeconds : 0.0, static_cast<unsigned long long>(views.maxMessage)
  );
  std::printf(
    "probe %d: answers: %llu applied, %llu refused, %llu dropped%s\n", options.uid, static_cast<unsigned long long>(answers[0]), static_cast<unsigned long long>(answers[1]),
    static_cast<unsigned long long>(answers[2]), flooding ? (" (flooded)") : ""
  );
  if (!options.rebuild.empty()) {
    rebuild.Report(options.uid);
  }
  if (!options.lobbyName.empty()) {
    const auto list = [](const std::vector<std::int32_t>& uids) {
      std::string text;
      for (const std::int32_t uid : uids) {
        text += (text.empty() ? "" : " ") + std::to_string(uid);
      }
      return text.empty() ? std::string("none") : text;
    };
    std::printf("probe %d: lobby: %llu messages, role %s, host %d, peers %s, script data from %s, left %s\n", options.uid,
                static_cast<unsigned long long>(lobby.messages), lobby.role.c_str(), lobby.hostUid, list(lobby.peers).c_str(), list(lobby.scriptFrom).c_str(),
                list(lobby.deleted).c_str());
  }
  if (!views.lateMs.empty()) {
    std::sort(views.lateMs.begin(), views.lateMs.end());
    const auto at = [&views](const double share) {
      return views.lateMs[std::min(views.lateMs.size() - 1u, static_cast<std::size_t>(static_cast<double>(views.lateMs.size()) * share))];
    };
    std::printf("probe %d: views late by: median %.0f ms, 90%% %.0f ms, 99%% %.0f ms, worst %.0f ms\n", options.uid, at(0.5), at(0.9), at(0.99), views.lateMs.back());
  }
  if (options.path.Any()) {
    std::printf(
      "probe %d: network: loss %.1f%%, latency %.0f ms, jitter %.0f ms: %llu of %llu datagrams lost\n", options.uid, options.path.lossPercent, options.path.latencyMs, options.path.jitterMs,
      static_cast<unsigned long long>(path.Lost()), static_cast<unsigned long long>(path.Seen())
    );
  }
  if (refused) {
    return 1;
  }
  const bool orderDone = !ordered || (orderAnswered && orderApplied && watch.queued);
  return joins > 0u && beatMessages > 0u && views.failed == 0u && orderDone ? 0 : 2;
}
