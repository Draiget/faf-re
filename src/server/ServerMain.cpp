// Engine addition, dedicated server (plan WP1.1, WP0.7, WP1.5): the `server` program. The sim and
// what a game needs of the engine, with no CScApp, wx, D3D, XACT or Win32.
//
// This is the first slice of it: a match with no players connected, the server being the one client,
// an observer with no army. It plays the match in `--match` to its end and leaves the replay, a result
// and the engine's log in `--out`. Seats (WP3.1), the lobby (WP2) and the net channel (WP10) come onto
// this.
//
// The console is for whoever runs the server: state changes, a status line every so often, and the
// sim's speed when it changes or comes close to -1. Everything else the engine says goes to the log.

#include <Windows.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <charconv>
#include <exception>
#include <filesystem>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "headless/ReplayLuaState.h"
#include "headless/SessionLoad.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "gpg/core/streams/BinaryReader.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ELobbyMsg.h"
#include "remote/net/LobbySignals.h"
#include "moho/app/IWinApp.h"
#include "moho/app/WinApp.h"
#include "moho/core/ThreadPlacement.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/MathReflection.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/LaunchInfoBuilder.h"
#include "moho/sim/CWldMap.h"
#include "remote/ServerClient.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WldSessionInfo.h"
#include "platform/X87Precision.h"
#include "remote/net/UdpSocket.h"
#include "remote/ContentTables.h"
#include "server/ControlListener.h"
#include "server/LiveReplaySender.h"
#include "server/ObserverListener.h"
#include "server/ReplayLog.h"
#include "server/LobbySignaller.h"
#include "server/ServerNet.h"
#include "server/ServerViews.h"
#include "remote/SpeedLimit.h"
#include "server/LinkSpeed.h"
#include "server/SpeedWatch.h"

namespace
{
  // WP1.5.
  constexpr int kExitEnded = 0;
  constexpr int kExitNobodyCame = 2;
  constexpr int kExitCrash = 3;
  constexpr int kExitBadInput = 4;
  constexpr int kExitStopped = 5;

  // The server's own client: an observer, named after the players in the launch.
  constexpr std::int32_t kServerUid = 0;
  constexpr const char* kServerName = "server";

  constexpr const char* kUsage =
    "usage: server --match <file.lua> --out <dir> /init <init.lua> [--speed <n>] [--stop-beat <n>] [--timeout <minutes>] [--status-minutes <n>] "
    "[--warn-beat-ms <n>] [--listen <ip:port>] [--join-seconds <n>] [--reconnect-seconds <n>] [--lead-ms <n>] [--view-threads <n>] [--per-player-views] [--team-views] [--away-pause-seconds <n>] [--defeated-view observe|disconnect] [--lobby-seconds <n>] [--lobby-away-seconds <n>] [--stats-every <beats>] [--congestion-control]\n";

  constexpr double kDefaultStatusMinutes = 10.0;
  // Plan WP13.7: how long a defeated player keeps their view with `DefeatedPlayerView = "disconnect"`: the defeat banner
  // and the commander's explosion (`AIBrain.OnDefeat`, `lua/aibrain.lua`, waits 10 s before it hands the army over).
  constexpr double kDefeatedLeaveSeconds = 10.0;
  // `net_Lag` is 500 ms in a lockstep game, time for every player's beats to arrive. Here it's only the
  // sim's head start on the next beat, and a player's command waits for all of it.
  constexpr float kDefaultLeadMs = 150.0f;
  constexpr float kDefaultWarnBeatMs = 90.0f; // speed -1 starts at `faf::server::kSpeedZeroBeatMs`
  constexpr double kStallSeconds = 30.0;
  // After a slow stretch the game runs fast for at most this long to make up the time.
  constexpr double kMaxCatchUpSeconds = 1.0;

  using Clock = std::chrono::steady_clock;

  volatile std::sig_atomic_t gStopSignal = 0;
  volatile std::sig_atomic_t gPauseRequests = 0;
  volatile std::sig_atomic_t gForceStartRequests = 0; // plan WPR.49: SIGUSR2, the operator starts the match from the lobby
  faf::server::CControlListener* gControl = nullptr;    // plan WP17.2: the console's lines also go to the control service

  [[nodiscard]] double SecondsSince(const Clock::time_point start)
  {
    return std::chrono::duration<double>(Clock::now() - start).count();
  }

  [[nodiscard]] bool ReadOption(const char* const name, std::string& value)
  {
    fa::vector<fa::string> args;
    if (!moho::CFG_GetArgOption(name, 1, &args) || args.empty()) {
      return false;
    }
    value = args[0].c_str();
    return true;
  }

  /** A line for whoever runs the server, also in the log so the two can be read together. */
  void Say(const char* const format, ...)
  {
    char text[1024];
    va_list args;
    va_start(args, format);
    (void)std::vsnprintf(text, sizeof(text), format, args);
    va_end(args);

    const std::time_t now = std::time(nullptr);
    std::tm local{};
    (void)localtime_r(&now, &local);
    char stamp[32];
    (void)std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local);
    std::printf("[%s] %s\n", stamp, text);
    gpg::Logf("server: %s", text);
    if (gControl != nullptr) {
      gControl->Event("log", "\"text\":" + faf::server::JsonString(text));
    }
  }

  [[nodiscard]] std::uint64_t ControlNowUs()
  {
    return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
    );
  }

  [[nodiscard]] std::string ClockText(const double seconds)
  {
    const int whole = static_cast<int>(seconds);
    char text[32];
    (void)std::snprintf(text, sizeof(text), "%02d:%02d:%02d", whole / 3600, whole / 60 % 60, whole % 60);
    return text;
  }

  /** A beat is a tenth of a second of game time. */
  [[nodiscard]] std::string GameClockText(const int beat)
  {
    return ClockText(beat / 10.0);
  }

  [[nodiscard]] long ResidentMegabytes()
  {
    std::ifstream file("/proc/self/statm");
    long totalPages = 0;
    long residentPages = 0;
    file >> totalPages >> residentPages;
    return residentPages * ::sysconf(_SC_PAGESIZE) / (1024 * 1024);
  }

  void CrashSignal(const int signalNumber)
  {
    char text[64];
    const int length = std::snprintf(text, sizeof(text), "server: crash, signal %d\n", signalNumber);
    (void)!::write(STDOUT_FILENO, text, static_cast<std::size_t>(length));
    std::_Exit(kExitCrash);
  }

  void PauseSignal(const int)
  {
    gPauseRequests = gPauseRequests + 1;
  }

  void ForceStartSignal(const int)
  {
    gForceStartRequests = gForceStartRequests + 1;
  }

  void StopSignal(const int signalNumber)
  {
    gStopSignal = signalNumber;
  }

  /** Counts the engine's warnings, as the console shows a number and leaves the text to the log. */
  class CLogWarningCounter final : public gpg::LogTarget
  {
  public:
    CLogWarningCounter()
      : gpg::LogTarget(true)
    {}

    void OnMessage(const gpg::LogSeverity level, const fa::string&, const fa::vector<fa::string>&, int) override
    {
      if (level == gpg::LogSeverity::Warn) {
        mWarnings.fetch_add(1, std::memory_order_relaxed);
      }
    }

    [[nodiscard]] unsigned long Count() const { return mWarnings.load(std::memory_order_relaxed); }

  private:
    std::atomic<unsigned long> mWarnings{0};
  };

  class CServerApp final : public moho::IWinApp
  {
  public:
    CServerApp()
      : moho::IWinApp("SupCom", "SupremeCommander")
    {}

    bool Init() override { return AppInitCommonServices(); }
    void Main() override {}
    void Destroy() override {}
  };

  /** One army with a player or an AI behind it, in the launch's order (`BuildLaunchInfo`). */
  struct SMatchPlayer
  {
    int slot = 0;
    std::string name;
    int team = 0;
    bool human = false;
    std::string result;
  };

  /** The match file: Lua that sets `MatchConfig`, the table `CLobby.LaunchGame` takes, `MatchSeed` and `MatchName`. */
  [[nodiscard]] bool LoadMatch(LuaPlus::LuaState* const state, const std::string& path, LuaPlus::LuaObject& config, std::int32_t& seed, std::string& error)
  {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      error = "cannot read " + path;
      return false;
    }
    std::stringstream text;
    text << file.rdbuf();
    if (!moho::SCR_LuaDoString(text.str().c_str(), state)) {
      error = path + " doesn't run";
      return false;
    }
    config = state->GetGlobal("MatchConfig");
    if (!config.IsTable()) {
      error = path + " sets no MatchConfig";
      return false;
    }
    const LuaPlus::LuaObject seedObject = state->GetGlobal("MatchSeed");
    seed = seedObject.IsNumber() ? static_cast<std::int32_t>(seedObject.GetNumber()) : 1;

    // The server is in the launch as an observer, so no army waits on it.
    LuaPlus::LuaObject observers = config["Observers"];
    if (!observers.IsTable()) {
      observers.AssignNewTable(state, 1, 0u);
      config.SetObject("Observers", observers);
    }
    LuaPlus::LuaObject self;
    self.AssignNewTable(state, 0, 2u);
    self.SetString("OwnerID", "0"); // `kServerUid`, as a lobby writes ids
    self.SetString("PlayerName", kServerName);
    observers.SetObject(observers.GetN() + 1, self);
    return true;
  }

  /** `MatchTokens`, by `OwnerID`: outside `MatchConfig`, as what's in there goes in the replay and to every player. */
  [[nodiscard]] std::map<std::int32_t, std::string> ReadTokens(LuaPlus::LuaState* const state)
  {
    std::map<std::int32_t, std::string> tokens;
    LuaPlus::LuaObject table = state->GetGlobal("MatchTokens");
    if (!table.IsTable()) {
      return tokens;
    }
    for (LuaPlus::LuaTableIterator it(&table, 1); !it.m_isDone; it.Next()) {
      const LuaPlus::LuaObject key = it.GetKey();
      const LuaPlus::LuaObject value = it.GetValue();
      if (key.IsString() && value.IsString()) {
        tokens[std::atoi(key.GetString())] = value.GetString();
      }
    }
    return tokens;
  }

  /**
   * Plan WPR.45: `MatchAddresses`, by `OwnerID`, each an IPv4 address or a list of them, outside `MatchConfig` as the
   * tokens are. The addresses FAF knows its players by. False with `error` for one that doesn't parse.
   */
  [[nodiscard]] bool ReadAddresses(LuaPlus::LuaState* const state, std::vector<std::uint32_t>& addresses, std::string& error)
  {
    LuaPlus::LuaObject table = state->GetGlobal("MatchAddresses");
    if (!table.IsTable()) {
      return true;
    }
    const auto add = [&](const LuaPlus::LuaObject& value) {
      faf::remote::net::SEndpoint endpoint;
      if (!value.IsString() || !faf::remote::net::ParseEndpoint(std::string(value.GetString()) + ":1", endpoint)) {
        error = std::string("MatchAddresses holds ") + (value.IsString() ? value.GetString() : "a value that isn't a string") + ", not an IPv4 address";
        return false;
      }
      addresses.push_back(endpoint.ip);
      return true;
    };
    for (LuaPlus::LuaTableIterator it(&table, 1); !it.m_isDone; it.Next()) {
      LuaPlus::LuaObject value = it.GetValue();
      if (value.IsTable()) {
        for (LuaPlus::LuaTableIterator one(&value, 1); !one.m_isDone; one.Next()) {
          if (!add(one.GetValue())) {
            return false;
          }
        }
      } else if (!add(value)) {
        return false;
      }
    }
    return true;
  }

  /** Plan WPR.42: the sim mods a match names. FAF's lobby puts only sim mods in `GameMods` (`Mods.GetGameMods`). */
  [[nodiscard]] int CountSimMods(const LuaPlus::LuaObject& config)
  {
    LuaPlus::LuaObject mods = config["GameMods"];
    int count = 0;
    if (mods.IsTable()) {
      for (LuaPlus::LuaTableIterator it(&mods, 1); !it.m_isDone; it.Next()) {
        ++count;
      }
    }
    return count;
  }

  [[nodiscard]] std::vector<SMatchPlayer> ReadPlayers(const LuaPlus::LuaObject& config)
  {
    std::vector<SMatchPlayer> players;
    LuaPlus::LuaObject options = config["PlayerOptions"];
    if (!options.IsTable()) {
      return players;
    }
    LuaPlus::LuaTableIterator it(&options, 1);
    while (!it.m_isDone) {
      LuaPlus::LuaObject key = it.GetKey();
      LuaPlus::LuaObject value = it.GetValue();
      SMatchPlayer player;
      player.slot = key.GetInteger();
      const LuaPlus::LuaObject name = value["PlayerName"];
      player.name = name.IsString() ? name.GetString() : "?";
      const LuaPlus::LuaObject team = value["Team"];
      player.team = team.IsNumber() ? static_cast<int>(team.GetNumber()) : 0;
      const LuaPlus::LuaObject human = value["Human"];
      player.human = human.IsBoolean() && human.GetBoolean();
      players.push_back(player);
      it.Next();
    }
    std::sort(players.begin(), players.end(), [](const SMatchPlayer& lhs, const SMatchPlayer& rhs) { return lhs.slot < rhs.slot; });
    return players;
  }

  /** Plan WP2.14: what a launch check compares, from a game configuration. */
  [[nodiscard]] faf::server::SLaunchFacts ReadLaunchFacts(const LuaPlus::LuaObject& config)
  {
    faf::server::SLaunchFacts facts;
    LuaPlus::LuaObject options = config["GameOptions"];
    if (options.IsTable()) {
      const LuaPlus::LuaObject scenario = options["ScenarioFile"];
      facts.scenario = scenario.IsString() ? scenario.GetString() : "";
    }
    LuaPlus::LuaObject players = config["PlayerOptions"];
    if (players.IsTable()) {
      for (LuaPlus::LuaTableIterator it(&players, 1); !it.m_isDone; it.Next()) {
        LuaPlus::LuaObject player = it.GetValue();
        if (!player.IsTable()) {
          continue;
        }
        const LuaPlus::LuaObject human = player["Human"];
        if (!human.IsBoolean() || !human.GetBoolean()) {
          continue;
        }
        const LuaPlus::LuaObject owner = player["OwnerID"];
        facts.humans.push_back(
          owner.IsString() ? std::atoi(owner.GetString()) : (owner.IsNumber() ? static_cast<std::int32_t>(owner.GetNumber()) : -1)
        );
      }
    }
    facts.gameMods = CountSimMods(config);
    return facts;
  }

  /** A launch request's configuration, decoded as `CLobby` decodes script data; false when it isn't a table. */
  [[nodiscard]] bool DecodeLaunchConfig(
    LuaPlus::LuaState* const state, const std::span<const std::uint8_t> bytes, LuaPlus::LuaObject& codec, LuaPlus::LuaObject& out
  )
  {
    try {
      moho::CMessage message(moho::ELobbyMsg::LOBMSG_DirectScriptData);
      (void)message.Append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
      moho::CMessageStream stream(&message, moho::CMessageStream::Access::kReadOnly);
      const gpg::BinaryReader reader{&stream};
      codec.SCR_FromByteStream(out, state, &reader);
    } catch (const std::exception&) {
      return false;
    }
    return out.IsTable();
  }

  /**
   * Plan WPR.55: the `LaunchInfo` message, the match's configuration in the lobby's Lua byte form. Empty when it can't
   * be written or is too large for one message's 16-bit size.
   */
  [[nodiscard]] std::vector<std::uint8_t> MakeLaunchInfo(LuaPlus::LuaObject& config)
  {
    moho::CMessage message(moho::ELobbyMsg::LOBMSG_DirectScriptData);
    bool written = false;
    {
      moho::CMessageStream stream(message, moho::CMessageStream::Access::kReadWrite);
      written = config.ToByteStream(stream);
    }
    constexpr std::size_t kHeaderBytes = 3u; // type, 16-bit size
    const std::size_t size = message.mBuff.Size();
    if (!written || size <= kHeaderBytes || size > 0xFFFFu) {
      return {};
    }
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(message.mBuff.start_);
    std::vector<std::uint8_t> out;
    out.reserve(1u + size - kHeaderBytes);
    out.push_back(static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::LaunchInfo));
    out.insert(out.end(), bytes + kHeaderBytes, bytes + size);
    return out;
  }

  /** One Lua value in the lobby's byte form (`LuaObject::ToByteStream`, as script data carries it); empty on failure. */
  [[nodiscard]] std::vector<std::uint8_t> LuaValueBytes(LuaPlus::LuaObject value)
  {
    moho::CMessage message(moho::ELobbyMsg::LOBMSG_DirectScriptData);
    bool written = false;
    {
      moho::CMessageStream stream(message, moho::CMessageStream::Access::kReadWrite);
      written = value.ToByteStream(stream);
    }
    constexpr std::size_t kHeaderBytes = 3u; // type, 16-bit size
    const std::size_t size = message.mBuff.Size();
    if (!written || size <= kHeaderBytes) {
      return {};
    }
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(message.mBuff.start_);
    return std::vector<std::uint8_t>(bytes + kHeaderBytes, bytes + size);
  }

  /**
   * Plan WPR.49: the game options no participant's lobby may change, with the match's values. The match file's
   * `MatchPinnedOptions`, a list of `GameOptions` keys, outside `MatchConfig` as the tokens are; without one, every
   * option `MatchConfig.GameOptions` sets (the game is launched with those whatever the host's lobby shows).
   */
  [[nodiscard]] faf::server::SPinnedOptions ReadPinnedOptions(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& config)
  {
    faf::server::SPinnedOptions pinned;
    LuaPlus::LuaObject options = config["GameOptions"];
    if (!options.IsTable()) {
      return pinned;
    }
    const auto pin = [&](const char* const key) {
      std::vector<std::uint8_t> bytes = LuaValueBytes(options[key]);
      if (options[key].IsNil() || bytes.empty()) {
        Say("MatchPinnedOptions names %s, which MatchConfig.GameOptions doesn't set; not pinned", key);
        return;
      }
      pinned[key] = std::move(bytes);
    };
    LuaPlus::LuaObject keys = state->GetGlobal("MatchPinnedOptions");
    if (keys.IsTable()) {
      for (LuaPlus::LuaTableIterator it(&keys, 1); !it.m_isDone; it.Next()) {
        const LuaPlus::LuaObject key = it.GetValue();
        if (key.IsString()) {
          pin(key.GetString());
        }
      }
      return pinned;
    }
    for (LuaPlus::LuaTableIterator it(&options, 1); !it.m_isDone; it.Next()) {
      const LuaPlus::LuaObject key = it.GetKey();
      if (key.IsString()) {
        pin(key.GetString());
      }
    }
    return pinned;
  }

  /** Plan WP2.6: the match file's `MatchContentCheck` ("off", "warn", "refuse"); "warn" without one. */
  [[nodiscard]] bool ReadContentCheck(LuaPlus::LuaState* const state, faf::remote::EContentCheck& mode, std::string& error)
  {
    const LuaPlus::LuaObject text = state->GetGlobal("MatchContentCheck");
    mode = faf::remote::EContentCheck::Warn;
    if (text.IsNil()) {
      return true;
    }
    const std::optional<faf::remote::EContentCheck> read = text.IsString() ? faf::remote::ReadContentCheck(text.GetString()) : std::nullopt;
    if (!read) {
      error = "MatchContentCheck is \"off\", \"warn\" or \"refuse\"";
      return false;
    }
    mode = *read;
    return true;
  }

  /** Plan WP17.8: the match file's `MatchUiMods`, the UI mods a player may run (`{}`: none); nothing when it isn't set. */
  [[nodiscard]] bool ReadUiMods(LuaPlus::LuaState* const state, std::optional<std::vector<std::string>>& allowed, std::string& error)
  {
    LuaPlus::LuaObject table = state->GetGlobal("MatchUiMods");
    if (table.IsNil()) {
      return true;
    }
    if (!table.IsTable()) {
      error = "MatchUiMods is a table of mod uids ({} for none)";
      return false;
    }
    allowed.emplace();
    for (LuaPlus::LuaTableIterator it(&table, 1); !it.m_isDone; it.Next()) {
      const LuaPlus::LuaObject value = it.GetValue();
      const std::size_t size = value.IsString() ? std::strlen(value.GetString()) : 0u;
      if (size == 0u || size > faf::remote::kMaxModText) {
        error = "MatchUiMods holds mod uids: strings of 1 to " + std::to_string(faf::remote::kMaxModText) + " characters";
        return false;
      }
      allowed->emplace_back(value.GetString());
    }
    return true;
  }

  /** Plan WP15.1: a tournament's rules, the match file's `MatchRules` table; each unset unless the match sets it. */
  struct SMatchRules
  {
    std::optional<double> reconnectSeconds;  // the reconnect window (`--reconnect-seconds`)
    std::optional<double> awayPauseSeconds;  // each player's pause while away (`--away-pause-seconds`)
    std::optional<double> lobbyAwaySeconds;  // the logical host's succession (`--lobby-away-seconds`)
    std::optional<double> observerDelaySeconds; // plan WP13.1: how far behind the game observers watch
    bool fixedSpeed = false;                 // nobody changes the game speed
    bool noCheats = false;                   // `CheatsEnabled` is "false", whatever a host or organiser sets
    std::string defeatedPlayerView;          // plan WP13.4: "observe" (as the original game) or "disconnect" (`--defeated-view`)
    std::optional<int> gameVersion;          // plan WP15.1: the FAF game version the match is for (`/lua/version.lua`)
  };

  [[nodiscard]] bool ReadMatchRules(LuaPlus::LuaState* const state, SMatchRules& matchRules, std::string& error)
  {
    const LuaPlus::LuaObject table = state->GetGlobal("MatchRules");
    if (table.IsNil()) {
      return true;
    }
    if (!table.IsTable()) {
      error = "MatchRules is a table";
      return false;
    }
    const auto seconds = [&](const char* const key, std::optional<double>& out) {
      const LuaPlus::LuaObject value = table[key];
      if (value.IsNil()) {
        return true;
      }
      if (!value.IsNumber() || value.GetNumber() < 0.0 || value.GetNumber() > 86400.0) {
        error = std::string("MatchRules.") + key + " is seconds, 0 to 86400";
        return false;
      }
      out = value.GetNumber();
      return true;
    };
    const auto flag = [&](const char* const key, bool& out) {
      const LuaPlus::LuaObject value = table[key];
      if (value.IsNil()) {
        return true;
      }
      if (!value.IsBoolean()) {
        error = std::string("MatchRules.") + key + " is true or false";
        return false;
      }
      out = value.GetBoolean();
      return true;
    };
    if (!(seconds("ReconnectSeconds", matchRules.reconnectSeconds) && seconds("AwayPauseSeconds", matchRules.awayPauseSeconds) &&
          seconds("LobbyAwaySeconds", matchRules.lobbyAwaySeconds) && seconds("ObserverDelaySeconds", matchRules.observerDelaySeconds) &&
          flag("FixedSpeed", matchRules.fixedSpeed) && flag("NoCheats", matchRules.noCheats))) {
      return false;
    }
    if (const LuaPlus::LuaObject version = table["GameVersion"]; !version.IsNil()) {
      // A number, or the text FAF's `GetVersion()` returns ("3839").
      const double number = version.IsNumber() ? version.GetNumber() : (version.IsString() ? std::atof(version.GetString()) : 0.0);
      if (number < 1.0 || number > 1000000.0 || number != static_cast<double>(static_cast<int>(number))) {
        error = "MatchRules.GameVersion is FAF's game version, a whole number such as 3839";
        return false;
      }
      matchRules.gameVersion = static_cast<int>(number);
    }
    if (const LuaPlus::LuaObject view = table["DefeatedPlayerView"]; !view.IsNil()) {
      const std::string text = view.IsString() ? view.GetString() : "";
      if (text != "observe" && text != "disconnect") {
        error = "MatchRules.DefeatedPlayerView is \"observe\" or \"disconnect\"";
        return false;
      }
      matchRules.defeatedPlayerView = text;
    }
    return true;
  }

  /** Plan WP13.1: the match file's `MatchObservers`, the tokens observers may watch with (a list, or uid = token). */
  [[nodiscard]] bool ReadMatchObservers(
    LuaPlus::LuaState* const state, std::vector<std::string>& tokens, std::string& error, const char* const name = "MatchObservers"
  )
  {
    LuaPlus::LuaObject table = state->GetGlobal(name);
    if (table.IsNil()) {
      return true;
    }
    if (!table.IsTable()) {
      error = std::string(name) + " is a table of tokens";
      return false;
    }
    for (LuaPlus::LuaTableIterator it(&table, 1); !it.m_isDone; it.Next()) {
      const LuaPlus::LuaObject value = it.GetValue();
      const std::size_t size = value.IsString() ? std::strlen(value.GetString()) : 0u;
      if (size == 0u || size > 1000u) {
        error = std::string(name) + " holds tokens: strings of 1 to 1000 characters";
        return false;
      }
      tokens.emplace_back(value.GetString());
    }
    return true;
  }

  /** Plan WP17.1: the match file's `MatchLobbyControl` ("organiser", "player"); "organiser" without one. */
  [[nodiscard]] bool ReadLobbyControl(LuaPlus::LuaState* const state, faf::server::ELobbyControl& control, std::string& error)
  {
    const LuaPlus::LuaObject text = state->GetGlobal("MatchLobbyControl");
    control = faf::server::ELobbyControl::Organiser;
    if (text.IsNil()) {
      return true;
    }
    const std::optional<faf::server::ELobbyControl> read = text.IsString() ? faf::server::ReadLobbyControl(text.GetString()) : std::nullopt;
    if (!read) {
      error = "MatchLobbyControl is \"organiser\" or \"player\"";
      return false;
    }
    control = *read;
    return true;
  }

  /** Plan WP17.1: a game option's value as the console shows it. */
  [[nodiscard]] std::string OptionText(const LuaPlus::LuaObject& value)
  {
    if (value.IsString()) {
      return value.GetString();
    }
    if (value.IsNumber()) {
      char text[32];
      std::snprintf(text, sizeof(text), "%g", value.GetNumber());
      return text;
    }
    if (value.IsBoolean()) {
      return value.GetBoolean() ? "true" : "false";
    }
    return value.IsNil() ? "nil" : "a table";
  }

  /** Plan WP17.1: the same option value: strings, numbers and booleans by value; a table is always taken as new. */
  [[nodiscard]] bool SameOption(const LuaPlus::LuaObject& a, const LuaPlus::LuaObject& b)
  {
    if (a.IsString() && b.IsString()) {
      return std::strcmp(a.GetString(), b.GetString()) == 0;
    }
    if (a.IsNumber() && b.IsNumber()) {
      return a.GetNumber() == b.GetNumber();
    }
    if (a.IsBoolean() && b.IsBoolean()) {
      return a.GetBoolean() == b.GetBoolean();
    }
    return a.IsNil() && b.IsNil();
  }

  struct STakenOption
  {
    std::string key;
    LuaPlus::LuaObject before; // nil when the match didn't set it
  };

  /**
   * Plan WP17.1: a player-hosted lobby's launch, already checked against the match (`CheckLaunch`: map, human seats, no
   * sim mods): the host's game options go over the match's `GameOptions`, but for those the server set up before the
   * lobby: `ScenarioFile` (the map), `GameSpeed` (the client manager's speed) and `TeamLock` (team views). Returns each
   * option changed, with its value before, so it can be put back.
   */
  [[nodiscard]] std::vector<STakenOption> TakeHostOptions(LuaPlus::LuaObject& config, LuaPlus::LuaObject& requested, const bool noCheats)
  {
    std::vector<STakenOption> taken;
    LuaPlus::LuaObject options = config["GameOptions"];
    LuaPlus::LuaObject hostOptions = requested["GameOptions"];
    if (!options.IsTable() || !hostOptions.IsTable()) {
      return taken;
    }
    for (LuaPlus::LuaTableIterator it(&hostOptions, 1); !it.m_isDone; it.Next()) {
      const LuaPlus::LuaObject key = it.GetKey();
      const LuaPlus::LuaObject value = it.GetValue();
      if (!key.IsString()) {
        continue;
      }
      const std::string name = key.GetString();
      if (name == "ScenarioFile" || name == "GameSpeed" || name == "TeamLock" || (noCheats && name == "CheatsEnabled")) {
        continue;
      }
      const LuaPlus::LuaObject before = options[name.c_str()];
      if (SameOption(before, value)) {
        continue;
      }
      taken.push_back(STakenOption{name, before});
      options.SetObject(name.c_str(), value);
    }
    return taken;
  }

  /** Plan WP17.2: a request's "Key=Value,Key=Value"; pairs without a key are skipped. */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>> OptionPairs(const std::string& text)
  {
    std::vector<std::pair<std::string, std::string>> pairs;
    for (std::size_t start = 0; start < text.size();) {
      const std::size_t comma = std::min(text.find(',', start), text.size());
      const std::string pair = text.substr(start, comma - start);
      if (const std::size_t equals = pair.find('='); equals != std::string::npos && equals > 0u) {
        pairs.emplace_back(pair.substr(0, equals), pair.substr(equals + 1));
      }
      start = comma + 1;
    }
    return pairs;
  }

  /** Plan WP17.2: the match's `PlayerOptions` entry of the human with this uid as `OwnerID`; nothing when there is none. */
  [[nodiscard]] std::optional<LuaPlus::LuaObject> MatchPlayerOf(const LuaPlus::LuaObject& config, const std::int64_t uid)
  {
    LuaPlus::LuaObject players = config["PlayerOptions"];
    if (players.IsTable()) {
      for (LuaPlus::LuaTableIterator it(&players, 1); !it.m_isDone; it.Next()) {
        LuaPlus::LuaObject player = it.GetValue();
        if (!player.IsTable()) {
          continue;
        }
        const LuaPlus::LuaObject human = player["Human"];
        const LuaPlus::LuaObject owner = player["OwnerID"];
        const std::int64_t id = owner.IsString() ? std::atoll(owner.GetString()) : (owner.IsNumber() ? static_cast<std::int64_t>(owner.GetNumber()) : -1);
        if (human.IsBoolean() && human.GetBoolean() && id == uid) {
          return player;
        }
      }
    }
    return std::nullopt;
  }

  void PutBackOptions(LuaPlus::LuaObject& config, const std::vector<STakenOption>& taken)
  {
    LuaPlus::LuaObject options = config["GameOptions"];
    for (const STakenOption& option : taken) {
      if (option.before.IsNil()) {
        options.SetNil(option.key.c_str());
      } else {
        options.SetObject(option.key.c_str(), option.before);
      }
    }
  }

  /** Plan WP17.1: why a rebuilt launch's seats aren't the ones the server's seats were made for; empty when they are. */
  [[nodiscard]] std::string SeatsDiffer(
    const moho::SLaunchBuild& before, const moho::CLaunchRoster& beforeRoster, const moho::SLaunchBuild& after, const moho::CLaunchRoster& afterRoster
  )
  {
    if (after.clientCount != before.clientCount || after.localClientIndex != before.localClientIndex || after.localSourceId != before.localSourceId) {
      return "the clients or the server's own source differ";
    }
    const std::vector<moho::SLaunchClient>& a = beforeRoster.Remotes();
    const std::vector<moho::SLaunchClient>& b = afterRoster.Remotes();
    if (a.size() != b.size()) {
      return "the players differ";
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
      if (a[i].uid != b[i].uid || a[i].clientIndex != b[i].clientIndex || a[i].commandSource != b[i].commandSource) {
        return std::string(a[i].name.c_str()) + "'s seat differs";
      }
    }
    return {};
  }

  /** What to call the game: the match file's `MatchName`, or the map's name without its `<LOC id>`. */
  [[nodiscard]] std::string ReadMatchTitle(const LuaPlus::LuaObject& config, LuaPlus::LuaState* const state)
  {
    const LuaPlus::LuaObject matchName = state->GetGlobal("MatchName");
    if (matchName.IsString()) {
      return matchName.GetString();
    }
    LuaPlus::LuaObject options = config["GameOptions"];
    const LuaPlus::LuaObject scenarioFile = options["ScenarioFile"];
    if (!scenarioFile.IsString()) {
      return "unnamed";
    }
    LuaPlus::LuaObject scenario = moho::WLD_LoadScenarioInfo(fa::string(scenarioFile.GetString()), state);
    if (scenario.IsNil()) {
      return scenarioFile.GetString();
    }
    const LuaPlus::LuaObject name = scenario["name"];
    if (!name.IsString()) {
      return scenarioFile.GetString();
    }
    std::string text = name.GetString();
    if (text.rfind("<LOC", 0) == 0) {
      const std::size_t close = text.find('>');
      if (close != std::string::npos) {
        text.erase(0, close + 1);
      }
    }
    return text;
  }

  [[nodiscard]] std::string JsonText(const std::string& text)
  {
    std::string escaped;
    for (const char c : text) {
      if (c == '"' || c == '\\') {
        escaped += '\\';
        escaped += c;
      } else if (static_cast<unsigned char>(c) >= 0x20) {
        escaped += c;
      }
    }
    return escaped;
  }

  struct SMatchEnd
  {
    std::string title;
    std::string map;
    bool ended = false;
    int beats = 0;
    int lastBeat = 0;
    double seconds = 0.0;
    std::string stoppedBy;
    std::string error;
    std::vector<SMatchPlayer> players;
  };

  void WriteResult(const std::string& path, const SMatchEnd& end)
  {
    std::ofstream file(path, std::ios::trunc);
    file << "{\"name\": \"" << JsonText(end.title) << "\", \"map\": \"" << JsonText(end.map) << "\", \"ended\": " << (end.ended ? "true" : "false")
         << ", \"beats\": " << end.beats << ", \"lastBeat\": " << end.lastBeat << ", \"seconds\": " << static_cast<int>(end.seconds)
         << ", \"stoppedBy\": \"" << JsonText(end.stoppedBy) << "\", \"error\": \"" << JsonText(end.error) << "\", \"players\": [";
    for (std::size_t index = 0; index < end.players.size(); ++index) {
      const SMatchPlayer& player = end.players[index];
      file << (index == 0 ? "" : ", ") << "{\"army\": " << index + 1 << ", \"name\": \"" << JsonText(player.name) << "\", \"team\": " << player.team
           << ", \"human\": " << (player.human ? "true" : "false") << ", \"result\": \"" << JsonText(player.result) << "\"}";
    }
    file << "]}\n";
  }

  /** `Sync.GameResult` (`SimSyncUtils.SyncGameResult`): a list of `{ army index, "victory 10" }`. */
  void ReadGameResults(LuaPlus::LuaObject& results, std::vector<SMatchPlayer>& players)
  {
    LuaPlus::LuaTableIterator it(&results, 1);
    while (!it.m_isDone) {
      LuaPlus::LuaObject entry = it.GetValue();
      const LuaPlus::LuaObject army = entry[1];
      const LuaPlus::LuaObject outcome = entry[2];
      if (army.IsNumber() && outcome.IsString()) {
        const int index = static_cast<int>(army.GetNumber()) - 1;
        if (index >= 0 && static_cast<std::size_t>(index) < players.size()) {
          SMatchPlayer& player = players[static_cast<std::size_t>(index)];
          player.result = outcome.GetString();
          Say("%s: %s", player.name.c_str(), player.result.substr(0, player.result.find(' ')).c_str());
        }
      }
      it.Next();
    }
  }

  [[nodiscard]] int Run(CLogWarningCounter& warnings, SMatchEnd& end)
  {
    std::string matchPath;
    std::string outDir;
    (void)ReadOption("--match", matchPath);
    (void)ReadOption("--out", outDir);
    std::string text;
    const bool speedGiven = ReadOption("--speed", text);
    const int speedOption = speedGiven ? std::atoi(text.c_str()) : 0;
    const int stopBeat = ReadOption("--stop-beat", text) ? std::atoi(text.c_str()) : 0;
    const double timeLimit = 60.0 * (ReadOption("--timeout", text) ? std::atof(text.c_str()) : 240.0);
    const double statusSeconds = 60.0 * (ReadOption("--status-minutes", text) ? std::atof(text.c_str()) : kDefaultStatusMinutes);
    const float warnBeatMs = ReadOption("--warn-beat-ms", text) ? static_cast<float>(std::atof(text.c_str())) : kDefaultWarnBeatMs;
    const std::string resultPath = outDir + "/result.json";
    const int viewThreads = ReadOption("--view-threads", text) ? std::atoi(text.c_str()) : 1;
    const bool perPlayerViews = moho::CFG_GetArgOption("--per-player-views", 0, nullptr);
    const float leadMs = ReadOption("--lead-ms", text) ? static_cast<float>(std::atof(text.c_str())) : kDefaultLeadMs;
    faf::server::SServerNetConfig netConfig;
    const bool listening = ReadOption("--listen", text);
    if (listening && !faf::remote::net::ParseEndpoint(text, netConfig.listen)) {
      end.error = "--listen takes <ip:port>, not " + text;
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    if (ReadOption("--join-seconds", text)) {
      netConfig.joinSeconds = std::atof(text.c_str());
    }
    const bool reconnectGiven = ReadOption("--reconnect-seconds", text);
    if (reconnectGiven) {
      netConfig.reconnectSeconds = std::atof(text.c_str());
    }
    netConfig.congestionControl = moho::CFG_GetArgOption("--congestion-control", 0, nullptr); // plan WP10.7, off by default
    const bool awayPauseGiven = ReadOption("--away-pause-seconds", text);
    double awayPauseSeconds = awayPauseGiven ? std::atof(text.c_str()) : 0.0;
    std::string defeatedView; // plan WP13.4
    const bool defeatedViewGiven = ReadOption("--defeated-view", defeatedView);
    // Plan WP2.2: a lobby before the game, the server signalling it. Until launch interception (WP2.14) it stays
    // open this long and then the game starts as the match file says.
    const double lobbySeconds = ReadOption("--lobby-seconds", text) ? std::atof(text.c_str()) : 0.0;

    LuaPlus::LuaState* const state = faf::headless::ReplayLuaState();
    LuaPlus::LuaObject config;
    std::int32_t seed = 1;
    if (!LoadMatch(state, matchPath, config, seed, end.error)) {
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    // Plan WP15.1: the tournament's rules from the match file; a command-line flag given still wins.
    SMatchRules matchRules;
    if (!ReadMatchRules(state, matchRules, end.error)) {
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    if (!reconnectGiven && matchRules.reconnectSeconds) {
      netConfig.reconnectSeconds = *matchRules.reconnectSeconds;
    }
    if (!awayPauseGiven && matchRules.awayPauseSeconds) {
      awayPauseSeconds = *matchRules.awayPauseSeconds;
    }
    if (!defeatedViewGiven) {
      defeatedView = matchRules.defeatedPlayerView.empty() ? "observe" : matchRules.defeatedPlayerView;
    } else if (defeatedView != "observe" && defeatedView != "disconnect") {
      end.error = "--defeated-view takes observe or disconnect, not " + defeatedView;
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    const bool disconnectDefeated = defeatedView == "disconnect";
    if (matchRules.noCheats) {
      LuaPlus::LuaObject options = config["GameOptions"];
      if (options.IsTable()) {
        options.SetString("CheatsEnabled", "false");
      }
    }
    {
      std::string said;
      const auto add = [&said](const std::string& part) { said += (said.empty() ? "" : ", ") + part; };
      if (matchRules.reconnectSeconds) {
        add("reconnect " + std::to_string(static_cast<int>(*matchRules.reconnectSeconds)) + " s" + (reconnectGiven ? " (the flag wins)" : ""));
      }
      if (matchRules.awayPauseSeconds) {
        add("away pause " + std::to_string(static_cast<int>(*matchRules.awayPauseSeconds)) + " s" + (awayPauseGiven ? " (the flag wins)" : ""));
      }
      if (matchRules.lobbyAwaySeconds) {
        add("host succession after " + std::to_string(static_cast<int>(*matchRules.lobbyAwaySeconds)) + " s");
      }
      if (matchRules.fixedSpeed) {
        add("fixed speed");
      }
      if (matchRules.noCheats) {
        add("no cheats");
      }
      if (!said.empty()) {
        Say("Match rules: %s", said.c_str());
      }
    }
    // A sim mod's Lua would run unchecked inside the server's sim; UI mods stay on the players' machines.
    if (const int simMods = CountSimMods(config); simMods > 0) {
      end.error = "the match names " + std::to_string(simMods) + " sim mods, and a dedicated server runs none";
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    std::vector<std::uint32_t> allowedAddresses;
    if (!ReadAddresses(state, allowedAddresses, end.error)) {
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    faf::remote::EContentCheck contentCheck = faf::remote::EContentCheck::Warn;
    if (!ReadContentCheck(state, contentCheck, end.error) || !ReadUiMods(state, netConfig.uiModsAllowed, end.error)) {
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    if (netConfig.uiModsAllowed) {
      Say("UI mods: %d allowed (MatchUiMods), judged under MatchContentCheck", static_cast<int>(netConfig.uiModsAllowed->size()));
    }
    if (ReadOption("--lobby-away-seconds", text)) {
      netConfig.lobbyAwaySeconds = std::atof(text.c_str());
    } else if (matchRules.lobbyAwaySeconds) {
      netConfig.lobbyAwaySeconds = *matchRules.lobbyAwaySeconds;
    }
    if (!ReadLobbyControl(state, netConfig.lobbyControl, end.error)) {
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }

    moho::CLaunchRoster roster(kServerUid, kServerName, {});
    // As a lockstep game's host launches it: each player may pause as often as the match's `Timeouts` says
    // (`Sim::Pause` spends them), and an observer never. The server's own source pauses for the operator, unlimited.
    moho::SLaunchBuild build = moho::BuildLaunchInfo(config, roster, seed, true, state);
    if (build.failure != nullptr) {
      Say("Can't host: the match can't launch: %s", build.failure);
      return kExitBadInput;
    }
    for (moho::SSTICommandSource& source : build.launchInfo->mCommandSources.mSrcs) {
      if (source.mIndex == build.localSourceId) {
        source.mTimeouts = -1;
      }
    }
    // Plan WP15.4 (#200): each player's pause budget stays with the server, by command source; the sim gets unlimited.
    std::map<std::uint32_t, int> pauseBudgets;
    const auto pauseBook = std::make_shared<faf::server::CPauseBook>(); // what the players are shown (step 5)
    std::map<std::uint32_t, int> pauseGranted; // what each source was given, for the book
    const auto takePauseBudgets = [&pauseBudgets, &pauseBook, &pauseGranted](moho::SLaunchBuild& launch) {
      pauseBudgets.clear();
      pauseGranted.clear();
      for (moho::SSTICommandSource& source : launch.launchInfo->mCommandSources.mSrcs) {
        if (source.mIndex != launch.localSourceId) {
          pauseBudgets[source.mIndex] = source.mTimeouts;
          pauseGranted[source.mIndex] = source.mTimeouts;
          pauseBook->SetGranted(source.mIndex, source.mTimeouts);
          source.mTimeouts = -1;
        }
      }
    };
    takePauseBudgets(build);
    end.title = ReadMatchTitle(config, state);
    end.map = build.mapName.c_str();
    end.players = ReadPlayers(config);

    LuaPlus::LuaObject gameOptions = config["GameOptions"];
    moho::SLaunchSpeed launchSpeed = moho::ReadLaunchSpeed(gameOptions);
    if (matchRules.fixedSpeed) {
      launchSpeed.adjustable = false; // plan WP15.1: the speed the match sets, whatever a player asks
    }
    if (speedGiven) {
      launchSpeed.speed = speedOption;
    }
    // Team views only where teams can't change: with `TeamLock` "locked" FAF's sim Lua refuses a player's
    // diplomacy (`SimUtils.BreakAlliance`, `OnAllianceResult`). A map's own script still can; then that army is cut.
    const LuaPlus::LuaObject teamLock = gameOptions["TeamLock"];
    const bool teamsLocked = teamLock.IsString() && std::strcmp(teamLock.GetString(), "locked") == 0;
    const bool teamViews = !perPlayerViews && (teamsLocked || moho::CFG_GetArgOption("--team-views", 0, nullptr));

    Say("Hosting game \"%s\" on %s, %d players, speed %+d%s", end.title.c_str(), end.map.c_str(), static_cast<int>(end.players.size()), launchSpeed.speed,
        launchSpeed.adjustable ? " (adjustable)" : "");
    for (const SMatchPlayer& player : end.players) {
      Say("  %s, team %d%s", player.name.c_str(), player.team, player.human ? "" : ", AI");
    }

    auto sessionInfo = std::make_unique<moho::SWldSessionInfo>();
    sessionInfo->mIsBeingRecorded = true;
    sessionInfo->mIsReplay = false;
    sessionInfo->mIsMultiplayer = false;
    sessionInfo->mSourceId = build.localSourceId;
    sessionInfo->mMapName = build.mapName;
    sessionInfo->mLaunchInfo = boost::static_pointer_cast<moho::LaunchInfoBase>(build.launchInfo);
    sessionInfo->mClientManager =
      moho::CLIENT_CreateClientManager(static_cast<std::size_t>(build.clientCount), nullptr, launchSpeed.speed, launchSpeed.adjustable);
    sessionInfo->mClientManager->CreateLocalClient(kServerName, build.localClientIndex, kServerUid, sessionInfo->mSourceId);
    // Not listening, nobody can sit in these: they count as loaded and stay silent, and the game goes on regardless.
    std::unique_ptr<faf::server::CServerNet> net;
    if (listening) {
      net = std::make_unique<faf::server::CServerNet>(netConfig);
    }
    // Plan WP17.2: the control API, for the control service only (research/WP17.2-control-api.md).
    std::unique_ptr<faf::server::CControlListener> control;
    struct SControlUnhook
    {
      ~SControlUnhook() { gControl = nullptr; } // before `control` goes: no `Say` reaches it after
    } controlUnhook;
    if (ReadOption("--control", text)) {
      faf::remote::net::SEndpoint controlAt;
      std::string keyPath;
      faf::server::ControlKey controlKey{};
      std::string controlError;
      if (!faf::remote::net::ParseEndpoint(text, controlAt)) {
        controlError = "--control takes <ip:port>, not " + text;
      } else if (!ReadOption("--control-key", keyPath)) {
        controlError = "--control needs --control-key <file>: 64 hex digits";
      } else {
        std::ifstream keyFile(keyPath);
        std::stringstream keyText;
        keyText << keyFile.rdbuf();
        if (!keyFile || !faf::server::ReadControlKey(keyText.str(), controlKey)) {
          controlError = "--control-key " + keyPath + " isn't 64 hex digits";
        }
      }
      if (controlError.empty()) {
        control = std::make_unique<faf::server::CControlListener>();
        if (!control->Open(controlAt, controlKey, controlError)) {
          control.reset();
        }
      }
      if (!control) {
        end.error = controlError;
        Say("Can't host: %s", end.error.c_str());
        return kExitBadInput;
      }
      gControl = control.get();
      Say("Control API on %s", controlAt.Text().c_str());
    }
    const auto controlSeats = [&net]() {
      std::string seats = "\"seats\":[";
      if (net) {
        bool first = true;
        for (const faf::server::CServerNet::SSeatState& seat : net->Seats()) {
          const auto flag = [](const bool on) { return on ? "true" : "false"; };
          seats += std::string(first ? "" : ",") + "{\"uid\":" + std::to_string(seat.uid) + ",\"name\":" + faf::server::JsonString(seat.name) +
                   ",\"joined\":" + flag(seat.joined) + ",\"loaded\":" + flag(seat.loaded) + ",\"lost\":" + flag(seat.lost) +
                   ",\"gone\":" + flag(seat.gone) + ",\"away\":" + flag(seat.away) + ",\"ping_ms\":" + std::to_string(seat.pingMs) +
                   ",\"ready\":" + faf::server::JsonString(seat.ready) + ",\"slot\":" + std::to_string(seat.lobbySlot) +
                   ",\"speed_limit\":" + (seat.speedLimit ? std::to_string(*seat.speedLimit) : std::string("null")) +
                   ",\"camera_updates\":" + std::to_string(seat.cameraUpdates) +
                   ",\"backlog_kb\":" + std::to_string(seat.backlogBytes / 1024u) + ",\"behind_beats\":" + std::to_string(seat.behindBeats) +
                   ",\"load\":" + faf::server::JsonString(seat.load) +
                   ",\"content\":" + faf::server::JsonString(seat.content) +
                   ",\"mods\":" + faf::server::JsonString(seat.mods) + ",\"ui_mods\":[";
          for (std::size_t i = 0; i < seat.uiMods.size(); ++i) {
            seats += (i == 0 ? "" : ",") + faf::server::JsonString(seat.uiMods[i]);
          }
          seats += "]}";
          first = false;
        }
      }
      return seats + "]";
    };
    // The requests that mean the same in the lobby and the game; false for one the caller answers.
    const auto controlCommon = [&net, &control](const faf::server::SControlRequest& request) {
      if (request.op == "allow" || request.op == "disallow") {
        faf::remote::net::SEndpoint address;
        if (!net) {
          control->Refuse(request.id, "this server has no players (--listen)");
        } else if (!faf::remote::net::ParseEndpoint(request.address + ":1", address)) {
          control->Refuse(request.id, request.op + " needs an IPv4 address, a.b.c.d");
        } else {
          net->RequestAddress(address.ip, request.op == "allow");
          Say("The control service %s %s", request.op == "allow" ? "allows" : "takes off the allowlist", request.address.c_str());
          control->Reply(request.id, {});
        }
        return true;
      }
      if (request.op != "eject") {
        return false;
      }
      if (!net) {
        control->Refuse(request.id, "this server has no players (--listen)");
      } else if (request.uid <= 0 || request.uid > INT32_MAX) {
        control->Refuse(request.id, "eject needs a participant's uid");
      } else if (!net->RequestEject(
                   static_cast<std::int32_t>(request.uid), "ejected by the organiser" + (request.reason.empty() ? std::string() : ": " + request.reason)
                 )) {
        control->Refuse(request.id, "no participant with uid " + std::to_string(request.uid));
      } else {
        control->Reply(request.id, {});
      }
      return true;
    };
    // Plan WP17.2: what happened, as data, beside the console's lines.
    const auto controlEvent = [&control](const std::string_view name, const std::string& fields) {
      if (control) {
        control->Event(name, fields);
      }
    };
    std::set<std::int32_t> controlLeftSaid; // a seat's `left` once, from the lobby or the game
    const auto controlLeft = [&controlEvent, &controlLeftSaid](const std::int32_t uid) {
      if (controlLeftSaid.insert(uid).second) {
        controlEvent("left", "\"uid\":" + std::to_string(uid));
      }
    };
    const auto controlNews = [&control] {
      for (const std::string& line : control->TakeNews()) {
        Say("%s", line.c_str());
      }
    };
    const std::map<std::int32_t, std::string> tokens = ReadTokens(state);
    std::map<std::uint32_t, faf::remote::CServerClient*> pauseSeats; // plan WP15.4: by command source
    std::map<std::int32_t, std::uint32_t> pauseSources;              // and each uid's source
    for (const moho::SLaunchClient& client : roster.Remotes()) {
      faf::remote::CServerClient& seat = faf::remote::CServerClient::Create(
        *static_cast<moho::CClientManagerImpl*>(sessionInfo->mClientManager), client.name.c_str(), client.clientIndex, client.uid, client.commandSource
      );
      pauseSeats[client.commandSource] = &seat;
      pauseSources[client.uid] = client.commandSource;
      if (const auto budget = pauseBudgets.find(client.commandSource); budget != pauseBudgets.end() && budget->second == 0) {
        seat.SetPauseAllowed(false);
      }
      if (!net) {
        seat.MarkLoaded();
        continue;
      }
      const auto token = tokens.find(client.uid);
      if (token == tokens.end() || token->second.empty()) {
        end.error = std::string("MatchTokens has no token for ") + client.name.c_str();
        Say("Can't host: %s", end.error.c_str());
        return kExitBadInput;
      }
      net->AddSeat(client.uid, client.name.c_str(), token->second, seat);
    }
    if (net) {
      for (const std::uint32_t ip : allowedAddresses) {
        net->AllowAddress(ip);
      }
      if (!allowedAddresses.empty()) {
        Say("%d addresses from MatchAddresses get a full handshake budget; others share a small one, and a valid token lists them",
            static_cast<int>(allowedAddresses.size()));
      }
      faf::server::SPinnedOptions lobbyPins; // plan WP17.2: the organised lobby's pins, which set_options adds to
      if (lobbySeconds <= 0.0) {
        net->CloseLobby(); // the game starts at once: nothing to relay (plan WPR.51)
      } else if (netConfig.lobbyControl == faf::server::ELobbyControl::Player) {
        // Plan WP17.1: a player hosts with a host's powers: nothing pinned, and the host's ejects go through.
        Say("Lobby: hosted by a player (MatchLobbyControl \"player\"): the host may change game options and eject");
      } else {
        faf::server::SPinnedOptions pinned = ReadPinnedOptions(state, config);
        std::string keys;
        for (const auto& [key, bytes] : pinned) {
          keys += (keys.empty() ? "" : ", ") + key;
        }
        Say("Lobby: %d game options pinned%s%s", static_cast<int>(pinned.size()), keys.empty() ? "" : ": ", keys.c_str());
        lobbyPins = pinned;
        net->PinLobbyOptions(std::move(pinned));
      }
      std::string netError;
      if (!net->Start(netError)) {
        end.error = netError;
        Say("Can't host: %s", end.error.c_str());
        return kExitBadInput;
      }
      Say("Listening on %s, %d seats, %.0f s to join", net->Local().Text().c_str(), static_cast<int>(roster.Remotes().size()), netConfig.joinSeconds);
      if (lobbySeconds > 0.0) {
        // Plan WP2.2, WP2.12: the server signals each participant's game as FAF's lobby server does over GPGNet; the
        // match's first participant hosts the lobby in its own FAF lobby; their lobbies talk through the relay.
        // The host's lobby starts on the match's scenario (`HostGame`'s scenario file, not the map file).
        const LuaPlus::LuaObject scenarioFile = gameOptions["ScenarioFile"];
        faf::server::CLobbySignaller signaller(
          scenarioFile.IsString() ? scenarioFile.GetString() : "",
          netConfig.lobbyControl == faf::server::ELobbyControl::Organiser ? faf::remote::net::kLobbySignalOrganised : std::uint8_t{0}
        );
        for (const moho::SLaunchClient& client : roster.Remotes()) {
          signaller.AddParticipant(client.uid, client.name.c_str());
        }
        Say("Lobby open for %.0f s, hosted by uid %d", lobbySeconds, static_cast<int>(signaller.Host()));
        net->SetLobbyHost(signaller.Host()); // plan WP17.1: whose ejects go through in a player-hosted lobby
        const Clock::time_point lobbyEnd = Clock::now() + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(lobbySeconds));
        std::vector<faf::server::CLobbySignaller::SOutgoing> out;
        std::size_t lastIn = 0;
        std::uint64_t toServer = 0;
        bool hostLeftSaid = false;
        bool launched = false;
        std::int32_t lastHost = signaller.Host();
        const int forceStartsBefore = gForceStartRequests;
        // Plan WP2.14: what the host's launch is checked against. The match file's configuration stays the one the
        // game starts with (plan WPR.55: the clients' launch comes from the server, never from the lobby's message).
        const faf::server::SLaunchFacts matchFacts = ReadLaunchFacts(config);
        const auto signal = [&net](const std::int32_t to, const faf::remote::net::ELobbySignal kind, std::string text) {
          faf::remote::net::SLobbySignal message;
          message.kind = kind;
          message.text = std::move(text);
          net->QueueLobbyFromServer(to, faf::remote::net::EncodeLobbySignal(message));
        };
        // Plan WP17.1, WP17.2: the launch built again once config's GameOptions changed (the host's or the organiser's),
        // on the seats the server made, so the server's sim starts from what the players' LaunchInfo says. Empty, or why
        // not (then `taken` is put back).
        const auto relaunch = [&](const std::vector<STakenOption>& taken) -> std::string {
          moho::CLaunchRoster rebuiltRoster(kServerUid, kServerName, {});
          moho::SLaunchBuild rebuilt = moho::BuildLaunchInfo(config, rebuiltRoster, seed, true, state);
          std::string why = rebuilt.failure != nullptr ? std::string("they don't launch: ") + rebuilt.failure : SeatsDiffer(build, roster, rebuilt, rebuiltRoster);
          if (!why.empty()) {
            PutBackOptions(config, taken);
            return why;
          }
          for (moho::SSTICommandSource& source : rebuilt.launchInfo->mCommandSources.mSrcs) {
            if (source.mIndex == rebuilt.localSourceId) {
              source.mTimeouts = -1; // as for the match's own launch above
            }
          }
          build = std::move(rebuilt);
          takePauseBudgets(build); // the options may set another `Timeouts`
          sessionInfo->mLaunchInfo = boost::static_pointer_cast<moho::LaunchInfoBase>(build.launchInfo);
          for (const auto& [source, seat] : pauseSeats) {
            const auto budget = pauseBudgets.find(source);
            seat->SetPauseAllowed(budget == pauseBudgets.end() || budget->second != 0);
          }
          return {};
        };
        while (!launched && Clock::now() < lobbyEnd && gStopSignal == 0) {
          for (const faf::server::CServerNet::SLobbyMessage& message : net->TakeLobbyMessages()) {
            ++toServer;
            std::span<const std::uint8_t> bytes;
            if (!faf::remote::net::IsLaunchRequest(message.message, bytes)) {
              continue;
            }
            if (message.from != signaller.Host() || launched) {
              Say("Lobby: a launch from uid %d, who isn't the host, ignored", static_cast<int>(message.from));
              continue;
            }
            LuaPlus::LuaObject requested;
            std::string refusal;
            if (!DecodeLaunchConfig(state, bytes, config, requested)) {
              refusal = "the launch couldn't be read";
            } else {
              refusal = faf::server::CheckLaunch(ReadLaunchFacts(requested), matchFacts);
            }
            // Plan WP17.1: a player-hosted lobby starts with its host's game options, on the seats the server made.
            if (refusal.empty() && netConfig.lobbyControl == faf::server::ELobbyControl::Player) {
              const std::vector<STakenOption> taken = TakeHostOptions(config, requested, matchRules.noCheats);
              if (!taken.empty()) {
                refusal = relaunch(taken);
                if (!refusal.empty()) {
                  refusal = "the host's game options change the match's seats: " + refusal;
                } else {
                  std::string changed;
                  LuaPlus::LuaObject options = config["GameOptions"];
                  for (const STakenOption& option : taken) {
                    changed += (changed.empty() ? "" : ", ") + option.key + "=" + OptionText(options[option.key.c_str()]);
                  }
                  Say("Lobby: the host's game options: %s", changed.c_str());
                }
              }
            }
            if (!refusal.empty()) {
              Say("Lobby: launch refused: %s", refusal.c_str());
              signal(message.from, faf::remote::net::ELobbySignal::LaunchRefused, refusal);
              continue;
            }
            Say("Lobby: the host launched; starting the match");
            controlEvent("launched", "\"by\":\"host\"");
            for (const std::int32_t uid : signaller.InLobbyUids()) {
              signal(uid, faf::remote::net::ELobbySignal::Launching, {});
            }
            launched = true;
          }
          // Plan WPR.49: the operator's force start (SIGUSR2): the match file's launch, as always, with no lobby message;
          // each client starts from the server's LaunchInfo whatever its lobby is doing.
          if (!launched && gForceStartRequests != forceStartsBefore) {
            Say("Lobby: the operator forces the start; the match starts as the match file says");
            controlEvent("launched", "\"by\":\"operator\"");
            launched = true;
          }
          for (const std::int32_t uid : net->TakeLobbyJoined()) {
            signaller.OnJoined(uid, out);
            controlEvent("joined", "\"uid\":" + std::to_string(uid));
          }
          for (const std::int32_t uid : net->TakeLobbyLeft()) {
            signaller.OnLeft(uid, out);
            controlLeft(uid);
          }
          // Plan WPR.50: a logical host gone quiet is succeeded; whoever is heard again gets the role it missed.
          for (const faf::server::CServerNet::SPresence& change : net->TakeLobbyPresence()) {
            controlEvent(change.away ? "away" : "back", "\"uid\":" + std::to_string(change.uid));
            if (change.away) {
              signaller.OnAway(change.uid, out);
            } else {
              signaller.OnBack(change.uid, out);
            }
          }
          for (const faf::server::CLobbySignaller::SOutgoing& message : out) {
            net->QueueLobbyFromServer(message.to, message.message);
          }
          out.clear();
          if (const std::int32_t host = signaller.Host(); host != lastHost && host != 0) {
            Say("Lobby: uid %d hosts now, in place of uid %d (succession %u)", static_cast<int>(host), static_cast<int>(lastHost), signaller.Successions());
            lastHost = host;
            net->SetLobbyHost(host);
            controlEvent("host", "\"uid\":" + std::to_string(host));
          }
          if (const std::size_t in = signaller.InLobby(); in != lastIn) {
            lastIn = in;
            Say("Lobby: %d of %d participants in", static_cast<int>(in), static_cast<int>(roster.Remotes().size()));
          }
          if (signaller.HostLeft() && !std::exchange(hostLeftSaid, true)) {
            Say("Lobby: the host left and nobody is left to take over; the lobby can't go on");
          }
          for (const std::string& line : net->TakeNews()) {
            Say("%s", line.c_str());
          }
          // Plan WP17.2: the control service's requests in the lobby.
          if (control) {
            std::vector<faf::server::SControlRequest> requests;
            control->Poll(requests, ControlNowUs());
            for (const faf::server::SControlRequest& request : requests) {
              if (request.op == "status") {
                control->Reply(request.id, "\"phase\":\"lobby\",\"host\":" + std::to_string(signaller.Host()) + "," + controlSeats());
              } else if (request.op == "set_options") {
                // Plan WP17.2: an organised lobby's options from the organiser: the launch, the pins, and the players' screens.
                const std::vector<std::pair<std::string, std::string>> pairs = OptionPairs(request.options);
                const auto fixed = std::find_if(pairs.begin(), pairs.end(), [&matchRules](const auto& pair) {
                  return pair.first == "ScenarioFile" || pair.first == "GameSpeed" || pair.first == "TeamLock" ||
                         (matchRules.noCheats && pair.first == "CheatsEnabled");
                });
                if (netConfig.lobbyControl == faf::server::ELobbyControl::Player) {
                  control->Refuse(request.id, "a player-hosted lobby's options are its host's");
                } else if (pairs.empty()) {
                  control->Refuse(request.id, "set_options needs options: Key=Value,Key=Value");
                } else if (fixed != pairs.end()) {
                  control->Refuse(request.id, fixed->first == "CheatsEnabled" ? std::string("the match's rules keep cheats off (MatchRules.NoCheats)")
                                                                               : fixed->first + " is set before the lobby opens; the match file has it");
                } else {
                  LuaPlus::LuaObject options = config["GameOptions"];
                  std::vector<STakenOption> taken;
                  for (const auto& [key, value] : pairs) {
                    taken.push_back(STakenOption{key, options[key.c_str()]});
                    options.SetString(key.c_str(), value.c_str());
                  }
                  if (const std::string why = relaunch(taken); !why.empty()) {
                    control->Refuse(request.id, "those options change the match's seats: " + why);
                  } else {
                    LuaPlus::LuaObject table;
                    table.AssignNewTable(state, 0, static_cast<unsigned>(pairs.size()));
                    for (const auto& [key, value] : pairs) {
                      lobbyPins[key] = LuaValueBytes(options[key.c_str()]);
                      table.SetString(key.c_str(), value.c_str());
                    }
                    net->RequestPins(lobbyPins);
                    // The other participants' lobby screens, in the host's name (lobby.lua takes GameOptions from the host
                    // alone). The host isn't sent one: a frame in its own uid would look like a new peer to it.
                    LuaPlus::LuaObject data;
                    data.AssignNewTable(state, 0, 2u);
                    data.SetString("Type", "GameOptions");
                    data.SetObject("Options", table);
                    moho::CMessage script(moho::ELobbyMsg::LOBMSG_BroadcastScriptData);
                    bool encoded = false;
                    {
                      moho::CMessageStream stream(script, moho::CMessageStream::Access::kReadWrite);
                      encoded = data.ToByteStream(stream);
                    }
                    std::size_t told = 0;
                    if (encoded) {
                      const auto* const bytes = reinterpret_cast<const std::uint8_t*>(script.mBuff.start_);
                      const std::vector<std::uint8_t> message(bytes, bytes + script.mBuff.Size());
                      for (const std::int32_t uid : signaller.InLobbyUids()) {
                        if (uid != signaller.Host()) {
                          net->QueueLobbyAs(uid, signaller.Host(), message);
                          ++told;
                        }
                      }
                    }
                    Say("The control service sets the game options: %s", request.options.c_str());
                    control->Reply(request.id, "\"options\":" + std::to_string(pairs.size()) + ",\"told\":" + std::to_string(told));
                    controlEvent("options", "\"options\":" + faf::server::JsonString(request.options));
                  }
                }
              } else if (request.op == "set_player") {
                // Plan WP17.2: a participant's team, faction and colours from the organiser: the match's launch, then
                // the lobby screens' slot (in the host's name, as `set_options`).
                const std::vector<std::pair<std::string, std::string>> pairs = OptionPairs(request.options);
                std::optional<LuaPlus::LuaObject> player = MatchPlayerOf(config, request.uid);
                std::vector<std::pair<std::string, int>> values;
                std::string bad;
                for (const auto& [key, text] : pairs) {
                  int value = 0;
                  const auto [last, error] = std::from_chars(text.data(), text.data() + text.size(), value);
                  if (key != "Team" && key != "Faction" && key != "PlayerColor" && key != "ArmyColor") {
                    bad = key + " isn't the organiser's to set here (Team, Faction, PlayerColor, ArmyColor)";
                  } else if (error != std::errc{} || last != text.data() + text.size() || value < 1 || value > 64) {
                    bad = key + " takes a whole number from 1 to 64";
                  } else {
                    values.emplace_back(key, value);
                    continue;
                  }
                  break;
                }
                if (netConfig.lobbyControl == faf::server::ELobbyControl::Player) {
                  control->Refuse(request.id, "a player-hosted lobby's slots are its host's");
                } else if (!player) {
                  control->Refuse(request.id, "no player of the match has uid " + std::to_string(request.uid));
                } else if (!bad.empty()) {
                  control->Refuse(request.id, bad);
                } else if (values.empty()) {
                  control->Refuse(request.id, "set_player needs a uid and options: Team=2,Faction=1");
                } else {
                  std::vector<std::pair<std::string, LuaPlus::LuaObject>> before;
                  for (const auto& [key, value] : values) {
                    before.emplace_back(key, (*player)[key.c_str()]);
                    player->SetInteger(key.c_str(), value);
                  }
                  if (const std::string why = relaunch({}); !why.empty()) {
                    for (const auto& [key, value] : before) {
                      if (value.IsNil()) {
                        player->SetNil(key.c_str());
                      } else {
                        player->SetObject(key.c_str(), value);
                      }
                    }
                    control->Refuse(request.id, "that changes the match's seats: " + why);
                  } else {
                    int slot = 0;
                    for (const faf::server::CServerNet::SSeatState& seat : net->Seats()) {
                      if (seat.uid == request.uid) {
                        slot = seat.lobbySlot;
                      }
                    }
                    std::size_t told = 0;
                    if (slot > 0) {
                      LuaPlus::LuaObject table;
                      table.AssignNewTable(state, 0, static_cast<unsigned>(values.size()));
                      for (const auto& [key, value] : values) {
                        table.SetInteger(key.c_str(), value);
                      }
                      LuaPlus::LuaObject data;
                      data.AssignNewTable(state, 0, 3u);
                      data.SetString("Type", "PlayerOptions");
                      data.SetInteger("Slot", slot);
                      data.SetObject("Options", table);
                      moho::CMessage script(moho::ELobbyMsg::LOBMSG_BroadcastScriptData);
                      bool encoded = false;
                      {
                        moho::CMessageStream stream(script, moho::CMessageStream::Access::kReadWrite);
                        encoded = data.ToByteStream(stream);
                      }
                      if (encoded) {
                        const auto* const bytes = reinterpret_cast<const std::uint8_t*>(script.mBuff.start_);
                        const std::vector<std::uint8_t> message(bytes, bytes + script.mBuff.Size());
                        for (const std::int32_t uid : signaller.InLobbyUids()) {
                          if (uid != signaller.Host()) {
                            net->QueueLobbyAs(uid, signaller.Host(), message);
                            ++told;
                          }
                        }
                      }
                    }
                    Say("The control service sets uid %d's %s (lobby slot %d)", static_cast<int>(request.uid), request.options.c_str(), slot);
                    control->Reply(request.id, "\"options\":" + std::to_string(values.size()) + ",\"slot\":" + std::to_string(slot) + ",\"told\":" + std::to_string(told));
                    controlEvent(
                      "player", "\"uid\":" + std::to_string(request.uid) + ",\"options\":" + faf::server::JsonString(request.options) + ",\"slot\":" + std::to_string(slot)
                    );
                  }
                }
              } else if (request.op == "force_start") {
                Say("The control service forces the start");
                gForceStartRequests = gForceStartRequests + 1;
                control->Reply(request.id, {});
              } else if (!controlCommon(request)) {
                control->Refuse(request.id, request.op == "pause" || request.op == "resume" || request.op == "end" || request.op == "substitute" ||
                                                  request.op == "extend_timeouts"
                                              ? "the game hasn't started"
                                              : "unknown op " + request.op);
              }
            }
            controlNews();
          }
          if (control) {
            // Plan WP17.2: who readied up or stood down in the lobby.
            for (const auto& [uid, ready] : net->TakeReadyChanges()) {
              controlEvent("ready", "\"uid\":" + std::to_string(uid) + ",\"ready\":" + (ready ? "true" : "false"));
            }
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        net->CloseLobby();
        Say("Lobby closed: %d of %d participants in, %llu messages to the server", static_cast<int>(lastIn), static_cast<int>(roster.Remotes().size()),
            static_cast<unsigned long long>(toServer));
      }
    } else if (!roster.Remotes().empty()) {
      Say("%d seats stay empty: this server isn't listening (--listen)", static_cast<int>(roster.Remotes().size()));
    }
    std::unique_ptr<faf::server::CObserverListener> observers; // plan WP13.1, with the replay below
    std::unique_ptr<faf::server::CLiveReplaySender> liveReplay; // plan WP15.3, likewise
    const auto sayNetNews = [&net, &observers, &liveReplay] {
      if (net) {
        for (const std::string& line : net->TakeNews()) {
          Say("%s", line.c_str());
        }
      }
      if (observers) {
        for (const std::string& line : observers->TakeNews()) {
          Say("%s", line.c_str());
        }
      }
      if (liveReplay) {
        for (const std::string& line : liveReplay->TakeNews()) {
          Say("%s", line.c_str());
        }
      }
    };

    Say("Loading the map");
    const Clock::time_point loadStart = Clock::now();
    moho::SWldGameData gameData{};
    if (!faf::headless::LoadSessionScenario(*sessionInfo, gameData, end.error)) {
      Say("Can't host: %s", end.error.c_str());
      WriteResult(resultPath, end);
      return kExitBadInput;
    }
    // `WLD_DoLoading`: the game version (and with it the engine patches) is fixed before the replay
    // names it and before the driver creates the sim.
    moho::FAF_BeginSession(false);
    // Plan WP15.1: a match for one FAF release is played on that release's game data, or not at all. The players' data is
    // the content check's (WP2.6).
    if (matchRules.gameVersion && *matchRules.gameVersion != moho::FAF_GetSessionGameVersion()) {
      end.error = "the match is for FAF game version " + std::to_string(*matchRules.gameVersion) + ", and this server's game data is version " +
                  std::to_string(moho::FAF_GetSessionGameVersion());
      Say("Can't host: %s", end.error.c_str());
      WriteResult(resultPath, end);
      return kExitBadInput;
    }

    std::unique_ptr<LuaPlus::LuaState> sessionState(gameData.mState);
    std::unique_ptr<moho::RRuleGameRules> rules(gameData.mGameRules);
    std::unique_ptr<moho::CWldMap> wldMap(gameData.mWldMap);
    gameData = moho::SWldGameData{};
    moho::STIMap* const launchMap = faf::headless::CompleteSessionLaunchInfo(*sessionInfo, *rules, *wldMap, *sessionState);
    const Wm3::AxisAlignedBox3f mapBounds = launchMap->GetBounds3D();
    const float mapSizeX = mapBounds.Max.x - mapBounds.Min.x;
    const float mapSizeZ = mapBounds.Max.z - mapBounds.Min.z;

    // Each player's view, before the driver: the sync walk's observer sees the sim from its first beat.
    const faf::remote::wire::SContentTables contentTables = faf::remote::BuildContentTables(*rules);
    std::unique_ptr<faf::server::CServerViews> views;
    std::map<std::size_t, std::int32_t> armyUids;                  // each player's army
    std::set<std::size_t> defeatedArmies;                          // plan WP13.7: defeats seen
    std::set<std::size_t> focusFreed;                              // plan WP11.1: defeated players free to focus
    std::vector<std::pair<double, std::int32_t>> defeatedLeaving;  // and when each such player goes
    if (net) {
      // Plan WP2.6, WP1.4: what each player's report is compared with: the server's own rules, before any player has
      // the launch to load them from.
      faf::remote::SContentReport content;
      content.blueprints = contentTables.Hash();
      const fa::string& gameMods = sessionInfo->mLaunchInfo->mGameMods; // the Lua byte form: NULs inside
      content.mods = faf::remote::HashModUids(faf::remote::ReadModUids(std::string(gameMods.c_str(), gameMods.size())));
      net->SetContentCheck(contentCheck, content);
      static constexpr const char* kModes[] = {"not compared", "warned of", "refused"};
      Say("Content: blueprints %016llx, mods %016llx; a player whose content differs is %s", static_cast<unsigned long long>(content.blueprints),
          static_cast<unsigned long long>(content.mods), kModes[static_cast<int>(contentCheck)]);
    }
    if (net && !roster.Remotes().empty()) {
      // Plan WPR.55: every client's launch comes from here; a game too large for one message is refused at start.
      const std::vector<std::uint8_t> launchInfo = MakeLaunchInfo(config);
      if (launchInfo.empty()) {
        end.error = "the match's configuration doesn't fit one launch message";
        Say("Can't host: %s", end.error.c_str());
        WriteResult(resultPath, end);
        return kExitBadInput;
      }
      std::map<std::size_t, std::int32_t> viewPlayers;
      const auto& armies = sessionInfo->mLaunchInfo->mArmyLaunchInfo;
      for (const moho::SLaunchClient& client : roster.Remotes()) {
        std::int32_t playerArmy = -1;
        for (std::size_t army = 0; army < armies.size(); ++army) {
          if (armies[army].mUnitSources.Contains(client.commandSource)) {
            viewPlayers[army] = client.uid;
            playerArmy = static_cast<std::int32_t>(army);
            break;
          }
        }
        net->QueueView(client.uid, launchInfo);
        net->QueueView(client.uid, faf::server::MakeGameInfo(mapSizeX, mapSizeZ, playerArmy, client.commandSource));
        net->SetFocusRule(client.uid, playerArmy); // plan WP11.1: their SetFocusArmy keeps them on it
      }
      armyUids = viewPlayers;
      views = std::make_unique<faf::server::CServerViews>(contentTables, *rules, mapSizeX, mapSizeZ, *net, std::move(viewPlayers), static_cast<unsigned int>(std::max(viewThreads, 1)), teamViews);
      if (teamViews && !disconnectDefeated) {
        views->EnableObserverViews(); // plan WP13.6
      }
      if (std::string statsEvery; ReadOption("--stats-every", statsEvery)) {
        views->SetStatsEveryBeats(static_cast<std::uint32_t>(std::max(1, std::atoi(statsEvery.c_str()))));
      }
      views->SetPauseBook(pauseBook);
      views->Install();
      Say("Views: %s", teamViews ? (teamsLocked ? "one per team, and each player's own units" : "one per team (--team-views), with teams unlocked")
                       : perPlayerViews ? "one per player (--per-player-views)" : "one per player, as teams aren't locked (TeamLock)");
    }
    sessionInfo->mLaunchInfo->mCommandSources.mOriginalSource = -1;

    const std::string replayPath = outDir + "/game.scfareplay";
    std::unique_ptr<gpg::Stream> replay = moho::VCR_OpenGPGNetURI(replayPath.c_str(), moho::EGpgNetOpenMode::Write);
    if (replay == nullptr) {
      end.error = "cannot write " + replayPath;
      Say("Can't host: %s", end.error.c_str());
      return kExitBadInput;
    }
    // Plan WP13.1, WP15.3: with observers or a live replay, the replay goes through a tee into a log they're both served
    // from, header included, each byte `ObserverDelaySeconds` late.
    std::string observeText;
    std::string liveText;
    const bool observeGiven = ReadOption("--observe", observeText);
    const bool liveGiven = ReadOption("--live-replay", liveText);
    std::shared_ptr<faf::server::CReplayLog> replayLog;
    if (observeGiven || liveGiven) {
      replayLog = std::make_shared<faf::server::CReplayLog>();
      replay = std::make_unique<faf::server::CReplayTee>(std::move(replay), replayLog, &ControlNowUs);
    }
    if (liveGiven) {
      if (const std::optional<faf::server::SGpgNetAddress> to = faf::server::ParseGpgNetAddress(liveText); !to) {
        end.error = "--live-replay takes gpgnet://host[:port]/path, not " + liveText;
        Say("Can't host: %s", end.error.c_str());
        return kExitBadInput;
      } else {
        liveReplay = std::make_unique<faf::server::CLiveReplaySender>(replayLog, &ControlNowUs, matchRules.observerDelaySeconds.value_or(0.0), *to);
        liveReplay->Start();
        Say("Live replay to %s:%d%s, %.0f s behind the game", to->host.c_str(), static_cast<int>(to->port), to->path.c_str(),
            matchRules.observerDelaySeconds.value_or(0.0));
      }
    }
    if (observeGiven) {
      text = observeText;
      faf::remote::net::SEndpoint observeAt;
      std::vector<std::string> tokens;
      std::vector<std::string> referees; // plan WP13.2
      if (!faf::remote::net::ParseEndpoint(text, observeAt)) {
        end.error = "--observe takes <ip:port>, not " + text;
      } else if (!ReadMatchObservers(state, tokens, end.error) || !ReadMatchObservers(state, referees, end.error, "MatchReferees")) {
        // `end.error` says why
      } else {
        observers = std::make_unique<faf::server::CObserverListener>(replayLog, &ControlNowUs, matchRules.observerDelaySeconds.value_or(0.0));
        if (control) {
          observers->HoldUnknownTokens(); // plan WP17.9: the organiser approves on the web
        }
        for (std::string& token : tokens) {
          observers->AllowToken(std::move(token));
        }
        for (const std::string& token : referees) {
          observers->AllowReferee(token);
        }
        if (observers->Start(observeAt, end.error)) {
          Say("Observers on %s: %d tokens, %.0f s behind the game; %d referees, no delay", observeAt.Text().c_str(), static_cast<int>(tokens.size()),
              matchRules.observerDelaySeconds.value_or(0.0), static_cast<int>(referees.size()));
        }
      }
      if (!end.error.empty()) {
        Say("Can't host: %s", end.error.c_str());
        return kExitBadInput;
      }
    }
    moho::VCR_WriteReplayHeader(*replay, *sessionInfo);

    // The issue thread only keeps `net_Lag` of beats ready past the last one taken, so what sets the
    // game's pace is when beats are taken: a client's frames, or this program's loop below.
    moho::sim_LocalLead = 0;
    moho::net_Lag = leadMs;
    moho::SIM_SetSessionPacing(moho::ESimSessionPacing::Local);
    moho::SIM_SetIssueWhilePaused(true);
    moho::IClientManager* const clientManager = sessionInfo->mClientManager;
    sessionInfo->mClientManager = nullptr;
    std::unique_ptr<moho::ISTIDriver> driver(moho::SIM_CreateDriver(
      static_cast<moho::CClientManagerImpl*>(clientManager), replay.release(), sessionInfo->mLaunchInfo, sessionInfo->mSourceId
    ));
    auto* const simDriver = static_cast<moho::CSimDriver*>(driver.get());
    // Ahead of the driver going away, on every way out: the network's thread touches its seats.
    struct SStopNet
    {
      faf::server::CServerNet* net;
      ~SStopNet()
      {
        if (net != nullptr) {
          net->Stop();
        }
      }
    } const stopNet{net.get()};
    Say("Map loaded in %.1f s", SecondsSince(loadStart));

    const Clock::time_point playStart = Clock::now();
    const HANDLE syncAvailable = driver->GetSyncDataAvailableEvent();
    faf::server::CSpeedWatch speedWatch(warnBeatMs);
    bool started = false;
    bool ready = false;
    bool stopped = false;
    bool stalled = false;
    int statusBeats = 0;
    std::uint64_t statusNetBytes = 0;
    double nextBeatAt = 0.0;
    std::array<std::pair<double, int>, 10> beatHistory{};
    std::size_t beatSamples = 0;
    double lastSample = 0.0;
    double lastStatus = 0.0;
    double lastBeatAt = 0.0;
    // Beats go on while the game is paused, and no game time with them.
    int pausedBeats = 0;
    std::int32_t pausedBy = -1;
    // The operator's (SIGUSR1, control API) pause or resume asked of the driver, until the game is so: a beat or more.
    std::optional<bool> operatorPauseWanted;
    int pauseRequestsDone = 0;
    // `--away-pause-seconds`: the game waits for a player who lost the connection, from a budget each has for the game.
    const auto serverSource = static_cast<std::int32_t>(sessionInfo->mSourceId);
    std::map<std::int32_t, double> awayBudget; // by uid: seconds of pause left
    std::map<std::int32_t, bool> away;         // by uid, while away
    std::map<std::int32_t, std::string> seatNames;
    for (const moho::SLaunchClient& client : roster.Remotes()) {
      seatNames[client.uid] = client.name.c_str();
    }
    bool awayPending = false; // someone went away and the game hasn't waited for them yet
    bool awayPausing = false; // the game is paused (or about to be) for whoever is away
    bool awayPauseSeen = false;
    double awayCharged = 0.0;

    // Plan WP10.7: the speed the game runs at: the one requested, held to the slowest playing seat's sim-speed limit, as
    // lockstep's `CClientManagerImpl::GetSimRate` holds it to the slowest client's.
    std::int32_t speedHolder = 0;
    faf::server::CLinkSpeedGovernor linkSpeeds; // plan WP10.7 step 2: links that fall behind hold the game too
    int pacedNow = 0;
    const auto pacedSpeed = [&net, &linkSpeeds](const int requested) {
      int paced = requested;
      if (net) {
        if (const auto slowest = net->SlowestSpeedLimit(); slowest && slowest->first < paced) {
          paced = slowest->first;
        }
        if (const auto link = linkSpeeds.Slowest(); link && link->first < paced) {
          paced = link->first;
        }
      }
      return std::clamp(paced, faf::remote::kMinSpeedLimit, std::max(requested, faf::remote::kMinSpeedLimit));
    };
    const auto watchSpeed = [&](const double elapsed) {
      moho::CClientManagerImpl* const manager = driver->GetClientManager();
      if (manager == nullptr) {
        return;
      }
      const float gameRate = moho::SIM_GetMeasuredGameRate();
      const float beatMs = gameRate > 0.0f ? faf::server::kSpeedZeroBeatMs / gameRate : 0.0f;
      const int asked = manager->GetSimRateRequested();
      // Plan WP10.7 step 2: each seat's link, how far behind it is at the speed the game runs at now.
      std::vector<faf::server::CServerNet::SSeatState> seatStates;
      const auto nameOf = [&seatStates](const std::int32_t uid) {
        for (const faf::server::CServerNet::SSeatState& seat : seatStates) {
          if (seat.uid == uid) {
            return seat.name;
          }
        }
        return "uid " + std::to_string(uid);
      };
      if (net) {
        seatStates = net->Seats();
        std::vector<faf::server::SLinkSample> samples;
        samples.reserve(seatStates.size());
        for (const faf::server::CServerNet::SSeatState& seat : seatStates) {
          samples.push_back(faf::server::SLinkSample{seat.uid, seat.behindSeconds, seat.gone});
        }
        for (const faf::server::SLinkNews& change : linkSpeeds.Update(elapsed, pacedNow, asked, samples)) {
          if (change.limit) {
            Say("%s's link is %.1f s behind: it holds the game at %+d at most", nameOf(change.uid).c_str(), change.behindSeconds, *change.limit);
          } else {
            Say("%s's link keeps up again: it no longer holds the game", nameOf(change.uid).c_str());
          }
        }
      }
      const int requested = pacedSpeed(asked);
      pacedNow = requested;
      // Plan WP10.7: who holds the game back (a player's game, step 0, or their link, step 2), when it changes.
      const auto slowest = net ? net->SlowestSpeedLimit() : std::nullopt;
      const auto link = net ? linkSpeeds.Slowest() : std::nullopt;
      const bool byLink = link && link->first < asked && (!slowest || link->first < slowest->first);
      const std::int32_t holder = byLink ? link->second : (slowest && slowest->first < asked ? slowest->second : 0);
      if (holder != speedHolder) {
        speedHolder = holder;
        if (holder != 0) {
          Say("Game speed held at %+d by %s's %s (requested %+d)", requested, nameOf(holder).c_str(), byLink ? "link" : "game", asked);
        } else {
          Say("Game speed no longer held by a player (requested %+d)", asked);
        }
      }
      if (views) {
        views->SetFrameSimRate(requested); // #178: the players' clients pace their display by it
      }
      // What the game really did over the last seconds: a median beat time doesn't show spikes.
      int speed = requested;
      std::pair<double, int>& oldest = beatHistory[beatSamples % beatHistory.size()];
      if (beatSamples >= beatHistory.size() && elapsed > oldest.first) {
        speed = std::min(requested, faf::server::SpeedOfBeatRate((end.beats - oldest.second) / (elapsed - oldest.first)));
      }
      oldest = {elapsed, end.beats};
      ++beatSamples;

      const faf::server::SSpeedNews news = speedWatch.Update(faf::server::SSpeedSample{elapsed, asked, speed, beatMs}); // what was asked; a hold is said above
      if (news.requestChanged) {
        Say("Game speed requested: %+d (was %+d)", requested, news.requestedBefore);
      }
      if (news.speedChanged) {
        Say("Sim speed %+d (was %+d, requested %+d), a beat takes %.0f ms", speed, news.speedBefore, asked, beatMs);
      }
      if (news.slowStarted) {
        Say("WARNING: the sim is close to speed -1: a beat takes %.0f ms, -1 starts at %.0f ms", beatMs, faf::server::kSpeedZeroBeatMs);
      }
      if (news.slowEnded) {
        Say("The sim is clear of speed -1 again: a beat takes %.0f ms", beatMs);
      }

      if (statusSeconds > 0.0 && elapsed - lastStatus >= statusSeconds) {
        const double beatsPerSecond = (end.beats - statusBeats) / (elapsed - lastStatus);
        const std::uint64_t netBytes = net ? net->BytesSent() : 0u;
        // Plan WP10.7: the player whose link is furthest behind, when anyone is more than a second behind.
        std::string behind;
        if (net) {
          const faf::server::CServerNet::SSeatState* worst = nullptr;
          const std::vector<faf::server::CServerNet::SSeatState> seats = net->Seats();
          for (const faf::server::CServerNet::SSeatState& seat : seats) {
            if (!seat.gone && (worst == nullptr || seat.behindBeats > worst->behindBeats)) {
              worst = &seat;
            }
          }
          if (worst != nullptr && worst->behindBeats > 10u) {
            behind = ", " + worst->name + " " + std::to_string(worst->behindBeats) + " beats behind (" + std::to_string(worst->backlogBytes / 1024u) + " KB)";
          }
        }
        Say("Status: game time %s, real time %s, speed %+d (requested %+d%s), %.1f beats/s, a beat takes %.0f ms, memory %ld MB, %.0f KB/s to players%s, %lu warnings in the log",
            GameClockText(end.lastBeat - pausedBeats).c_str(), ClockText(elapsed).c_str(), speed, asked,
            requested < asked ? (", held at " + std::string(requested >= 0 ? "+" : "") + std::to_string(requested) + " by a player (see the hold line)").c_str() : "",
            beatsPerSecond, beatMs, ResidentMegabytes(),
            static_cast<double>(netBytes - statusNetBytes) / 1024.0 / (elapsed - lastStatus), behind.c_str(), warnings.Count());
        statusNetBytes = netBytes;
        lastStatus = elapsed;
        statusBeats = end.beats;
      }
    };

    while (!end.ended && !stopped) {
      const double elapsed = SecondsSince(playStart);
      if (elapsed > timeLimit) {
        end.error = "out of time";
        break;
      }
      if (simDriver->DiagDriverState() == moho::EDriverState::Failed) {
        end.error = "the sim driver failed";
        break;
      }
      if (gStopSignal != 0) {
        end.stoppedBy = "signal " + std::to_string(gStopSignal);
        Say("Stopping on signal %d", gStopSignal);
        break;
      }
      sayNetNews();
      // Plan WP17.2: the control service's requests in the game. Pause and resume take the operator's path (SIGUSR1).
      if (control) {
        std::vector<faf::server::SControlRequest> requests;
        control->Poll(requests, ControlNowUs());
        for (const faf::server::SControlRequest& request : requests) {
          const bool pending = gPauseRequests != pauseRequestsDone;
          if (request.op == "status") {
            control->Reply(
              request.id, "\"phase\":\"game\",\"started\":" + std::string(started ? "true" : "false") + ",\"beat\":" + std::to_string(end.lastBeat) +
                            ",\"paused\":" + std::string(pausedBy != -1 ? "true" : "false") + "," + controlSeats()
            );
          } else if (request.op == "pause" || request.op == "resume") {
            const bool pause = request.op == "pause";
            if (!started) {
              control->Refuse(request.id, "the game hasn't started");
            } else if (pending) {
              control->Refuse(request.id, "a pause or resume is on its way");
            } else if (pause == operatorPauseWanted.value_or(pausedBy != -1)) {
              control->Refuse(request.id, pause ? "the game is paused already" : "the game isn't paused");
            } else {
              gPauseRequests = gPauseRequests + 1;
              control->Reply(request.id, {});
            }
          } else if (request.op == "force_start") {
            control->Refuse(request.id, "the game has started");
          } else if (request.op == "approve_observer" || request.op == "refuse_observer") {
            // Plan WP17.9: the organiser answers an observer's request (or lets a token in before anyone asks).
            if (!observers) {
              control->Refuse(request.id, "this server takes no observers (--observe)");
            } else if (request.token.empty() || request.token.size() > 1000u) {
              control->Refuse(request.id, request.op + " needs the observer's token");
            } else {
              if (request.op == "approve_observer") {
                observers->AllowToken(request.token);
              } else {
                observers->RefuseToken(request.token);
              }
              Say("The control service %s observer token %s", request.op == "approve_observer" ? "approves" : "refuses", request.token.c_str());
              control->Reply(request.id, {});
            }
          } else if (request.op == "substitute") {
            // Plan WP15.4 (#200): another person takes a player's seat (army, sources, pauses) from now on.
            if (!net) {
              control->Refuse(request.id, "this server has no players (--listen)");
            } else if (request.token.empty() || request.token.size() > 1024u || request.name.empty() || request.name.size() > 256u) {
              control->Refuse(request.id, "substitute needs a token (1 to 1024 characters) and a name (1 to 256)");
            } else if (request.uid <= 0 || request.uid > INT32_MAX ||
                       !net->RequestSubstitute(static_cast<std::int32_t>(request.uid), request.token, request.name)) {
              control->Refuse(request.id, "no player in the game with uid " + std::to_string(request.uid));
            } else {
              control->Reply(request.id, {});
              controlEvent("substitute", "\"uid\":" + std::to_string(request.uid) + ",\"name\":" + faf::server::JsonString(request.name));
            }
          } else if (request.op == "extend_timeouts") {
            // Plan WP15.4 (#200): more pauses for one player.
            const auto source = pauseSources.find(static_cast<std::int32_t>(request.uid));
            const auto budget = source == pauseSources.end() ? pauseBudgets.end() : pauseBudgets.find(source->second);
            if (budget == pauseBudgets.end()) {
              control->Refuse(request.id, "no player with uid " + std::to_string(request.uid));
            } else if (request.count <= 0 || request.count > 1000) {
              control->Refuse(request.id, "extend_timeouts takes a count from 1 to 1000");
            } else if (budget->second < 0) {
              control->Refuse(request.id, "that player's pauses are unlimited already");
            } else {
              budget->second += static_cast<int>(request.count);
              pauseGranted[budget->first] += static_cast<int>(request.count);
              pauseBook->SetGranted(budget->first, pauseGranted[budget->first]);
              if (const auto seat = pauseSeats.find(budget->first); seat != pauseSeats.end()) {
                seat->second->SetPauseAllowed(true);
              }
              Say("The control service gives uid %lld %lld more pause%s: %d left", static_cast<long long>(request.uid),
                  static_cast<long long>(request.count), request.count == 1 ? "" : "s", budget->second);
              control->Reply(request.id, "\"left\":" + std::to_string(budget->second));
            }
          } else if (request.op == "end") {
            // Plan WP15.4 (#200): the organiser ends the game now, with each army's result if given ("1=victory,2=defeat",
            // army numbers from 1 as the sim's `GameResult` has them). With results it counts as ended; without, as stopped.
            std::vector<std::pair<std::size_t, std::string>> results;
            std::string bad;
            for (std::size_t start = 0; start < request.results.size() && bad.empty();) {
              const std::size_t comma = std::min(request.results.find(',', start), request.results.size());
              const std::string pair = request.results.substr(start, comma - start);
              const std::size_t equals = pair.find('=');
              const int army = equals == std::string::npos ? 0 : std::atoi(pair.substr(0, equals).c_str());
              const std::string outcome = equals == std::string::npos ? std::string() : pair.substr(equals + 1);
              if (army < 1 || static_cast<std::size_t>(army) > end.players.size() ||
                  (outcome != "victory" && outcome != "defeat" && outcome != "draw")) {
                bad = pair;
              } else {
                results.emplace_back(static_cast<std::size_t>(army - 1), outcome);
              }
              start = comma + 1;
            }
            if (!bad.empty()) {
              control->Refuse(request.id, "end takes results as army=victory|defeat|draw, armies 1 to " + std::to_string(end.players.size()) + ", not " + bad);
            } else {
              for (const auto& [index, outcome] : results) {
                end.players[index].result = outcome + " 0";
                Say("%s: %s (set by the organiser)", end.players[index].name.c_str(), outcome.c_str());
              }
              end.ended = !results.empty();
              end.stoppedBy = "the organiser" + (request.reason.empty() ? std::string() : ": " + request.reason);
              stopped = true;
              Say("The control service ends the game%s", results.empty() ? "" : " with a result");
              control->Reply(request.id, "\"results\":" + std::to_string(results.size()));
            }
          } else if (!controlCommon(request)) {
            control->Refuse(request.id, request.op == "set_options" || request.op == "set_player" || request.op == "force_start" ? "the game has started" : "unknown op " + request.op);
          }
        }
        controlNews();
      }
      // Requests wait in the listener until a control service is connected to hear them.
      if (net && !defeatedLeaving.empty()) {
        // Plan WP13.7: out of the match as a player who leaves is (the seat's eject); no view after this.
        const double now = SecondsSince(playStart);
        std::erase_if(defeatedLeaving, [&](const std::pair<double, std::int32_t>& leaving) {
          if (now < leaving.first) {
            return false;
          }
          (void)net->RequestEject(leaving.second, "defeated (DefeatedPlayerView is disconnect)");
          return true;
        });
      }
      if (control && net) {
        // Plan WP17.2, WP17.8: a seat's content or mod verdict as it is made: who differs, for the web.
        for (const faf::server::CServerNet::SSeatState& seat : net->TakeJudged()) {
          std::string fields = "\"uid\":" + std::to_string(seat.uid) + ",\"name\":" + faf::server::JsonString(seat.name) +
                               ",\"content\":" + faf::server::JsonString(seat.content) + ",\"mods\":" + faf::server::JsonString(seat.mods) +
                               ",\"ui_mods\":[";
          for (std::size_t i = 0; i < seat.uiMods.size(); ++i) {
            fields += (i == 0 ? "" : ",") + faf::server::JsonString(seat.uiMods[i]);
          }
          controlEvent("content", fields + "]");
        }
      }
      if (control && observers && control->Connected()) {
        for (const faf::server::CObserverListener::SRequest& asked : observers->TakeRequests()) {
          controlEvent("observer_request", "\"token\":" + faf::server::JsonString(asked.token) + ",\"from\":" + faf::server::JsonString(asked.from));
        }
      }
      if (net && net->NobodyCame()) {
        end.stoppedBy = "nobody connected";
        Say("Nobody connected in time");
        break;
      }
      if (const int requests = gPauseRequests; started && requests != pauseRequestsDone) {
        pauseRequestsDone = requests;
        const bool pause = !operatorPauseWanted.value_or(pausedBy != -1); // against what the game will be, not what it was
        Say("The operator asks to %s the game", pause ? "pause" : "resume");
        operatorPauseWanted = pause;
        if (pause) {
          driver->RequestPause();
        } else {
          driver->Resume();
        }
      }
      if (net && started) {
        // Plan WP3.5, WP14.2. The reconnect window runs on meanwhile. A pause someone else ends or takes over isn't renewed.
        for (const faf::server::CServerNet::SPresence& change : net->TakePresence()) {
          if (change.gone) {
            controlLeft(change.uid);
          } else {
            controlEvent(change.away ? "away" : "back", "\"uid\":" + std::to_string(change.uid));
          }
          if (awayPauseSeconds <= 0.0) {
            continue;
          }
          if (change.away) {
            away[change.uid] = true;
            awayBudget.try_emplace(change.uid, awayPauseSeconds);
            awayPending = true;
          } else {
            away.erase(change.uid);
          }
        }
        if (awayPausing && pausedBy == serverSource) {
          for (const auto& [uid, isAway] : away) {
            awayBudget[uid] -= elapsed - awayCharged;
          }
        }
        awayCharged = elapsed;
        std::string waitingFor;
        double budgetLeft = 0.0;
        for (const auto& [uid, isAway] : away) {
          if (awayBudget[uid] > 0.0) {
            waitingFor = seatNames[uid];
            budgetLeft = std::max(budgetLeft, awayBudget[uid]);
          }
        }
        if (awayPausing && pausedBy == serverSource) {
          awayPauseSeen = true;
        } else if (awayPausing && awayPauseSeen) {
          awayPausing = false; // resumed, or paused by someone else
        }
        if (!waitingFor.empty() && awayPending && !awayPausing && pausedBy == -1) {
          awayPending = false;
          awayPausing = true;
          awayPauseSeen = false;
          Say("Pausing the game while %s is away, for %.0f s at most", waitingFor.c_str(), budgetLeft);
          driver->RequestPause();
        } else if (waitingFor.empty() && awayPausing) {
          awayPausing = false;
          awayPending = false;
          Say("%s", away.empty() ? "Resuming the game: nobody is away" : "Resuming the game: the time to wait for whoever is away has run out");
          driver->Resume();
        }
      }
      if (started && elapsed - lastSample >= 1.0) {
        lastSample = elapsed;
        watchSpeed(elapsed);
        if (!stalled && elapsed - lastBeatAt >= kStallSeconds) {
          stalled = true;
          Say("WARNING: no beat for %.0f s, at game time %s", kStallSeconds, GameClockText(end.lastBeat - pausedBeats).c_str());
        }
      }

      driver->Dispatch();
      if (driver->HasSyncData() && SecondsSince(playStart) < nextBeatAt) {
        const double wait = std::min(nextBeatAt - SecondsSince(playStart), 0.05);
        if (wait > 0.0) {
          std::this_thread::sleep_for(std::chrono::duration<double>(wait));
        }
        continue;
      }
      if (!driver->HasSyncData()) {
        // `WLD_DoPostInitializing` / `WLD_DoWaiting`: the first beat is out and this client is ready;
        // once every client is, the issue thread may run.
        if (started && !ready) {
          if (moho::CClientManagerImpl* const manager = driver->GetClientManager(); manager != nullptr && manager->IsEveryoneReady()) {
            driver->DecrementOutstandingRequestsAndSignal();
            ready = true;
          }
        }
        (void)::WaitForSingleObject(syncAvailable, 50);
        continue;
      }
      {
        moho::SSyncData* rawPacket = nullptr;
        driver->GetSyncData(rawPacket);
        const std::unique_ptr<moho::SSyncData> packet(rawPacket);
        if (!packet) {
          continue;
        }
        ++end.beats;
        end.lastBeat = packet->mCurBeat;
        lastBeatAt = SecondsSince(playStart);
        if (net) {
          net->NoteBeat(end.lastBeat);
        }
        pausedBeats += packet->mPausedBy != -1 ? 1 : 0;
        if (packet->mPausedBy != pausedBy) {
          const auto& sources = sessionInfo->mLaunchInfo->mCommandSources.mSrcs;
          if (packet->mPausedBy == -1) {
            Say("Game resumed, at game time %s", GameClockText(end.lastBeat - pausedBeats).c_str());
          } else if (static_cast<std::size_t>(packet->mPausedBy) < sources.size()) {
            Say("Game paused by %s, at game time %s", sources[static_cast<std::size_t>(packet->mPausedBy)].mName.c_str(), GameClockText(end.lastBeat - pausedBeats).c_str());
          } else {
            Say("Game paused, at game time %s", GameClockText(end.lastBeat - pausedBeats).c_str());
          }
          // Plan WP15.4: the pause a player's budget pays for, as the sim would have spent it (only from running to paused).
          if (pausedBy == -1 && packet->mPausedBy != -1) {
            const auto source = static_cast<std::uint32_t>(packet->mPausedBy);
            if (const auto budget = pauseBudgets.find(source); budget != pauseBudgets.end() && budget->second > 0) {
              --budget->second;
              if (budget->second == 0) {
                if (const auto seat = pauseSeats.find(source); seat != pauseSeats.end()) {
                  seat->second->SetPauseAllowed(false);
                }
              }
              Say("%s has %d pause%s left", source < sources.size() ? sources[static_cast<std::size_t>(source)].mName.c_str() : "a player", budget->second, budget->second == 1 ? "" : "s");
            }
          }
          pausedBy = packet->mPausedBy;
          if (operatorPauseWanted && *operatorPauseWanted == (pausedBy != -1)) {
            operatorPauseWanted.reset(); // the game is where the operator asked
          }
        }
        if (moho::CClientManagerImpl* const manager = driver->GetClientManager(); manager != nullptr) {
          nextBeatAt = std::max(nextBeatAt, lastBeatAt - kMaxCatchUpSeconds) + faf::server::SecondsPerBeat(pacedSpeed(manager->GetSimRateRequested()));
        }
        if (stalled) {
          stalled = false;
          Say("Beats are coming again, at game time %s", GameClockText(end.lastBeat - pausedBeats).c_str());
        }
        if (!started) {
          // `WLD_DoInitializing`: the first beat is applied, then this client declares itself ready.
          started = true;
          Say("Game started");
          controlEvent("game_started", "\"beat\":" + std::to_string(end.lastBeat));
          if (moho::CClientManagerImpl* const manager = driver->GetClientManager(); manager != nullptr) {
            manager->Cleanup();
          }
        }

        LuaPlus::LuaObject sync;
        if (faf::headless::ReadSyncNaming(*packet, state, {"GameResult", "GameEnded"}, sync)) {
          LuaPlus::LuaObject results = sync["GameResult"];
          if (results.IsTable()) {
            ReadGameResults(results, end.players);
            // Plan WP11.1: with `DefeatedPlayerView = "observe"`, a defeated player may focus on any army (the original
            // client's `SetFocusArmy(-1)` on defeat); they see only what their view (WP13.6) was sent.
            for (std::size_t army = 0; net && !disconnectDefeated && army < end.players.size(); ++army) {
              if (end.players[army].result.starts_with("defeat") && focusFreed.insert(army).second) {
                if (const auto found = armyUids.find(army); found != armyUids.end()) {
                  net->FreeFocus(found->second);
                }
              }
            }
            // Plan WP13.7: with `DefeatedPlayerView = "disconnect"`, a defeated player goes once they've seen it.
            for (std::size_t army = 0; disconnectDefeated && army < end.players.size(); ++army) {
              if (end.players[army].result.starts_with("defeat") && defeatedArmies.insert(army).second) {
                if (const auto found = armyUids.find(army); found != armyUids.end()) {
                  defeatedLeaving.emplace_back(SecondsSince(playStart) + kDefeatedLeaveSeconds, found->second);
                }
              }
            }
          }
          const LuaPlus::LuaObject gameEnded = sync["GameEnded"];
          if (!gameEnded.IsNil() && (!gameEnded.IsBoolean() || gameEnded.GetBoolean())) {
            end.ended = true;
          }
        }
        if (stopBeat > 0 && end.lastBeat >= stopBeat) {
          stopped = true;
          end.stoppedBy = "--stop-beat";
        }
      }
    }

    end.seconds = SecondsSince(playStart);
    if (net) {
      net->Stop();
      sayNetNews();
    }
    // `WLD_Teardown`: the driver stops and gives up the packets it holds, which finishes the replay.
    driver->ShutDown();
    if (views) {
      if (views->Failures() != 0u) {
        Say("WARNING: %llu view lanes didn't encode", static_cast<unsigned long long>(views->Failures()));
      }
      views->Uninstall();
      Say("%s", net->Intake().Report().c_str());
      Say("%s", views->LaneReport().c_str());
    }
    if (net) {
      net->Stop(); // its counters are the network thread's
      Say("%s", net->LinkReport().c_str());
    }
    while (driver->HasSyncData()) {
      moho::SSyncData* rawPacket = nullptr;
      driver->GetSyncData(rawPacket);
      delete rawPacket;
    }
    sessionState.reset();
    rules.reset();
    wldMap.reset();
    driver.reset(); // the replay closes: the observers' log is finished
    if (observers || liveReplay) {
      // Observers and the live replay are behind the game: they get its last moments before the server goes, for the
      // delay and a little more.
      const auto waitEnd = Clock::now() + std::chrono::duration_cast<Clock::duration>(
                                            std::chrono::duration<double>(matchRules.observerDelaySeconds.value_or(0.0) + 10.0)
                                          );
      while (((observers && !observers->AllSent()) || (liveReplay && !liveReplay->Done())) && Clock::now() < waitEnd && gStopSignal == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        sayNetNews();
      }
      sayNetNews();
      if (observers) {
        observers->Stop();
      }
      if (liveReplay) {
        liveReplay->Stop();
      }
    }

    WriteResult(resultPath, end);
    controlEvent(
      "game_ended", "\"ended\":" + std::string(end.ended ? "true" : "false") + ",\"beats\":" + std::to_string(end.beats) +
                      ",\"stopped_by\":" + faf::server::JsonString(end.stoppedBy) + ",\"error\":" + faf::server::JsonString(end.error)
    );
    if (end.ended) {
      Say("Game ended: game time %s, real time %s", GameClockText(end.lastBeat - pausedBeats).c_str(), ClockText(end.seconds).c_str());
    } else if (!end.error.empty()) {
      Say("ERROR: the game didn't finish: %s, at game time %s, real time %s", end.error.c_str(), GameClockText(end.lastBeat - pausedBeats).c_str(), ClockText(end.seconds).c_str());
    } else {
      Say("Game stopped (%s): game time %s, real time %s", end.stoppedBy.c_str(), GameClockText(end.lastBeat - pausedBeats).c_str(), ClockText(end.seconds).c_str());
    }
    Say("Replay %s, result %s, %lu warnings in the log", replayPath.c_str(), resultPath.c_str(), warnings.Count());
    if (!end.error.empty()) {
      return kExitCrash;
    }
    if (end.stoppedBy == "nobody connected") {
      return kExitNobodyCame;
    }
    return gStopSignal != 0 ? kExitStopped : kExitEnded;
  }
} // namespace

int main(int, char**)
{
  for (const int signalNumber : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT}) {
    (void)std::signal(signalNumber, &CrashSignal);
  }
  for (const int signalNumber : {SIGINT, SIGTERM}) {
    (void)std::signal(signalNumber, &StopSignal);
  }
  (void)std::signal(SIGUSR1, &PauseSignal);
  (void)std::signal(SIGUSR2, &ForceStartSignal);
  std::setvbuf(stdout, nullptr, _IOLBF, 0);

  // `WinMain` / `CScApp::CScApp`, and `CScApp::Init` without the splash, fonts, UI manager and device.
  moho::APP_InitializeIdentity();
  moho::PLAT_Init();
  (void)SetSse2Mode(0);

  std::string matchPath;
  std::string outDir;
  if (!ReadOption("--match", matchPath) || !ReadOption("--out", outDir)) {
    std::printf("%s", kUsage);
    return kExitBadInput;
  }
  std::error_code directoryError;
  std::filesystem::create_directories(outDir, directoryError);

  // Without `/log`, the engine's log goes next to the replay. A target here sees all of startup.
  static CLogWarningCounter warnings;
  std::string logOption;
  if (!ReadOption("/log", logOption)) {
    static std::ofstream logFile(outDir + "/server.log", std::ios::out | std::ios::trunc);
    if (logFile) {
      static gpg::StreamLogTarget logTarget(logFile, 3U);
    }
  }

  Say("faf-re dedicated server, build %s", gpg::diag::BuildIdentity());
  CServerApp app;
  if (!app.Init()) {
    Say("ERROR: the engine's services didn't start");
    return kExitCrash;
  }
  moho::USER_LoadPreferences(fa::string("Game.prefs"));
  platform::SetX87PrecisionControl(_PC_24);
  moho::PlaceCurrentThread(moho::EThreadRole::Main);

  int code = kExitCrash;
  SMatchEnd end;
  try {
    code = Run(warnings, end);
  } catch (const std::exception& error) {
    Say("ERROR: %s", error.what());
    end.error = error.what();
    WriteResult(outDir + "/result.json", end);
  }
  std::fflush(stdout);
  // What's left of the engine ends with the process, as headless's does.
  std::_Exit(code);
}
