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
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
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
#include "server/LobbySignaller.h"
#include "server/ServerNet.h"
#include "server/ServerViews.h"
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
    "[--warn-beat-ms <n>] [--listen <ip:port>] [--join-seconds <n>] [--reconnect-seconds <n>] [--lead-ms <n>] [--view-threads <n>] [--per-player-views] [--team-views] [--away-pause-seconds <n>] [--lobby-seconds <n>] [--stats-every <beats>]\n";

  constexpr double kDefaultStatusMinutes = 10.0;
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
    if (ReadOption("--reconnect-seconds", text)) {
      netConfig.reconnectSeconds = std::atof(text.c_str());
    }
    const double awayPauseSeconds = ReadOption("--away-pause-seconds", text) ? std::atof(text.c_str()) : 0.0;
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
    end.title = ReadMatchTitle(config, state);
    end.map = build.mapName.c_str();
    end.players = ReadPlayers(config);

    LuaPlus::LuaObject gameOptions = config["GameOptions"];
    moho::SLaunchSpeed launchSpeed = moho::ReadLaunchSpeed(gameOptions);
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
    const std::map<std::int32_t, std::string> tokens = ReadTokens(state);
    for (const moho::SLaunchClient& client : roster.Remotes()) {
      faf::remote::CServerClient& seat = faf::remote::CServerClient::Create(
        *static_cast<moho::CClientManagerImpl*>(sessionInfo->mClientManager), client.name.c_str(), client.clientIndex, client.uid, client.commandSource
      );
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
      if (lobbySeconds <= 0.0) {
        net->CloseLobby(); // the game starts at once: nothing to relay (plan WPR.51)
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
        faf::server::CLobbySignaller signaller(scenarioFile.IsString() ? scenarioFile.GetString() : "");
        for (const moho::SLaunchClient& client : roster.Remotes()) {
          signaller.AddParticipant(client.uid, client.name.c_str());
        }
        Say("Lobby open for %.0f s, hosted by uid %d", lobbySeconds, static_cast<int>(signaller.Host()));
        const Clock::time_point lobbyEnd = Clock::now() + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(lobbySeconds));
        std::vector<faf::server::CLobbySignaller::SOutgoing> out;
        std::size_t lastIn = 0;
        std::uint64_t toServer = 0;
        bool hostLeftSaid = false;
        bool launched = false;
        // Plan WP2.14: what the host's launch is checked against. The match file's configuration stays the one the
        // game starts with (plan WPR.55: the clients' launch comes from the server, never from the lobby's message).
        const faf::server::SLaunchFacts matchFacts = ReadLaunchFacts(config);
        const auto signal = [&net](const std::int32_t to, const faf::remote::net::ELobbySignal kind, std::string text) {
          faf::remote::net::SLobbySignal message;
          message.kind = kind;
          message.text = std::move(text);
          net->QueueLobbyFromServer(to, faf::remote::net::EncodeLobbySignal(message));
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
            if (!refusal.empty()) {
              Say("Lobby: launch refused: %s", refusal.c_str());
              signal(message.from, faf::remote::net::ELobbySignal::LaunchRefused, refusal);
              continue;
            }
            Say("Lobby: the host launched; starting the match");
            for (const std::int32_t uid : signaller.InLobbyUids()) {
              signal(uid, faf::remote::net::ELobbySignal::Launching, {});
            }
            launched = true;
          }
          for (const std::int32_t uid : net->TakeLobbyJoined()) {
            signaller.OnJoined(uid, out);
          }
          for (const std::int32_t uid : net->TakeLobbyLeft()) {
            signaller.OnLeft(uid, out);
          }
          for (const faf::server::CLobbySignaller::SOutgoing& message : out) {
            net->QueueLobbyFromServer(message.to, message.message);
          }
          out.clear();
          if (const std::size_t in = signaller.InLobby(); in != lastIn) {
            lastIn = in;
            Say("Lobby: %d of %d participants in", static_cast<int>(in), static_cast<int>(roster.Remotes().size()));
          }
          if (signaller.HostLeft() && !std::exchange(hostLeftSaid, true)) {
            Say("Lobby: the host left; the lobby can't go on");
          }
          for (const std::string& line : net->TakeNews()) {
            Say("%s", line.c_str());
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
    const auto sayNetNews = [&net] {
      if (net) {
        for (const std::string& line : net->TakeNews()) {
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
      }
      views = std::make_unique<faf::server::CServerViews>(contentTables, *rules, mapSizeX, mapSizeZ, *net, std::move(viewPlayers), static_cast<unsigned int>(std::max(viewThreads, 1)), teamViews);
      if (std::string statsEvery; ReadOption("--stats-every", statsEvery)) {
        views->SetStatsEveryBeats(static_cast<std::uint32_t>(std::max(1, std::atoi(statsEvery.c_str()))));
      }
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

    const auto watchSpeed = [&](const double elapsed) {
      moho::CClientManagerImpl* const manager = driver->GetClientManager();
      if (manager == nullptr) {
        return;
      }
      const float gameRate = moho::SIM_GetMeasuredGameRate();
      const float beatMs = gameRate > 0.0f ? faf::server::kSpeedZeroBeatMs / gameRate : 0.0f;
      const int requested = manager->GetSimRateRequested();
      // What the game really did over the last seconds: a median beat time doesn't show spikes.
      int speed = requested;
      std::pair<double, int>& oldest = beatHistory[beatSamples % beatHistory.size()];
      if (beatSamples >= beatHistory.size() && elapsed > oldest.first) {
        speed = std::min(requested, faf::server::SpeedOfBeatRate((end.beats - oldest.second) / (elapsed - oldest.first)));
      }
      oldest = {elapsed, end.beats};
      ++beatSamples;

      const faf::server::SSpeedNews news = speedWatch.Update(faf::server::SSpeedSample{elapsed, requested, speed, beatMs});
      if (news.requestChanged) {
        Say("Game speed requested: %+d (was %+d)", requested, news.requestedBefore);
      }
      if (news.speedChanged) {
        Say("Sim speed %+d (was %+d, requested %+d), a beat takes %.0f ms", speed, news.speedBefore, requested, beatMs);
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
        Say("Status: game time %s, real time %s, speed %+d (requested %+d), %.1f beats/s, a beat takes %.0f ms, memory %ld MB, %.0f KB/s to players, %lu warnings in the log",
            GameClockText(end.lastBeat - pausedBeats).c_str(), ClockText(elapsed).c_str(), speed, requested, beatsPerSecond, beatMs, ResidentMegabytes(),
            static_cast<double>(netBytes - statusNetBytes) / 1024.0 / (elapsed - lastStatus), warnings.Count());
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
      if (net && net->NobodyCame()) {
        end.stoppedBy = "nobody connected";
        Say("Nobody connected in time");
        break;
      }
      if (const int requests = gPauseRequests; started && requests != pauseRequestsDone) {
        pauseRequestsDone = requests;
        Say("The operator asks to %s the game", pausedBy == -1 ? "pause" : "resume");
        if (pausedBy == -1) {
          driver->RequestPause();
        } else {
          driver->Resume();
        }
      }
      if (net && started) {
        // Plan WP3.5, WP14.2. The reconnect window runs on meanwhile. A pause someone else ends or takes over isn't renewed.
        for (const faf::server::CServerNet::SPresence& change : net->TakePresence()) {
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
          pausedBy = packet->mPausedBy;
        }
        if (moho::CClientManagerImpl* const manager = driver->GetClientManager(); manager != nullptr) {
          nextBeatAt = std::max(nextBeatAt, lastBeatAt - kMaxCatchUpSeconds) + faf::server::SecondsPerBeat(manager->GetSimRateRequested());
        }
        if (stalled) {
          stalled = false;
          Say("Beats are coming again, at game time %s", GameClockText(end.lastBeat - pausedBeats).c_str());
        }
        if (!started) {
          // `WLD_DoInitializing`: the first beat is applied, then this client declares itself ready.
          started = true;
          Say("Game started");
          if (moho::CClientManagerImpl* const manager = driver->GetClientManager(); manager != nullptr) {
            manager->Cleanup();
          }
        }

        LuaPlus::LuaObject sync;
        if (faf::headless::ReadSyncNaming(*packet, state, {"GameResult", "GameEnded"}, sync)) {
          LuaPlus::LuaObject results = sync["GameResult"];
          if (results.IsTable()) {
            ReadGameResults(results, end.players);
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
    driver.reset();

    WriteResult(resultPath, end);
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
