// Engine addition (in-game launcher plan, .plans/ingame-launcher, WP4-WP5): the in-game launcher's online service
// (src/moho/app/OnlineLauncher.h).

#include "moho/app/OnlineLauncher.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <exception>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/net/Common.h"
#include "moho/sim/CWldSession.h"
#include "moho/ui/IUIManager.h"
#include "online/ControlService.h"
#include "online/FafAuth.h"
#include "online/FafLobby.h"
#include "online/GameLink.h"
#include "online/LaunchArgs.h"
#include "online/ReplayRelay.h"
#include "platform/PlatformDefines.h"
#include "platform/Process.h"

namespace
{
  using namespace faf::online;

  void LogLine(
    const char* const line
  )
  {
    gpg::Logf("ONLINE: %s", line);
  }

  /** Where the launcher keeps its sign-in: %LOCALAPPDATA%, $XDG_DATA_HOME or ~/.local/share, then faf-re/online. */
  std::filesystem::path DataFolder()
  {
    for (const char* name : {"LOCALAPPDATA", "XDG_DATA_HOME"}) {
      if (const char* const folder = std::getenv(name); folder != nullptr && folder[0] != '\0') {
        return std::filesystem::path(folder) / "faf-re" / "online";
      }
    }
    const char* const home = std::getenv("HOME");
    return std::filesystem::path(home != nullptr ? home : ".") / ".local" / "share" / "faf-re" / "online";
  }

  /** FAF's faf-uid program: FAF_UID, else next to the game, else the official client's copy (Windows). */
  std::string UidProgram()
  {
    if (const char* const set = std::getenv("FAF_UID"); set != nullptr && set[0] != '\0') {
      return set;
    }
#if FAFRE_PLATFORM_WINDOWS
    const char* const name = "faf-uid.exe";
#else
    const char* const name = "faf-uid";
#endif
    std::error_code ignored;
    if (const auto here = std::filesystem::current_path(ignored) / name; std::filesystem::exists(here, ignored)) {
      return here.string();
    }
#if FAFRE_PLATFORM_WINDOWS
    if (const char* const programs = std::getenv("ProgramFiles"); programs != nullptr) {
      const auto client = std::filesystem::path(programs) / "FAF Client" / "natives" / name;
      if (std::filesystem::exists(client, ignored)) {
        return client.string();
      }
    }
#endif
    return {};
  }

  /**
   * Our control services (docs/CONTROL_SERVICE.md) whose lobbies the launcher lists beside FAF's games: one address
   * per line in control-services.txt in DataFolder() ('#' starts a comment), and FAF_ONLINE_CONTROL (a test hook,
   * comma-separated). None by default. The player's FAF access token goes to each of them, so the list is a file Lua
   * can't write: a UI mod can't send the token elsewhere.
   */
  std::vector<std::string> ControlServiceAddresses()
  {
    std::vector<std::string> out;
    const auto add = [&out](std::string line) {
      if (const std::size_t hash = line.find('#'); hash != std::string::npos) {
        line.erase(hash);
      }
      while (!line.empty() &&
             (line.back() == '\r' || line.back() == ' ' || line.back() == '\t' || line.back() == '/')) {
        line.pop_back();
      }
      std::size_t first = 0;
      while (first < line.size() && (line[first] == ' ' || line[first] == '\t')) {
        ++first;
      }
      line.erase(0, first);
      if (
        (line.starts_with("http://") || line.starts_with("https://")) &&
        std::find(out.begin(), out.end(), line) == out.end()
      ) {
        out.push_back(line);
      }
    };
    std::ifstream in(DataFolder() / "control-services.txt");
    for (std::string line; std::getline(in, line);) {
      add(line);
    }
    if (const char* const test = std::getenv("FAF_ONLINE_CONTROL"); test != nullptr) {
      std::string all = test;
      for (std::size_t start = 0; start <= all.size();) {
        const std::size_t comma = all.find(',', start);
        add(all.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (comma == std::string::npos) {
          break;
        }
        start = comma + 1;
      }
    }
    return out;
  }

  std::string Lower(
    std::string text
  )
  {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
      return std::tolower(c);
    });
    return text;
  }

  enum class MatchState
  {
    Idle,
    Preparing, ///< game_launch came; the ICE session is being fetched
    Running,   ///< the GPGNet lobby or the game runs in this process
    Ending,    ///< the player quit; back to the launcher once the session is gone
    Failed,
  };

  const char* MatchStateName(
    const MatchState state
  )
  {
    switch (state) {
    case MatchState::Idle:
      return "idle";
    case MatchState::Preparing:
      return "preparing";
    case MatchState::Running:
      return "running";
    case MatchState::Ending:
      return "ending";
    case MatchState::Failed:
      return "failed";
    }
    return "idle";
  }

  /**
   * Test hooks, unset for players: FAF_ONLINE_OAUTH, FAF_ONLINE_API, FAF_ONLINE_USER_SERVICE and FAF_ONLINE_WS point
   * the launcher at another FAF stack (a local one); FAF_ONLINE_ACCESS_TOKEN_FILE uses that access token instead of a
   * sign-in; FAF_ONLINE_TEST_UNIQUE_ID replaces faf-uid there (FafLobby refuses it for faforever.com);
   * FAF_ONLINE_AUTOTEST=host:<map>:<seconds> hosts a game once in the lobby and presses Exit after that long in FAF's
   * lobby; with :game after it, presses Launch there and leaves the game after that long as the score screen does.
   * Either way it quits for real once back in the launcher.
   */
  std::string TestSetting(
    const char* const name
  )
  {
    const char* const value = std::getenv(name);
    return value != nullptr ? value : "";
  }

  FafEndpoints GameEndpoints()
  {
    FafEndpoints endpoints;
    if (const std::string oauth = TestSetting("FAF_ONLINE_OAUTH"); !oauth.empty()) {
      endpoints.oauthUrl = oauth;
    }
    if (const std::string api = TestSetting("FAF_ONLINE_API"); !api.empty()) {
      endpoints.apiUrl = api;
    }
    endpoints.scopes = "openid offline public_profile lobby";
    endpoints.tokenDescription = "faf-re game login";
    endpoints.approveWho = "the game";
    return endpoints;
  }

  FafLobbySettings GameLobbySettings()
  {
    FafLobbySettings settings;
    settings.userAgent = "faf-re-client";
    settings.version = gpg::diag::BuildVersion();
    settings.uidProgram = UidProgram();
    if (const std::string service = TestSetting("FAF_ONLINE_USER_SERVICE"); !service.empty()) {
      settings.userServiceUrl = service;
    }
    settings.webSocketUrl = TestSetting("FAF_ONLINE_WS");
    settings.testUniqueId = TestSetting("FAF_ONLINE_TEST_UNIQUE_ID");
    return settings;
  }

  /** The service: made on the first FafOnline_* call, ended by ONLINE_Shutdown. */
  /**
   * The FAF init file a start without /init ran. The game then runs its default data-path script, SupComDataPath.lua;
   * FAF's copy of it only runs init_faf.lua from its own folder, so the game is on FAF's files as with
   * /init init_faf.lua. The script itself when it is an init file, else the first init_<name>.lua it names that sits
   * next to it; empty when there is none (the game is not on FAF's files).
   */
  std::string InitFromDataPathScript()
  {
    const std::filesystem::path script = moho::DISK_GetDataPathScriptFile();
    if (script.empty()) {
      return {};
    }
    const std::string name = Lower(script.filename().string());
    if (name.starts_with("init_") && name.ends_with(".lua")) {
      return script.string();
    }
    std::ifstream in(script, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    text = Lower(text);
    for (std::size_t at = text.find("init_"); at != std::string::npos; at = text.find("init_", at + 1)) {
      std::size_t end = at + 5;
      while (end < text.size() && (std::isalnum(static_cast<unsigned char>(text[end])) != 0 || text[end] == '_')) {
        ++end;
      }
      if (end == at + 5 || text.compare(end, 4, ".lua") != 0) {
        continue;
      }
      const std::filesystem::path named = script.parent_path() / text.substr(at, end + 4 - at);
      std::error_code missing;
      if (std::filesystem::exists(named, missing)) {
        return named.string();
      }
    }
    return {};
  }

  struct Service
  {
    FafAuth auth{GameEndpoints()};
    FafLobby lobby{GameLobbySettings()};
    bool lobbyStarted = false;
    /// A failed lobby connection is tried again at this time (unset: no try planned).
    std::chrono::steady_clock::time_point lobbyRetryAt{};
    /// Failed tries in a row; the wait before the next doubles with each, from 5 s to 80 s.
    int lobbyFailures = 0;
    LaunchPlayer me;
    bool haveMe = false;
    /// Every player the lobby told us about (player_info), by login: ratings, country and clan for the game list.
    std::map<std::string, LaunchPlayer> players;
    std::string notice;
    /// The last hand-off of the sign-in page to the browser: "" (none yet), "opening", "opened", or why it failed. A
    /// thread of its own writes it, as the shell can take a moment.
    struct PageOpen
    {
      std::mutex lock;
      std::string state;
    };
    std::shared_ptr<PageOpen> pageOpen = std::make_shared<PageOpen>();
    std::string realInit; ///< the command line's /init: the game files this process has mounted

    MatchState match = MatchState::Idle;
    std::string matchMessage;
    GameLaunch launch;
    std::thread iceThread;
    std::atomic<bool> iceReady{false};
    std::string iceJson = "[]";
    bool forceRelay = false;
    std::unique_ptr<GameLink> link;
    std::unique_ptr<ReplayRelay> relay;
    std::unique_ptr<ReplayRelay> finishingRelay; ///< the last match's, sending its last bytes
    std::chrono::steady_clock::time_point finishingSince;
    bool endedFromLobby = false;
    std::string fixedToken; ///< FAF_ONLINE_ACCESS_TOKEN_FILE's, a test hook
    /// Our control services (ControlServiceAddresses), followed while the player is signed in to FAF.
    std::vector<std::unique_ptr<ControlServiceClient>> controls;

    // FAF_ONLINE_AUTOTEST (a test hook): host on <map> (host:<map>:<seconds>[:game]), or join the first open game the
    // launcher lists through its Join (join:<seconds>); leave after <seconds> in the lobby or the game, quit after.
    std::string autotestMap; ///< the map to host; "join" for the join test
    bool autotestJoin = false;
    int autotestSeconds = 0;
    bool autotestGame = false; ///< launch the game from FAF's lobby, leave that
    /// 0: host once in the lobby; 1: wait for the match; 2: in FAF's lobby; 5: launched, waiting for the session;
    /// 6: in the game; 3: left, waiting to be back; 4: done
    int autotestStep = 0;
    std::chrono::steady_clock::time_point autotestSince;

    Service()
    {
      auth.SetLog(LogLine);
      lobby.SetLog(LogLine);
      std::error_code ignored;
      std::filesystem::create_directories(DataFolder(), ignored);
      auth.SetTokenFile(DataFolder() / "game.token");
      fa::vector<fa::string> init;
      if (moho::CFG_GetArgOption("/init", 1, &init) && !init.empty()) {
        realInit = init[0].c_str();
      } else {
        // Started without /init (the exe run directly): the init file the default data-path script ran.
        realInit = InitFromDataPathScript();
        LogLine(
          realInit.empty() ? "no /init, and the data-path script runs no FAF init file"
                           : ("no /init; the data-path script runs " + realInit).c_str()
        );
      }
      if (const std::string file = TestSetting("FAF_ONLINE_ACCESS_TOKEN_FILE"); !file.empty()) {
        std::ifstream in(file, std::ios::binary);
        std::getline(in, fixedToken);
        while (!fixedToken.empty() && (fixedToken.back() == '\r' || fixedToken.back() == ' ')) {
          fixedToken.pop_back();
        }
        LogLine(fixedToken.empty() ? "test: FAF_ONLINE_ACCESS_TOKEN_FILE is empty" : "test: a fixed access token");
      }
      if (const std::string test = TestSetting("FAF_ONLINE_AUTOTEST"); test.starts_with("host:")) {
        const std::size_t colon = test.find(':', 5);
        autotestMap = test.substr(5, colon == std::string::npos ? std::string::npos : colon - 5);
        autotestSeconds = colon == std::string::npos ? 30 : std::atoi(test.c_str() + colon + 1);
        autotestGame = test.ends_with(":game");
        LogLine(("autotest: host on " + autotestMap + ", leave the " + (autotestGame ? "game" : "lobby") + " after " +
                 std::to_string(autotestSeconds) + " s")
                  .c_str());
      } else if (test.starts_with("join:")) {
        autotestMap = "join";
        autotestJoin = true;
        autotestSeconds = std::atoi(test.c_str() + 5);
        LogLine(("autotest: join the first open game, leave the lobby after " + std::to_string(autotestSeconds) + " s")
                  .c_str());
      }
      if (fixedToken.empty()) {
        auth.Resume(); // a kept sign-in signs in again; without one, nothing goes out
      }
    }

    [[nodiscard]] bool SignedIn() const
    {
      return !fixedToken.empty() || auth.GetState() == FafAuth::State::LoggedIn;
    }

    [[nodiscard]] std::string CurrentToken() const
    {
      return !fixedToken.empty() ? fixedToken : auth.AccessToken();
    }

    ~Service()
    {
      for (const auto& control : controls) {
        control->Stop();
      }
      if (iceThread.joinable()) {
        iceThread.join();
      }
      lobby.SetGameHandler({});
      lobby.Disconnect();
      if (link) {
        link->Stop();
      }
    }

    /**
     * The access token for a request on a worker thread: refreshed when it is near its end, as the lobby, the
     * control services and the replay relay reconnect long after the sign-in (a token lasts an hour).
     */
    FafLobby::TokenSource Tokens()
    {
      return [this]() -> std::expected<std::string, std::string> {
        if (!fixedToken.empty()) {
          return fixedToken;
        }
        return auth.FreshAccessToken();
      };
    }
  };

  std::unique_ptr<Service> gService;

  Service& TheService()
  {
    if (!gService) {
      gService = std::make_unique<Service>();
    }
    return *gService;
  }

  void Fail(
    Service& s,
    std::string why
  )
  {
    LogLine(why.c_str());
    s.match = MatchState::Failed;
    s.matchMessage = std::move(why);
  }

  void SendGameEnded(
    Service& s
  )
  {
    // The official client says so when its game process ends (FafServerAccessor.notifyGameEnded).
    (void)s.lobby.Send(JsonObject({
      {"command", JsonString("GameState")},
      {"target", JsonString("game")},
      {"args", JsonArray({JsonString("Ended")})},
    }));
  }

  /** A start that failed half way: everything it began goes, and FAF hears the game is over for this player. */
  void AbortMatch(
    Service& s,
    std::string why
  )
  {
    s.lobby.SetGameHandler({});
    if (moho::GPGNET_GetPtr()) {
      moho::GPGNET_Shutdown();
    }
    moho::CFG_ClearLaunchArgs();
    if (s.link) {
      s.link->Stop();
      s.link.reset();
    }
    if (s.relay) {
      s.relay->Stop();
      s.relay.reset();
    }
    SendGameEnded(s);
    Fail(s, std::move(why));
  }

  /** game_launch: the game's files must be the ones this process has mounted; then its ICE servers, off this thread. */
  void BeginLaunch(
    Service& s,
    const JsonNode& message
  )
  {
    if (s.match == MatchState::Preparing || s.match == MatchState::Running || s.match == MatchState::Ending) {
      LogLine("a game_launch while a match runs; ignored");
      return;
    }
    s.launch = ReadGameLaunch(message);
    const std::string wanted = "init_" + s.launch.featuredMod + ".lua";
    if (!s.realInit.empty() && Lower(std::filesystem::path(s.realInit).filename().string()) != Lower(wanted)) {
      // Swapping the mounted game files inside a running game is WP8; until then the game starts again on them.
      Fail(
        s,
        "This game uses FAF's " + s.launch.featuredMod + " files. Start the game with /init " + wanted + " to join it."
      );
      SendGameEnded(s);
      return;
    }
    s.match = MatchState::Preparing;
    s.matchMessage = "Preparing the game";
    s.iceReady = false;
    if (s.iceThread.joinable()) {
      s.iceThread.join();
    }
    // Each match asks for its own session; a failed ask must not hand over the last match's TURN servers.
    s.iceJson = "[]";
    s.forceRelay = false;
    s.iceThread = std::thread([&s, uid = s.launch.uid] {
      // A fresh access token for the API (it lasts an hour), then the game's ICE session (CoturnService.java).
      const auto token = s.Tokens()();
      platform::http::Call call;
      call.url = s.auth.Endpoints().apiUrl + "/ice/session/game/" + uid;
      call.headers = "Accept: application/json\r\nAuthorization: Bearer " + (token ? *token : std::string()) + "\r\n";
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body); sent && status == 200) {
        if (const auto session = ParseJson(body)) {
          s.iceJson = body; // the game takes the session object as it is (docs/LAUNCHER_NATIVE_NETWORK.md)
          s.forceRelay = session->Bool("forceRelay");
        }
      } else {
        LogLine(
          ("no ICE session for game " + uid + " (" + std::to_string(status) + "); the game links without TURN").c_str()
        );
      }
      s.iceReady = true;
    });
  }

  /** On the main thread: the match's switches, its GPGNet side and replay relay, then FAF's GPGNet lobby. */
  void StartMatch(
    Service& s
  )
  {
    s.link = std::make_unique<GameLink>();
    s.link->SetLog(LogLine);
    const auto port = s.link->Listen();
    if (!port) {
      AbortMatch(s, port.error());
      return;
    }
    GameLinkSettings link;
    link.login = s.haveMe ? s.me.login : s.auth.UserName();
    link.playerId = s.haveMe ? std::atoi(s.me.id.c_str()) : 0;
    link.initMode = s.launch.initMode;
    link.iceServersJson = s.iceJson;
    s.link->Start(link, [&s](const JsonNode& message) {
      (void)s.lobby.Send(message);
    });
    s.lobby.SetGameHandler([game = s.link.get()](const JsonNode& message) {
      game->FromLobby(message);
    });

    s.relay = std::make_unique<ReplayRelay>();
    s.relay->SetLog(LogLine);
    const auto replayPort = s.relay->Listen();
    if (replayPort) {
      s.relay->Start(s.Tokens());
    }

    LaunchLocal local;
    local.gpgnetPort = *port;
    local.replayPort = replayPort ? *replayPort : 0;
    local.initFile = s.realInit;
    local.forceRelay = s.forceRelay;
    moho::CFG_SetLaunchArgs(BuildLaunchArgs(s.launch, s.haveMe ? &s.me : nullptr, local));

    // What StartGpgNetFromCommandLine does at startup (CScApp.cpp), now for this match.
    u_long address = 0;
    u_short gpgnetPort = 0;
    const std::string endpoint = "127.0.0.1:" + std::to_string(*port);
    if (!moho::NET_GetAddrInfo(endpoint.c_str(), 0, true, address, gpgnetPort)) {
      AbortMatch(s, "no address for the game's GPGNet");
      return;
    }
    try {
      moho::GPGNET_Attach(address, gpgnetPort);
    } catch (const std::exception& exception) {
      AbortMatch(s, std::string("GPGNet: ") + exception.what());
      return;
    }
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    moho::IUIManager* const ui = moho::UI_GetManager();
    if (state == nullptr || ui == nullptr || !ui->SetNewLuaState(state)) {
      AbortMatch(s, "the UI couldn't take the lobby");
      return;
    }
    // FAF's lobby reads its switches when it loads (lobby.lua's argv), so each match loads it again.
    (void)moho::SCR_LuaDoString(
      "if __modules then __modules['/lua/ui/lobby/lobby.lua'] = nil __modules['/lua/ui/lobby/autolobby.lua'] = nil "
      "__modules['/lua/multiplayer/gpgnet.lua'] = nil end",
      state
    );
    if (!moho::SCR_LuaDoString("import('/lua/multiplayer/gpgnet.lua').CreateUI()", state)) {
      AbortMatch(s, "FAF's lobby didn't start");
      return;
    }
    s.match = MatchState::Running;
    s.matchMessage = "In the game";
    LogLine(("match " + s.launch.uid + " started in this process").c_str());
  }

  /** On the main thread, once no session runs: the match's pieces go, and the launcher opens again. */
  void FinishMatch(
    Service& s
  )
  {
    s.lobby.SetGameHandler({});
    SendGameEnded(s);
    moho::GPGNET_Shutdown();
    moho::CFG_ClearLaunchArgs();
    if (s.link) {
      s.link->Stop();
      s.link.reset();
    }
    if (s.relay) {
      s.finishingRelay = std::move(s.relay); // its last bytes go out while the launcher runs
      s.finishingSince = std::chrono::steady_clock::now();
    }
    s.match = MatchState::Idle;
    s.matchMessage.clear();
    LogLine(("match " + s.launch.uid + " ended; back to the launcher").c_str());
    if (s.endedFromLobby) {
      (void)moho::UI_StartFrontEnd(); // after a game the session's end opened the front end already
    } else {
      // FAF's way out of a game (EscapeHandler.SafeQuit: the score screen, the game menu) stops drawing the world and
      // the UI before it quits, as the process ends there; here the launcher comes next, so both draw again (their
      // defaults).
      moho::CON_Execute("ren_Oblivion false");
      moho::CON_Execute("ren_Ui true");
    }
  }

  // --- Lua ---------------------------------------------------------------------------------------------------------

  void SetField(
    lua_State* const L,
    const char* const key,
    const std::string& value
  )
  {
    lua_pushstring(L, key);
    lua_pushstring(L, value.c_str());
    lua_rawset(L, -3);
  }

  void SetField(
    lua_State* const L,
    const char* const key,
    const double value
  )
  {
    lua_pushstring(L, key);
    lua_pushnumber(L, static_cast<lua_Number>(value));
    lua_rawset(L, -3);
  }

  void SetBool(
    lua_State* const L,
    const char* const key,
    const bool value
  )
  {
    lua_pushstring(L, key);
    lua_pushboolean(L, value ? 1 : 0);
    lua_rawset(L, -3);
  }

  std::string TableString(
    lua_State* const L,
    const int table,
    const char* const key
  )
  {
    lua_pushstring(L, key);
    lua_gettable(L, table);
    const char* const text = lua_isstring(L, -1) ? lua_tostring(L, -1) : nullptr;
    std::string out = text != nullptr ? text : "";
    lua_pop(L, 1);
    return out;
  }

  std::optional<double> TableNumber(
    lua_State* const L,
    const int table,
    const char* const key
  )
  {
    lua_pushstring(L, key);
    lua_gettable(L, table);
    std::optional<double> out;
    if (lua_isnumber(L, -1)) {
      out = static_cast<double>(lua_tonumber(L, -1));
    }
    lua_pop(L, 1);
    return out;
  }

  bool TableBool(
    lua_State* const L,
    const int table,
    const char* const key
  )
  {
    lua_pushstring(L, key);
    lua_gettable(L, table);
    const bool out = lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    return out;
  }

  /** The featured mod whose files this process has mounted (`/init init_<mod>.lua`); empty when it wasn't started on
   * one of FAF's init files. */
  std::string LoadedFeaturedMod(
    const Service& s
  )
  {
    const std::string name = Lower(std::filesystem::path(s.realInit).filename().string());
    if (!name.starts_with("init_") || !name.ends_with(".lua") || name.size() <= 9) {
      return {};
    }
    return name.substr(5, name.size() - 9);
  }

  /** Host and join only on the featured mod already loaded: another one needs the game's files swapped (WP8), and
   * until then a game on it would start on the wrong files. */
  std::expected<void, std::string> CheckFeaturedMod(
    const Service& s,
    const std::string& featuredMod
  )
  {
    const std::string loaded = LoadedFeaturedMod(s);
    if (loaded.empty()) {
      return std::unexpected(std::string("this game wasn't started on FAF's game files (/init init_faf.lua)"));
    }
    if (!featuredMod.empty() && Lower(featuredMod) != loaded) {
      return std::unexpected(
        "this needs FAF's " + featuredMod + " files; the game runs " + loaded +
        " (the launcher starts the game again on them)"
      );
    }
    return {};
  }

  const char* AuthStateName(
    const FafAuth::State state
  )
  {
    switch (state) {
    case FafAuth::State::LoggedOut:
      return "signedout";
    case FafAuth::State::Working:
      return "working";
    case FafAuth::State::WaitingForApproval:
      return "waiting";
    case FafAuth::State::LoggedIn:
      return "signedin";
    }
    return "signedout";
  }

  const char* LobbyStateName(
    const FafLobby::State state
  )
  {
    switch (state) {
    case FafLobby::State::Disconnected:
      return "off";
    case FafLobby::State::Connecting:
      return "connecting";
    case FafLobby::State::SignedIn:
      return "signedin";
    case FafLobby::State::Failed:
      return "failed";
    }
    return "off";
  }

  const char* ControlStateName(ControlServiceClient::State state);

  /** Hands the sign-in page to the browser on a thread of its own and logs how that went (the page holds the code). */
  void OpenSignInPage(
    Service& s
  )
  {
    const std::string url = s.auth.VerifyUrl();
    if (url.empty()) {
      return;
    }
    const std::shared_ptr<Service::PageOpen> shared = s.pageOpen;
    {
      std::lock_guard<std::mutex> lock(shared->lock);
      shared->state = "opening";
    }
    LogLine("opening FAF's sign-in page in the browser");
    std::thread([shared, url] {
      const auto opened = platform::process::OpenInBrowser(url);
      const std::string state = opened ? std::string("opened") : opened.error();
      LogLine(opened ? "the browser took FAF's sign-in page" : ("the sign-in page didn't open: " + state).c_str());
      std::lock_guard<std::mutex> lock(shared->lock);
      shared->state = state;
    }).detach();
  }

  /** table FafOnline_Status(): signIn, message, code, url, pageOpen, secondsLeft, login; lobby, lobbyMessage, notice;
   * match, matchMessage; loadedMod; servers, serversMessage, serverCount (our control services). */
  int StatusBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    lua_newtable(L);
    SetField(L, "signIn", s.SignedIn() ? "signedin" : AuthStateName(s.auth.GetState()));
    SetField(L, "message", s.auth.Message());
    SetField(L, "code", s.auth.UserCode());
    SetField(L, "url", s.auth.VerifyUrl());
    {
      std::lock_guard<std::mutex> lock(s.pageOpen->lock);
      SetField(L, "pageOpen", s.pageOpen->state);
    }
    SetField(L, "secondsLeft", static_cast<double>(s.auth.SecondsLeft()));
    SetField(L, "login", s.haveMe ? s.me.login : s.auth.UserName());
    SetField(L, "lobby", LobbyStateName(s.lobby.GetState()));
    SetField(L, "lobbyMessage", s.lobby.Message());
    double retryIn = 0;
    if (s.lobbyRetryAt != std::chrono::steady_clock::time_point{}) {
      retryIn = std::max(0.0, std::chrono::duration<double>(s.lobbyRetryAt - std::chrono::steady_clock::now()).count());
    }
    SetField(L, "lobbyRetryIn", std::ceil(retryIn)); // seconds to the next try after a failure; 0: none planned
    SetField(L, "notice", s.notice);
    SetField(L, "match", MatchStateName(s.match));
    // The FAF game the match is (its uid in FafOnline_Games), for the lobby screen's title and rules.
    SetField(L, "matchGame", s.match == MatchState::Idle ? std::string() : s.launch.uid);
    SetField(L, "matchMessage", s.matchMessage);
    SetField(L, "loadedMod", LoadedFeaturedMod(s));
    // Our control services: how many, and the worst state among them (off, connecting, failed, live).
    std::string servers = s.controls.empty() ? "none" : "live";
    std::string serversMessage;
    for (const auto& control : s.controls) {
      const auto state = control->GetState();
      if (state != ControlServiceClient::State::Live) {
        servers = ControlStateName(state);
        serversMessage = control->Address() + ": " + control->Message();
      }
    }
    SetField(L, "servers", servers);
    SetField(L, "serversMessage", serversMessage);
    SetField(L, "serverCount", static_cast<double>(s.controls.size()));
    return 1;
  }

  int SignInBody(
    lua_State* const L
  )
  {
    (void)L;
    TheService().auth.StartLogin();
    return 0;
  }

  int CancelSignInBody(
    lua_State* const L
  )
  {
    (void)L;
    TheService().auth.CancelLogin();
    return 0;
  }

  int SignOutBody(
    lua_State* const L
  )
  {
    (void)L;
    Service& s = TheService();
    s.lobby.Disconnect();
    s.lobbyStarted = false;
    s.lobbyRetryAt = {};
    s.lobbyFailures = 0;
    s.haveMe = false;
    s.auth.Logout();
    return 0;
  }

  /** Connects to FAF's lobby again after it failed (its last message stays until the new try reports). */
  void RetryLobby(
    Service& s
  )
  {
    s.lobbyRetryAt = {};
    LogLine("trying FAF's lobby again");
    s.lobby.Connect(s.Tokens());
  }

  /** ok = FafOnline_RetryLobby(): connects to FAF's lobby again now, when it failed. */
  int RetryLobbyBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const bool retry = s.lobbyStarted && s.lobby.GetState() == FafLobby::State::Failed;
    if (retry) {
      RetryLobby(s);
    }
    lua_pushboolean(L, retry ? 1 : 0);
    return 1;
  }

  /** FafOnline_OpenSignInPage(): hands the sign-in page to the browser again (the engine opens it once by itself). */
  int OpenSignInPageBody(
    lua_State* const L
  )
  {
    (void)L;
    OpenSignInPage(TheService());
    return 0;
  }

  /** table FafOnline_Games(): FAF's open and running games, each a table. */
  int GamesBody(
    lua_State* const L
  )
  {
    lua_newtable(L);
    int index = 1;
    for (const FafGame& game : TheService().lobby.Games()) {
      lua_newtable(L);
      SetField(L, "uid", game.uid);
      SetField(L, "title", game.title);
      SetField(L, "host", game.host);
      SetField(L, "map", game.mapname);
      SetField(L, "featuredMod", game.featuredMod);
      SetField(L, "state", game.state);
      SetField(L, "visibility", game.visibility);
      SetField(L, "ratingType", game.ratingType);
      SetField(L, "gameType", game.gameType);
      SetField(L, "players", static_cast<double>(game.numPlayers));
      SetField(L, "maxPlayers", static_cast<double>(game.maxPlayers));
      SetField(L, "simMods", static_cast<double>(game.simMods.size()));
      SetBool(L, "password", game.passwordProtected);
      SetBool(L, "enforceRating", game.enforceRatingRange);
      // teams = { {team = "2", players = { {login, rating, country, clan}, ... }}, ... }; rating is what FAF shows
      // (mean - 3 deviations) for the game's rating type, or nil when the lobby didn't say.
      lua_pushstring(L, "teams");
      lua_newtable(L);
      int teamIndex = 1;
      for (const auto& [team, logins] : game.teams) {
        lua_newtable(L);
        SetField(L, "team", team);
        lua_pushstring(L, "players");
        lua_newtable(L);
        int playerIndex = 1;
        for (const std::string& login : logins) {
          lua_newtable(L);
          SetField(L, "login", login);
          if (const auto player = TheService().players.find(login); player != TheService().players.end()) {
            SetField(L, "country", player->second.country);
            SetField(L, "clan", player->second.clan);
            const auto rating = player->second.ratings.find(game.ratingType.empty() ? "global" : game.ratingType);
            if (rating != player->second.ratings.end()) {
              SetField(L, "rating", rating->second.mean - 3.0 * rating->second.deviation);
              SetField(L, "games", static_cast<double>(rating->second.games));
            }
          }
          lua_rawseti(L, -2, playerIndex++);
        }
        lua_rawset(L, -3);
        lua_rawseti(L, -2, teamIndex++);
      }
      lua_rawset(L, -3);
      if (game.ratingMin) {
        SetField(L, "ratingMin", *game.ratingMin);
      }
      if (game.ratingMax) {
        SetField(L, "ratingMax", *game.ratingMax);
      }
      lua_rawseti(L, -2, index++);
    }
    return 1;
  }

  void PushResult(lua_State* L, const std::expected<void, std::string>& result);

  /** The switch a restart on another featured mod adds, so the new start takes up what the launcher was doing. */
  constexpr const char* kResumeArg = "/fafre_resume";

  /** What the launcher was doing when it restarted the game (DataFolder, next to the sign-in). */
  std::filesystem::path ResumeFile()
  {
    return DataFolder() / "resume.json";
  }

  /** The init file of `featuredMod` next to the one this game runs on, where FAF's client keeps them. */
  std::filesystem::path FeaturedModInit(
    const Service& s,
    const std::string& featuredMod
  )
  {
    return std::filesystem::path(s.realInit).parent_path() / ("init_" + Lower(featuredMod) + ".lua");
  }

  /**
   * Whether the game can play on `featuredMod`: the one it runs on now, or one whose init file sits next to it, which
   * a restart loads (FAF's client writes it the first time it starts a game on that featured mod).
   */
  std::expected<void, std::string> FeaturedModFiles(
    const Service& s,
    const std::string& featuredMod
  )
  {
    const std::string mod = Lower(featuredMod);
    if (mod.empty() || mod.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos) {
      return std::unexpected("not a featured mod: " + featuredMod);
    }
    const std::string loaded = LoadedFeaturedMod(s);
    if (loaded.empty()) {
      return std::unexpected(std::string("this game wasn't started on FAF's game files (/init init_faf.lua)"));
    }
    if (mod == loaded) {
      return {};
    }
    std::error_code missing;
    if (!std::filesystem::exists(FeaturedModInit(s, mod), missing)) {
      return std::unexpected(
        std::string(
          "its game files aren't on this computer yet (FAF's client gets them the first time it starts a "
          "game on it)"
        )
      );
    }
    return {};
  }

  /** ok, why = FafOnline_FeaturedModFiles(mod): whether the game can play on that featured mod (a restart, or none). */
  int FeaturedModFilesBody(
    lua_State* const L
  )
  {
    const std::string mod = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    PushResult(L, FeaturedModFiles(TheService(), mod));
    return 2;
  }

  /**
   * ok, why = FafOnline_RestartOn(mod, action): starts the game again on `mod`'s files, with what the launcher does
   * next (`action`: its string, number and boolean fields, such as a host request) kept for the new start; the
   * launcher then quits this one. Until the game swaps its files while running (plan WP8), this is how it changes
   * featured mod.
   */
  int RestartOnBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string mod = lua_isstring(L, 1) ? Lower(lua_tostring(L, 1)) : std::string();
    if (!lua_istable(L, 2)) {
      PushResult(L, std::unexpected(std::string("FafOnline_RestartOn takes the featured mod and a table")));
      return 2;
    }
    if (const auto files = FeaturedModFiles(s, mod); !files) {
      PushResult(L, files);
      return 2;
    }
    if (s.match != MatchState::Idle && s.match != MatchState::Failed) {
      PushResult(L, std::unexpected(std::string("a match is starting or running")));
      return 2;
    }
    std::vector<std::pair<std::string, JsonNode>> fields;
    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
      if (lua_type(L, -2) == LUA_TSTRING) { // a number key would be turned into a string in place and break lua_next
        const std::string key = lua_tostring(L, -2);
        switch (lua_type(L, -1)) {
        case LUA_TSTRING:
          fields.emplace_back(key, JsonString(lua_tostring(L, -1)));
          break;
        case LUA_TNUMBER:
          fields.emplace_back(key, JsonNumber(lua_tonumber(L, -1)));
          break;
        case LUA_TBOOLEAN:
          fields.emplace_back(key, JsonBool(lua_toboolean(L, -1) != 0));
          break;
        default:
          break;
        }
      }
      lua_pop(L, 1);
    }
    const double written = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string text = ToJson(JsonObject({
      {"mod", JsonString(mod)},
      {"written", JsonNumber(written)},
      {"action", JsonObject(std::move(fields))},
    }));
    {
      std::ofstream out(ResumeFile(), std::ios::binary | std::ios::trunc);
      out << text;
      if (!out) {
        PushResult(L, std::unexpected("can't write " + ResumeFile().string()));
        return 2;
      }
    }
    const auto program = platform::process::CurrentProgram();
    if (!program) {
      std::error_code ignored;
      std::filesystem::remove(ResumeFile(), ignored);
      PushResult(L, std::unexpected(program.error()));
      return 2;
    }
    // The same switches, with the other init file, and the resume switch once.
    std::vector<std::string> args;
    const std::vector<std::string> current = platform::process::CurrentArgs();
    for (std::size_t i = 0; i < current.size(); ++i) {
      const std::string name = Lower(current[i]);
      if (name == "/init") {
        ++i; // and its file
      } else if (name == "/log" && i + 1 < current.size()) {
        // Its own log beside this one's (game.log -> game.fafdevelop.log): the same file would be emptied.
        std::filesystem::path log = current[++i];
        log.replace_extension("." + mod + log.extension().string());
        args.push_back(current[i - 1]);
        args.push_back(log.string());
      } else if (name != kResumeArg) {
        args.push_back(current[i]);
      }
    }
    const std::string init = FeaturedModInit(s, mod).string();
    args.push_back("/init");
    args.push_back(init);
    args.push_back(kResumeArg);
    LogLine(("starting the game again on " + mod + "'s files (" + init + ")").c_str());
    if (const auto started = platform::process::Start(*program, args); !started) {
      std::error_code ignored;
      std::filesystem::remove(ResumeFile(), ignored);
      PushResult(L, started);
      return 2;
    }
    PushResult(L, {});
    return 2;
  }

  /**
   * table|nil FafOnline_TakeResume(): what the launcher was doing when it started this game again on its featured
   * mod (RestartOn), once: the file goes. Nothing on a start without /fafre_resume, for another featured mod, or
   * from more than 5 minutes ago.
   */
  int TakeResumeBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    // Once per start: the launcher is made again after each match, with nothing left to resume.
    static bool taken = false;
    if (taken || !moho::CFG_GetArgOption(kResumeArg, 0, nullptr)) {
      lua_pushnil(L);
      return 1;
    }
    taken = true;
    std::string text;
    {
      std::ifstream in(ResumeFile(), std::ios::binary);
      text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::error_code ignored;
    std::filesystem::remove(ResumeFile(), ignored);
    const auto resume = ParseJson(text);
    const double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
    const JsonNode* const action = resume ? resume->Get("action") : nullptr;
    if (!resume || action == nullptr || action->kind != JsonNode::Kind::Object) {
      LogLine("started to resume, but there is nothing to resume");
      lua_pushnil(L);
      return 1;
    }
    if (resume->String("mod") != LoadedFeaturedMod(s) || now - resume->Number("written") > 300.0) {
      LogLine(("a resume for " + resume->String("mod") + " doesn't fit this start; dropped").c_str());
      lua_pushnil(L);
      return 1;
    }
    lua_newtable(L);
    for (const auto& [key, value] : action->members) {
      switch (value.kind) {
      case JsonNode::Kind::String:
        SetField(L, key.c_str(), value.text);
        break;
      case JsonNode::Kind::Number:
        SetField(L, key.c_str(), value.number);
        break;
      case JsonNode::Kind::Bool:
        SetBool(L, key.c_str(), value.boolean);
        break;
      default:
        break;
      }
    }
    LogLine(("resuming on " + resume->String("mod") + ": " + action->String("kind")).c_str());
    return 1;
  }

  const char* ControlStateName(
    const ControlServiceClient::State state
  )
  {
    switch (state) {
    case ControlServiceClient::State::Stopped:
      return "off";
    case ControlServiceClient::State::Connecting:
      return "connecting";
    case ControlServiceClient::State::Live:
      return "live";
    case ControlServiceClient::State::Failed:
      return "failed";
    }
    return "off";
  }

  /** Why this build can't join a game on our servers from the launcher yet. */
  const char* ServerJoinUnavailable()
  {
#if FAF_SERVER_MODE
    // A server session lives until the process ends (remote/client/ServerConnect.cpp): it has no end that returns
    // to the launcher yet.
    return "Joining a server game from the launcher comes later: a server game can't hand back to the launcher yet.";
#else
    return "This build of the game can't play on our servers (it was built without server mode).";
#endif
  }

  /**
   * table FafOnline_ServerGames(): the lobbies of our control services, each a table: key, host, name, state, kind,
   * origin, tournament, map, service, humans, humanSeats, aiSeats, openSeats, seated (the player has a seat), stale,
   * joinable, why. Join and watch lines are the player's credentials and stay here.
   */
  int ServerGamesBody(
    lua_State* const L
  )
  {
    lua_newtable(L);
    int index = 1;
    for (const auto& control : TheService().controls) {
      for (const ServerLobby& lobby : control->Lobbies()) {
        int humans = 0;
        int humanSeats = 0;
        int aiSeats = 0;
        int openSeats = 0;
        for (const ServerSeat& seat : lobby.seats) {
          if (seat.kind == "ai") {
            ++aiSeats;
          } else {
            ++humanSeats;
            if (seat.uid.empty()) {
              ++openSeats;
            } else {
              ++humans;
            }
          }
        }
        lua_newtable(L);
        SetField(L, "key", lobby.key);
        SetField(L, "host", lobby.host);
        SetField(L, "name", lobby.name);
        SetField(L, "state", lobby.state);
        SetField(L, "kind", lobby.kind);
        SetField(L, "origin", lobby.origin);
        SetField(L, "tournament", lobby.tournament);
        SetField(L, "map", lobby.map);
        SetField(L, "service", control->Address());
        SetField(L, "humans", static_cast<double>(humans));
        SetField(L, "humanSeats", static_cast<double>(humanSeats));
        SetField(L, "aiSeats", static_cast<double>(aiSeats));
        SetField(L, "openSeats", static_cast<double>(openSeats));
        SetBool(L, "seated", !lobby.join.empty());
        SetBool(L, "stale", lobby.stale);
        SetBool(L, "joinable", false);
        SetField(L, "why", ServerJoinUnavailable());
        lua_rawseti(L, -2, index++);
      }
    }
    return 1;
  }

  /** ok, why = FafOnline_JoinServer(key): refused until a server game can hand back to the launcher. */
  int JoinServerBody(
    lua_State* const L
  )
  {
    PushResult(L, std::unexpected(std::string(ServerJoinUnavailable())));
    return 2;
  }

  void PushResult(
    lua_State* const L,
    const std::expected<void, std::string>& result
  )
  {
    lua_pushboolean(L, result ? 1 : 0);
    if (result) {
      lua_pushnil(L);
    } else {
      lua_pushstring(L, result.error().c_str());
    }
  }

  /** ok, why = FafOnline_Join(uid[, password]) */
  int JoinBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const char* const uid = lua_isstring(L, 1) ? lua_tostring(L, 1) : nullptr;
    const char* const password = lua_gettop(L) >= 2 && lua_isstring(L, 2) ? lua_tostring(L, 2) : nullptr;
    if (uid == nullptr) {
      PushResult(L, std::unexpected(std::string("FafOnline_Join needs the game's uid")));
    } else if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      PushResult(L, std::unexpected(std::string("not in FAF's lobby")));
    } else if (s.match != MatchState::Idle && s.match != MatchState::Failed) {
      PushResult(L, std::unexpected(std::string("a match is already starting or running")));
    } else {
      std::string featuredMod;
      for (const FafGame& game : s.lobby.Games()) {
        if (game.uid == uid) {
          featuredMod = game.featuredMod;
        }
      }
      if (const auto usable = CheckFeaturedMod(s, featuredMod); !usable) {
        PushResult(L, usable);
      } else {
        PushResult(L, s.lobby.JoinGame(uid, password != nullptr ? password : ""));
      }
    }
    return 2;
  }

  /** ok, why = FafOnline_Host{title=, map=, mod=, password=, visibility=} */
  int HostBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    if (!lua_istable(L, 1)) {
      PushResult(L, std::unexpected(std::string("FafOnline_Host takes a table")));
      return 2;
    }
    FafHostRequest request;
    request.title = TableString(L, 1, "title");
    request.mapname = TableString(L, 1, "map");
    if (const std::string mod = TableString(L, 1, "mod"); !mod.empty()) {
      request.featuredMod = mod;
    }
    if (const std::string visibility = TableString(L, 1, "visibility"); !visibility.empty()) {
      request.visibility = visibility;
    }
    request.password = TableString(L, 1, "password");
    request.ratingMin = TableNumber(L, 1, "ratingMin");
    request.ratingMax = TableNumber(L, 1, "ratingMax");
    request.enforceRatingRange = TableBool(L, 1, "enforceRating");
    if (request.mapname.empty()) {
      PushResult(L, std::unexpected(std::string("no map")));
    } else if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      PushResult(L, std::unexpected(std::string("not in FAF's lobby")));
    } else if (s.match != MatchState::Idle && s.match != MatchState::Failed) {
      PushResult(L, std::unexpected(std::string("a match is already starting or running")));
    } else if (const auto usable = CheckFeaturedMod(s, request.featuredMod); !usable) {
      PushResult(L, usable);
    } else {
      PushResult(L, s.lobby.HostGame(request));
    }
    return 2;
  }

  template <int (*Body)(lua_State*)>
  int Binding(
    lua_State* const luaContext
  )
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    return state != nullptr && state->m_state != nullptr ? Body(state->m_state) : 0;
  }

  void RegisterOnlineBindings()
  {
    using moho::CScrLuaBinder;
    static CScrLuaBinder status(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Status",
      &Binding<&StatusBody>,
      nullptr,
      "<global>",
      "table FafOnline_Status() - the in-game launcher's FAF sign-in, lobby and match state. Absent on the original "
      "executable."
    );
    static CScrLuaBinder signIn(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_SignIn",
      &Binding<&SignInBody>,
      nullptr,
      "<global>",
      "FafOnline_SignIn() - starts FAF's sign-in by device code."
    );
    static CScrLuaBinder cancel(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_CancelSignIn",
      &Binding<&CancelSignInBody>,
      nullptr,
      "<global>",
      "FafOnline_CancelSignIn() - stops waiting for the browser's approval."
    );
    static CScrLuaBinder signOut(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_SignOut",
      &Binding<&SignOutBody>,
      nullptr,
      "<global>",
      "FafOnline_SignOut() - leaves FAF's lobby and forgets the kept sign-in."
    );
    static CScrLuaBinder page(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_OpenSignInPage",
      &Binding<&OpenSignInPageBody>,
      nullptr,
      "<global>",
      "FafOnline_OpenSignInPage() - hands FAF's sign-in page to the browser (again)."
    );
    static CScrLuaBinder featuredModFiles(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_FeaturedModFiles",
      &Binding<&FeaturedModFilesBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_FeaturedModFiles(mod) - whether the game can play on that featured mod (with a restart)."
    );
    static CScrLuaBinder restartOn(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_RestartOn",
      &Binding<&RestartOnBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_RestartOn(mod, action) - starts the game again on that featured mod's files, with "
      "the action for the new start; quit this one after."
    );
    static CScrLuaBinder takeResume(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_TakeResume",
      &Binding<&TakeResumeBody>,
      nullptr,
      "<global>",
      "table FafOnline_TakeResume() - what to do after a restart on another featured mod (once), or nil."
    );
    static CScrLuaBinder retryLobby(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_RetryLobby",
      &Binding<&RetryLobbyBody>,
      nullptr,
      "<global>",
      "bool FafOnline_RetryLobby() - connects to FAF's lobby again now, when the connection failed."
    );
    static CScrLuaBinder games(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Games",
      &Binding<&GamesBody>,
      nullptr,
      "<global>",
      "table FafOnline_Games() - FAF's open and running games."
    );
    static CScrLuaBinder join(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Join",
      &Binding<&JoinBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_Join(uid, [password]) - asks FAF to join that game; the match starts in this game."
    );
    static CScrLuaBinder serverGames(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_ServerGames",
      &Binding<&ServerGamesBody>,
      nullptr,
      "<global>",
      "table FafOnline_ServerGames() - the games on our servers, from the control services in control-services.txt."
    );
    static CScrLuaBinder joinServer(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_JoinServer",
      &Binding<&JoinServerBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_JoinServer(key) - joins a game on our servers (not yet: says why)."
    );
    static CScrLuaBinder host(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Host",
      &Binding<&HostBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_Host{title, map, mod, password, visibility, ratingMin, ratingMax, enforceRating} - hosts "
      "a P2P game on FAF."
    );
  }

  struct OnlineLuaFuncDefBootstrap
  {
    OnlineLuaFuncDefBootstrap()
    {
      RegisterOnlineBindings();
    }
  };

  OnlineLuaFuncDefBootstrap gOnlineLuaFuncDefBootstrap;
} // namespace

void moho::ONLINE_Frame()
{
  // FAF_ONLINE_AUTOTEST=screens (a test hook): the launcher walks through every screen it opens and back, then quits
  // (launcher.lua TestWalk, which runs once per Lua state).
  static const bool screensTest = TestSetting("FAF_ONLINE_AUTOTEST") == "screens";
  if (screensTest && moho::WLD_GetActiveSession() == nullptr) {
    static auto nextTry = std::chrono::steady_clock::now();
    if (const auto now = std::chrono::steady_clock::now(); now >= nextTry) {
      nextTry = now + std::chrono::seconds(2);
      if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
        (void)moho::SCR_LuaDoString(
          "local launcher = __modules and __modules['/fafengine/modules/lua/ui/launcher/launcher.lua'] "
          "if launcher and launcher.TestWalk then launcher.TestWalk() end",
          state
        );
      }
    }
  }
  if (!gService) {
    // An autotest (a test hook) starts the service on its own, as the launcher's screen would.
    static const bool autotest = TestSetting("FAF_ONLINE_AUTOTEST").starts_with("host:") ||
      TestSetting("FAF_ONLINE_AUTOTEST").starts_with("join:");
    if (!autotest || moho::USER_GetLuaState() == nullptr) {
      return;
    }
    (void)TheService();
  }
  Service& s = *gService;
  // The sign-in's code came: its page goes to the browser (not through Lua's OpenURL, which only opens what the init
  // file's protocol list allows, from the game's thread).
  if (s.auth.TakeOpenPage()) {
    OpenSignInPage(s);
  }
  // Signed in: into FAF's lobby and our control services' event streams; signed out: out of them.
  if (s.SignedIn() && !s.lobbyStarted) {
    s.lobby.Connect(s.Tokens());
    s.lobbyStarted = true;
    for (const std::string& address : ControlServiceAddresses()) {
      auto control =
        std::make_unique<ControlServiceClient>(address, std::string("faf-re-client/") + gpg::diag::BuildVersion());
      control->SetLog(LogLine);
      control->SetTokens(s.Tokens());
      control->Start();
      LogLine(("control service " + address + ": following its lobbies").c_str());
      s.controls.push_back(std::move(control));
    }
  } else if (!s.SignedIn() && s.auth.GetState() == FafAuth::State::LoggedOut && s.lobbyStarted) {
    s.lobby.Disconnect();
    s.lobbyStarted = false;
    s.lobbyRetryAt = {};
    s.lobbyFailures = 0;
    for (const auto& control : s.controls) {
      control->Stop();
    }
    s.controls.clear();
  }
  // FAF's lobby dropped or never answered: tried again by itself, 5 s after the first failure, the wait doubling up
  // to 80 s, as the official client reconnects. Not while a match starts or runs: its game messages use this
  // connection, and a new one would be a second session in FAF's eyes.
  if (
    s.lobbyStarted && s.lobby.GetState() == FafLobby::State::Failed &&
    (s.match == MatchState::Idle || s.match == MatchState::Failed)
  ) {
    const auto now = std::chrono::steady_clock::now();
    if (s.lobbyRetryAt == std::chrono::steady_clock::time_point{}) {
      s.lobbyRetryAt = now + std::chrono::seconds(5 << std::min(s.lobbyFailures, 4));
      ++s.lobbyFailures;
    } else if (now >= s.lobbyRetryAt) {
      RetryLobby(s);
    }
  } else if (s.lobby.GetState() == FafLobby::State::SignedIn) {
    s.lobbyFailures = 0;
  }
  for (const JsonNode& message : s.lobby.TakeMessages()) {
    const std::string command = message.String("command");
    if (command == "welcome") {
      if (const JsonNode* const me = message.Get("me")) {
        s.me = ReadLaunchPlayer(*me);
        s.haveMe = true;
      }
    } else if (command == "player_info") {
      if (
        const JsonNode* const players = message.Get("players");
        players != nullptr && players->kind == JsonNode::Kind::Array
      ) {
        for (const JsonNode& player : players->items) {
          LaunchPlayer record = ReadLaunchPlayer(player);
          if (record.login == s.me.login) {
            s.me = record; // the ratings after a game
          }
          if (!record.login.empty()) {
            s.players[record.login] = std::move(record);
          }
        }
      }
    } else if (command == "notice") {
      s.notice = message.String("text");
    } else if (command == "game_launch") {
      BeginLaunch(s, message);
    }
  }
  if (s.match == MatchState::Preparing && s.iceReady.load()) {
    if (s.iceThread.joinable()) {
      s.iceThread.join();
    }
    StartMatch(s);
  }
  if (s.match == MatchState::Ending && moho::WLD_GetActiveSession() == nullptr) {
    FinishMatch(s);
  }
  if (!s.autotestMap.empty()) {
    const auto now = std::chrono::steady_clock::now();
    if (s.autotestStep == 0 && s.autotestJoin) {
      // The launcher's own Join on the first open game it lists (launcher.lua TestJoin), tried every 2 s.
      if (s.match != MatchState::Idle) {
        s.autotestStep = 1;
      } else if (now - s.autotestSince > std::chrono::seconds(2)) {
        s.autotestSince = now;
        if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
          (void)moho::SCR_LuaDoString(
            "local launcher = __modules and __modules['/fafengine/modules/lua/ui/launcher/launcher.lua'] "
            "if launcher and launcher.TestJoin then launcher.TestJoin() end",
            state
          );
        }
      }
    } else if (s.autotestStep == 0 && s.lobby.GetState() == FafLobby::State::SignedIn) {
      FafHostRequest request;
      request.title = "faf-re in-game launcher test";
      request.mapname = s.autotestMap;
      if (const std::string loaded = LoadedFeaturedMod(s); !loaded.empty()) {
        request.featuredMod = loaded; // on the featured mod this test client runs
      }
      const auto sent = s.lobby.HostGame(request);
      LogLine(sent ? "autotest: game_host sent" : ("autotest: game_host failed: " + sent.error()).c_str());
      s.autotestStep = 1;
    } else if (s.autotestStep == 1 && s.match == MatchState::Running) {
      s.autotestStep = 2;
      s.autotestSince = now;
    } else if (s.autotestStep == 2 && s.autotestGame && now - s.autotestSince > std::chrono::seconds(8)) {
      // A game: the host presses Launch in FAF's lobby (the engine's lobby hook, data/fafengine).
      LogLine("autotest: pressing Launch in FAF's lobby");
      if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
        (void)moho::SCR_LuaDoString(
          "local lobby = __modules and __modules['/lua/ui/lobby/lobby.lua'] "
          "LOG('ONLINE: autotest: Launch pressed: ' .. tostring(lobby and lobby.FafReTestPressLaunch and "
          "lobby.FafReTestPressLaunch()))",
          state
        );
      }
      s.autotestStep = 5;
      s.autotestSince = now;
    } else if (s.autotestStep == 5 && moho::WLD_GetActiveSession() != nullptr) {
      LogLine("autotest: the game's session runs");
      s.autotestStep = 6;
      s.autotestSince = now;
    } else if (s.autotestStep == 5 && now - s.autotestSince > std::chrono::seconds(90)) {
      LogLine("autotest: no game session 90 s after Launch; pressing Exit in the lobby");
      s.autotestStep = 2;
      s.autotestGame = false;
      s.autotestSeconds = 0;
    } else if (s.autotestStep == 6 && now - s.autotestSince > std::chrono::seconds(s.autotestSeconds)) {
      // What the score screen's Continue and the game menu's exit call with /gpgnet (FAF score.lua, tabs.lua).
      LogLine("autotest: leaving the game as the score screen does (EscapeHandler.SafeQuit)");
      if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
        (void)moho::SCR_LuaDoString("import('/lua/ui/dialogs/eschandler.lua').SafeQuit()", state);
      }
      s.autotestStep = 3;
      s.autotestSince = now;
    } else if (
      s.autotestStep == 2 && !s.autotestGame && now - s.autotestSince > std::chrono::seconds(s.autotestSeconds)
    ) {
      LogLine("autotest: pressing Exit (ExitApplication)");
      if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
        (void)moho::SCR_LuaDoString("ExitApplication()", state);
      }
      s.autotestStep = 3;
      s.autotestSince = now;
    } else if (s.autotestStep == 3 && s.match == MatchState::Idle && now - s.autotestSince > std::chrono::seconds(8)) {
      LogLine("autotest: the game still runs 8 s after leaving, back in the launcher; quitting for real");
      s.autotestStep = 4;
      s.autotestMap.clear();
      if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
        (void)moho::SCR_LuaDoString("ExitApplication()", state); // no launcher match now: this one quits
      }
    } else if (s.autotestStep == 1 && s.match == MatchState::Failed) {
      LogLine(("autotest: the match failed: " + s.matchMessage).c_str());
      s.autotestStep = 4;
      s.autotestMap.clear();
    }
  }
  if (
    s.finishingRelay &&
    (s.finishingRelay->Finish(std::chrono::milliseconds(0)) ||
     std::chrono::steady_clock::now() - s.finishingSince > std::chrono::seconds(70))
  ) {
    s.finishingRelay->Stop();
    s.finishingRelay.reset();
  }
}

bool moho::ONLINE_ReturnToLauncherInsteadOfQuitting()
{
  if (!gService) {
    return false;
  }
  Service& s = *gService;
  if (s.match == MatchState::Ending) {
    return true; // FAF's lobby's own exit, from ReturnToMenu below
  }
  if (s.match != MatchState::Running) {
    return false;
  }
  s.match = MatchState::Ending;
  s.endedFromLobby = moho::WLD_GetActiveSession() == nullptr;
  if (!s.endedFromLobby) {
    // A game: its session ends as the engine ends any (the front end opens after it, and with it the launcher).
    moho::CON_Execute("quit"); // the console's quit: CON_WLD_RequestEndSession, the session only
  } else if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
    // FAF's lobby: its own way back (lobby.lua ReturnToMenu), which closes its connections.
    (void)moho::SCR_LuaDoString(
      "local lobby = __modules and __modules['/lua/ui/lobby/lobby.lua'] "
      "if lobby and lobby.ReturnToMenu then lobby.ReturnToMenu(false) end",
      state
    );
  }
  return true;
}

void moho::ONLINE_Shutdown()
{
  if (gService && gService->match != MatchState::Idle && gService->match != MatchState::Failed) {
    gService->lobby.SetGameHandler({});
    moho::CFG_ClearLaunchArgs();
  }
  gService.reset();
}
