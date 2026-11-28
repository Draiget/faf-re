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
#include <set>
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
#if FAF_SERVER_MODE
#include "moho/app/ServerLobbyUi.h"
#include "remote/client/ServerConnect.h"
#endif
#include "online/ControlService.h"
#include "online/FafAuth.h"
#include "online/FafChat.h"
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

  /**
   * One FAF server: the main one players use, or FAF's test server, with the addresses FAF's client config lists for
   * them (content.faforever.com/dfc-config.json). Each keeps its own sign-in (token file): an account and its tokens
   * on one are not the other's.
   */
  struct FafServer
  {
    const char* name; ///< "main" or "test", as FafOnline_SetServer takes it
    const char* title;
    const char* oauth;
    const char* api;
    const char* user;
    const char* content;
    const char* replay;
    const char* website; ///< FAF's website (its news posts)
    const char* chat;
    const char* tokenFile;
  };

  constexpr FafServer kServers[] = {
    {"main",
     "FAF",
     "https://hydra.faforever.com",
     "https://api.faforever.com",
     "https://user.faforever.com",
     "https://content.faforever.com",
     "https://replay.faforever.com",
     "https://direct.faforever.com",
     "wss://chat.faforever.com",
     "game.token"},
    {"test",
     "FAF test server",
     "https://hydra.faforever.xyz",
     "https://api.faforever.xyz",
     "https://user.faforever.xyz",
     "https://content.faforever.xyz",
     "https://replay.faforever.xyz",
     "https://direct.faforever.xyz",
     "wss://chat.faforever.xyz",
     "game-test.token"},
  };

  std::string gServerName; ///< the chosen server's name, read from server.txt on first use (main thread)

  /** The server the player chose (server.txt in the data folder; the main one when there is none). */
  const FafServer& CurrentServer()
  {
    if (gServerName.empty()) {
      std::ifstream in(DataFolder() / "server.txt", std::ios::binary);
      std::getline(in, gServerName);
      while (!gServerName.empty() && (gServerName.back() == '\r' || gServerName.back() == ' ')) {
        gServerName.pop_back();
      }
      if (gServerName.empty()) {
        gServerName = "main";
      }
    }
    for (const FafServer& server : kServers) {
      if (gServerName == server.name) {
        return server;
      }
    }
    return kServers[0];
  }

  FafEndpoints GameEndpoints()
  {
    FafEndpoints endpoints;
    endpoints.oauthUrl = CurrentServer().oauth;
    endpoints.apiUrl = CurrentServer().api;
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
    settings.userServiceUrl = CurrentServer().user;
    if (const std::string service = TestSetting("FAF_ONLINE_USER_SERVICE"); !service.empty()) {
      settings.userServiceUrl = service;
    }
    settings.webSocketUrl = TestSetting("FAF_ONLINE_WS");
    settings.testUniqueId = TestSetting("FAF_ONLINE_TEST_UNIQUE_ID");
    return settings;
  }

  /** FAF's chat on the chosen server (FAF_ONLINE_CHAT, a test hook, points it at another one). */
  FafChatSettings GameChatSettings()
  {
    FafChatSettings settings;
    settings.webSocketUrl = CurrentServer().chat;
    if (const std::string chat = TestSetting("FAF_ONLINE_CHAT"); !chat.empty()) {
      settings.webSocketUrl = chat;
    }
    settings.userAgent = "faf-re-client/" + std::string(gpg::diag::BuildVersion());
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

  /**
   * Engine addition: the game the player asked one of our control services to make (FafOnline_RequestServerGame), as
   * a thread of its own follows it: sent, then its host's state every 2 s until its lobby has the player's join line
   * (which stays here) or it is over.
   */
  struct ServerRequestJob
  {
    std::mutex lock;
    std::string state = "sending"; ///< sending, queued, starting, lobby, game, ended, refused, cancelled, failed
    std::string message;           ///< the service's or host's reason, or why the job failed
    int position = 0;              ///< in the host's queue, 1 is next
    std::string ref;               ///< <host>/<id>
    std::string lobbyKey;          ///< <host>/<lobby id> once it has one
    std::string join;              ///< the player's join line
    std::string service;
    std::atomic<bool> stop{false};
    std::atomic<bool> cancel{false};
    std::atomic<bool> done{false};
    /// The launcher joined its lobby once: it isn't joined by itself again (a player who left stays out), only from
    /// the games list.
    std::atomic<bool> joined{false};
    /// The player left its game (the launcher's way out): the server takes them out of that match for good.
    std::atomic<bool> left{false};
    std::thread worker;
  };
  std::shared_ptr<ServerRequestJob> gServerRequest;

  struct Service
  {
    FafAuth auth{GameEndpoints()};
    FafLobby lobby{GameLobbySettings()};
    FafChat chat{GameChatSettings()};
    /// FAF's matchmaker queues as `matchmaker_info` gives them (ladder1v1, tmm2v2, ...), by name.
    struct MatchQueue
    {
      std::string name;
      int teamSize = 0;
      int players = 0;                             ///< searching in it now
      std::chrono::steady_clock::time_point popAt; ///< when the queue next makes matches
    };
    std::map<std::string, MatchQueue> queues;
    std::set<std::string> searching;  ///< the queues this player searches in (`search_info`)
    std::string matchmaking = "idle"; ///< idle, searching, found (a match is being made), cancelled
    std::string matchedQueue;
    bool askedQueues = false; ///< matchmaker_info asked for on this lobby connection
    /// The matchmaker party this player is in (FAF lobby server party_service.py): its owner's FAF id ("" when the
    /// player is in none, which the lobby counts as a party of one) and its members with the factions each may get.
    struct PartyMember
    {
      std::string id;
      std::vector<std::string> factions;
    };
    std::string partyOwner;
    std::vector<PartyMember> partyMembers;
    /// Invitations to other players' parties: the inviter's FAF id and when it came (the lobby keeps one for a day).
    std::map<std::string, std::chrono::steady_clock::time_point> partyInvites;
    std::string partyNote; ///< the last thing that happened to the party, for the player ("You were removed ...")
    bool battleEnding = false; ///< a match waits for the launcher's background battle to end (asked once)
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
    /// The player's friends and foes by FAF id, as the lobby's `social` message lists them (and changes made since).
    std::set<std::string> friends;
    std::set<std::string> foes;
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
    /// The match is a game on one of our servers (FafOnline_JoinServer), not a FAF one: no GPGNet, nothing to FAF.
    bool serverGame = false;
    std::string serverGameKey; ///< its lobby, <host>/<id>
    std::string fixedToken; ///< FAF_ONLINE_ACCESS_TOKEN_FILE's, a test hook
    /// Our control services (ControlServiceAddresses), followed while the player is signed in to FAF.
    std::vector<std::unique_ptr<ControlServiceClient>> controls;

    // FAF_ONLINE_AUTOTEST (a test hook): host on <map> (host:<map>:<seconds>[:game]), or join the first open game the
    // launcher lists through its Join (join:<seconds>); leave after <seconds> in the lobby or the game, quit after.
    std::string autotestMap; ///< the map to host; "join" for the join test
    bool autotestJoin = false;
    bool autotestServer = false;      ///< server:<map>:<seconds>[:game]: Create game on our server, through the dialog
    bool autotestThenPreview = false; ///< ...:then-preview: a single-player session (the unit preview) after it
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
      chat.SetLog(LogLine);
      std::error_code ignored;
      std::filesystem::create_directories(DataFolder(), ignored);
      auth.SetTokenFile(DataFolder() / CurrentServer().tokenFile);
      LogLine((std::string("server: ") + CurrentServer().title + ", sign-in at " + auth.Endpoints().oauthUrl +
               ", API " + auth.Endpoints().apiUrl + ", lobby through " + GameLobbySettings().userServiceUrl +
               ", token file " + CurrentServer().tokenFile)
                .c_str());
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
      if (
        const std::string test = TestSetting("FAF_ONLINE_AUTOTEST");
        test.starts_with("host:") || test.starts_with("server:")
      ) {
        autotestServer = test.starts_with("server:");
        const std::size_t from = autotestServer ? 7 : 5;
        const std::size_t colon = test.find(':', from);
        autotestMap = test.substr(from, colon == std::string::npos ? std::string::npos : colon - from);
        autotestSeconds = colon == std::string::npos ? 30 : std::atoi(test.c_str() + colon + 1);
        autotestThenPreview = test.ends_with(":then-preview");
        autotestGame = test.ends_with(":game") || test.contains(":game:");
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
      if (gServerRequest) {
        gServerRequest->stop = true;
        if (gServerRequest->worker.joinable()) {
          gServerRequest->worker.join();
        }
        gServerRequest.reset();
      }
      for (const auto& control : controls) {
        control->Stop();
      }
      if (iceThread.joinable()) {
        iceThread.join();
      }
      chat.Disconnect();
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

    ReplayRelaySettings relaySettings;
    relaySettings.userServiceUrl = GameLobbySettings().userServiceUrl; // the chosen server's
    s.relay = std::make_unique<ReplayRelay>(relaySettings);
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
    if (s.serverGame) {
      // A game on our server: its lobby task and channel go; FAF never heard of it.
#if FAF_SERVER_MODE
      moho::SERVERLOBBY_End();
#endif
      s.serverGame = false;
      s.match = MatchState::Idle;
      s.matchMessage.clear();
      if (gServerRequest) {
        const std::lock_guard<std::mutex> lock(gServerRequest->lock);
        if (gServerRequest->lobbyKey == s.serverGameKey) {
          gServerRequest->left = true;
        }
      }
      LogLine(("server game " + s.serverGameKey + " ended; back to the launcher").c_str());
      if (s.endedFromLobby) {
        (void)moho::UI_StartFrontEnd();
      } else {
        moho::CON_Execute("ren_Oblivion false");
        moho::CON_Execute("ren_Ui true");
      }
      return;
    }
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
    SetField(L, "server", CurrentServer().name);
    SetField(L, "serverTitle", CurrentServer().title);
    SetBool(L, "lobbyKicked", s.lobby.Kicked());
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
    SetBool(L, "serverGame", s.serverGame && s.match != MatchState::Idle);
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
  void PushResult(lua_State* L, const std::expected<void, std::string>& result);

  /**
   * table|nil FafOnline_Player(login): what FAF's lobby told us about that player (its player_info, or the signed-in
   * player's welcome): id, login, country (ISO code, lower case), clan (tag), ratings = {[type] = {mean, deviation,
   * rating, games}}. nil for a player the lobby didn't mention.
   */
  int PlayerBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string login = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const LaunchPlayer* found = nullptr;
    if (const auto it = s.players.find(login); it != s.players.end()) {
      found = &it->second;
    } else if (s.haveMe && s.me.login == login) {
      found = &s.me;
    }
    if (found == nullptr) {
      lua_pushnil(L);
      return 1;
    }
    lua_newtable(L);
    SetField(L, "id", found->id);
    SetField(L, "login", found->login);
    SetField(L, "country", Lower(found->country));
    SetField(L, "clan", found->clan);
    lua_pushstring(L, "ratings");
    lua_newtable(L);
    for (const auto& [type, rating] : found->ratings) {
      lua_pushstring(L, type.c_str());
      lua_newtable(L);
      SetField(L, "mean", rating.mean);
      SetField(L, "deviation", rating.deviation);
      SetField(L, "rating", static_cast<double>(static_cast<long long>(rating.mean - 3.0 * rating.deviation)));
      SetField(L, "games", static_cast<double>(rating.games));
      lua_rawset(L, -3);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /** table FafOnline_Social(): friends and foes, each a table of FAF ids (text) to true. */
  int SocialBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    lua_newtable(L);
    for (const auto& [key, ids] : {std::pair{"friends", &s.friends}, std::pair{"foes", &s.foes}}) {
      lua_pushstring(L, key);
      lua_newtable(L);
      for (const std::string& id : *ids) {
        SetBool(L, id.c_str(), true);
      }
      lua_rawset(L, -3);
    }
    return 1;
  }

  /** One online player as the contacts and search show them: id, login, country, clan, global rating, friend, foe. */
  void PushContact(
    lua_State* const L,
    const Service& s,
    const LaunchPlayer& player
  )
  {
    lua_newtable(L);
    SetField(L, "id", player.id);
    SetField(L, "login", player.login);
    SetField(L, "country", Lower(player.country));
    SetField(L, "clan", player.clan);
    if (const auto global = player.ratings.find("global"); global != player.ratings.end()) {
      SetField(
        L, "rating", static_cast<double>(static_cast<long long>(global->second.mean - 3.0 * global->second.deviation))
      );
      SetField(L, "games", static_cast<double>(global->second.games));
    }
    SetBool(L, "friend", s.friends.contains(player.id));
    SetBool(L, "foe", s.foes.contains(player.id));
  }

  /**
   * list FafOnline_Players(text, limit): the players online in FAF's lobby whose login holds `text` (any case), by
   * login, at most `limit` (100 when not given), each as FafOnline_Contacts lists them; the total matching second.
   */
  int PlayersBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string text = Lower(lua_isstring(L, 1) ? lua_tostring(L, 1) : "");
    const int limit = lua_isnumber(L, 2) ? std::max(1, static_cast<int>(lua_tonumber(L, 2))) : 100;
    lua_newtable(L);
    int count = 0;
    int matching = 0;
    for (const auto& [login, player] : s.players) {
      if (!text.empty() && Lower(login).find(text) == std::string::npos) {
        continue;
      }
      ++matching;
      if (count < limit) {
        lua_pushnumber(L, static_cast<lua_Number>(++count));
        PushContact(L, s, player);
        lua_rawset(L, -3);
      }
    }
    lua_pushnumber(L, static_cast<lua_Number>(matching));
    return 2;
  }

  /**
   * table FafOnline_Contacts(): {friends = list, foes = list}, each player as FafOnline_Players lists them when online
   * (online = true), else only their id (FAF's lobby names only the players online).
   */
  int ContactsBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    std::map<std::string, const LaunchPlayer*> online;
    for (const auto& [login, player] : s.players) {
      online[player.id] = &player;
    }
    lua_newtable(L);
    for (const auto& [key, ids] : {std::pair{"friends", &s.friends}, std::pair{"foes", &s.foes}}) {
      lua_pushstring(L, key);
      lua_newtable(L);
      int count = 0;
      for (const std::string& id : *ids) {
        lua_pushnumber(L, static_cast<lua_Number>(++count));
        if (const auto it = online.find(id); it != online.end()) {
          PushContact(L, s, *it->second);
          SetBool(L, "online", true);
        } else {
          lua_newtable(L);
          SetField(L, "id", id);
          SetBool(L, "online", false);
          SetBool(L, "friend", s.friends.contains(id));
          SetBool(L, "foe", s.foes.contains(id));
        }
        lua_rawset(L, -3);
      }
      lua_rawset(L, -3);
    }
    return 1;
  }

  /** ok, why = FafOnline_SetFoe(id, on): adds the player with that FAF id to the foes (on) or removes them. */
  int SetFoeBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const bool on = lua_toboolean(L, 2) != 0;
    if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos) {
      PushResult(L, std::unexpected(std::string("FafOnline_SetFoe needs a player's FAF id")));
      return 2;
    }
    if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      PushResult(L, std::unexpected(std::string("not in FAF's lobby")));
      return 2;
    }
    const auto sent =
      s.lobby.Send(JsonObject({{"command", JsonString(on ? "social_add" : "social_remove")}, {"foe", JsonDigits(id)}}));
    if (sent) {
      if (on) {
        s.foes.insert(id);
        s.friends.erase(id);
      } else {
        s.foes.erase(id);
      }
      LogLine(((on ? "social: added foe " : "social: removed foe ") + id).c_str());
    }
    PushResult(L, sent);
    return 2;
  }

  /** ok, why = FafOnline_SetFriend(id, on): adds the player with that FAF id to the friends (on) or removes them. */
  int SetFriendBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const bool on = lua_toboolean(L, 2) != 0;
    if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos) {
      PushResult(L, std::unexpected(std::string("FafOnline_SetFriend needs a player's FAF id")));
      return 2;
    }
    if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      PushResult(L, std::unexpected(std::string("not in FAF's lobby")));
      return 2;
    }
    const auto sent = s.lobby.Send(
      JsonObject({{"command", JsonString(on ? "social_add" : "social_remove")}, {"friend", JsonDigits(id)}})
    );
    if (sent) {
      // The lobby doesn't answer with a new list; this one follows the change.
      if (on) {
        s.friends.insert(id);
        s.foes.erase(id);
      } else {
        s.friends.erase(id);
      }
      LogLine(((on ? "social: added friend " : "social: removed friend ") + id).c_str());
    }
    PushResult(L, sent);
    return 2;
  }

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

  // --- FAF's chat (online/FafChat): started by the launcher's Chat page, not before
  // -----------------------------------

  const char* ChatStateName(
    const FafChat::State state
  )
  {
    switch (state) {
    case FafChat::State::Connecting:
      return "connecting";
    case FafChat::State::Joined:
      return "joined";
    case FafChat::State::Failed:
      return "failed";
    case FafChat::State::Off:
      break;
    }
    return "off";
  }

  /** The chat's token from the server's user service (GET /irc/ergochat/token with the FAF sign-in). */
  FafChat::TokenSource ChatTokens(
    Service& s
  )
  {
    return
      [bearer = s.Tokens(),
       url = GameLobbySettings().userServiceUrl + "/irc/ergochat/token"]() -> std::expected<std::string, std::string> {
      const auto token = bearer();
      if (!token) {
        return std::unexpected(token.error());
      }
      platform::http::Call call;
      call.url = url;
      call.headers = "Accept: application/json\r\nAuthorization: Bearer " + *token + "\r\n";
      call.userAgent = "faf-re-client";
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body); !sent) {
        return std::unexpected("FAF's user service didn't answer: " + sent.error());
      }
      if (status != 200) {
        return std::unexpected("FAF's user service answered HTTP " + std::to_string(status) + " for the chat's token");
      }
      const auto answer = ParseJson(body);
      if (!answer || answer->String("value").empty()) {
        return std::unexpected(std::string("FAF's user service sent no chat token"));
      }
      return answer->String("value");
    };
  }

  /** ok, why = FafChat_Start(): signs in to the FAF server's chat (once signed in to FAF); again after a failure. */
  int ChatStartBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    std::string nick = s.haveMe ? s.me.login : s.auth.UserName();
    if (nick.empty()) {
      nick = s.lobby.Login();
    }
    if (nick.empty() && !s.fixedToken.empty()) {
      nick = TestSetting("FAF_ONLINE_TEST_NICK"); // a test hook: a fixed token names nobody, and no lobby may answer
    }
    std::expected<void, std::string> result;
    if (!s.SignedIn()) {
      result = std::unexpected(std::string("sign in to FAF first"));
    } else if (nick.empty()) {
      result = std::unexpected(std::string("FAF hasn't said who you are yet"));
    } else if (s.chat.GetState() == FafChat::State::Off || s.chat.GetState() == FafChat::State::Failed) {
      s.chat.Connect(ChatTokens(s), nick);
    }
    PushResult(L, result);
    return 2;
  }

  /** table FafChat_Status(): state (off, connecting, joined, failed), message, nick, channels = {name, ...}. */
  int ChatStatusBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    lua_newtable(L);
    SetField(L, "state", ChatStateName(s.chat.GetState()));
    SetField(L, "message", s.chat.Message());
    SetField(L, "nick", s.chat.Nick());
    lua_pushstring(L, "channels");
    lua_newtable(L);
    int index = 1;
    for (const std::string& channel : s.chat.Channels()) {
      lua_pushstring(L, channel.c_str());
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /**
   * table FafChat_Lines(channel, from): the channel's lines from number `from` on (0: from its first kept one), at
   * most 300: {total = lines it ever had, lines = {{from, text, time, self, action, event, history}, ...}}.
   */
  int ChatLinesBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string channel = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const std::size_t from =
      lua_isnumber(L, 2) ? static_cast<std::size_t>(std::max(0.0, double(lua_tonumber(L, 2)))) : 0;
    std::size_t total = 0;
    std::vector<FafChatLine> lines = s.chat.Lines(channel, from, total);
    if (lines.size() > 300) {
      lines.erase(lines.begin(), lines.end() - 300);
    }
    lua_newtable(L);
    SetField(L, "total", static_cast<double>(total));
    lua_pushstring(L, "lines");
    lua_newtable(L);
    int index = 1;
    for (const FafChatLine& line : lines) {
      lua_newtable(L);
      SetField(L, "from", line.from);
      SetField(L, "text", line.text);
      SetField(L, "time", line.time);
      SetBool(L, "self", line.self);
      SetBool(L, "action", line.action);
      SetBool(L, "event", line.event);
      SetBool(L, "history", line.history);
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /** table FafChat_Channel(channel): {topic, users = {nick, ...}} (nicks with their @ or + kept). */
  int ChatChannelBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string channel = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    lua_newtable(L);
    SetField(L, "topic", s.chat.Topic(channel));
    lua_pushstring(L, "users");
    lua_newtable(L);
    int index = 1;
    for (const std::string& user : s.chat.Users(channel)) {
      lua_pushstring(L, user.c_str());
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /** ok, why = FafChat_Say(channel, text): says it ("/me ..." as an action). */
  int ChatSayBody(
    lua_State* const L
  )
  {
    const std::string channel = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const std::string text = lua_isstring(L, 2) ? lua_tostring(L, 2) : "";
    PushResult(L, TheService().chat.Say(channel, text));
    return 2;
  }

  /** ok, why = FafChat_Join(channel) and FafChat_Leave(channel). */
  int ChatJoinBody(
    lua_State* const L
  )
  {
    PushResult(L, TheService().chat.Join(lua_isstring(L, 1) ? lua_tostring(L, 1) : ""));
    return 2;
  }

  int ChatLeaveBody(
    lua_State* const L
  )
  {
    PushResult(L, TheService().chat.Part(lua_isstring(L, 1) ? lua_tostring(L, 1) : ""));
    return 2;
  }

  /** FafChat_Private(nick): a private conversation with that player among the chat's channels (Leave closes it). */
  int ChatPrivateBody(
    lua_State* const L
  )
  {
    TheService().chat.OpenPrivate(lua_isstring(L, 1) ? lua_tostring(L, 1) : "");
    return 0;
  }

  /**
   * table FafOnline_Queues(): FAF's matchmaker: state (idle, searching, found, cancelled), matched (the queue a match
   * was found in), queues = {{name, teamSize, players, popIn (seconds), searching}, ...}.
   */
  int QueuesBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    lua_newtable(L);
    SetField(L, "state", s.matchmaking);
    SetField(L, "matched", s.matchedQueue);
    lua_pushstring(L, "queues");
    lua_newtable(L);
    int index = 1;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& [name, queue] : s.queues) {
      lua_newtable(L);
      SetField(L, "name", queue.name);
      SetField(L, "teamSize", static_cast<double>(queue.teamSize));
      SetField(L, "players", static_cast<double>(queue.players));
      const double popIn = queue.popAt == std::chrono::steady_clock::time_point{}
        ? 0.0
        : std::max(0.0, std::chrono::duration<double>(queue.popAt - now).count());
      SetField(L, "popIn", std::floor(popIn));
      SetBool(L, "searching", s.searching.contains(name));
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /** ok, why = FafOnline_Search(queue, on): starts or stops searching for a match in a matchmaker queue. */
  int SearchBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string queue = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const bool on = lua_toboolean(L, 2) != 0;
    std::expected<void, std::string> result;
    if (queue.empty() || !s.queues.contains(queue)) {
      result = std::unexpected(std::string("no such queue"));
    } else if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      result = std::unexpected(std::string("not connected to FAF's lobby"));
    } else if (on && s.match != MatchState::Idle && s.match != MatchState::Failed) {
      result = std::unexpected(std::string("a game is under way"));
    } else {
      if (on && s.matchmaking == "cancelled") {
        s.matchmaking = "idle";
      }
      result = s.lobby.Send(JsonObject(
        {{"command", JsonString("game_matchmaking")},
         {"queue_name", JsonString(queue)},
         {"state", JsonString(on ? "start" : "stop")}}
      ));
      if (result) {
        LogLine(("matchmaker: " + std::string(on ? "searching in " : "stopped searching in ") + queue).c_str());
      }
    }
    PushResult(L, result);
    return 2;
  }

  /** A login for a FAF id, from the lobby's player list ("" when the lobby hasn't told us about that player). */
  std::string LoginOf(
    const Service& s,
    const std::string& id
  )
  {
    if (s.haveMe && s.me.id == id) {
      return s.me.login;
    }
    for (const auto& [login, player] : s.players) {
      if (player.id == id) {
        return login;
      }
    }
    return {};
  }

  /**
   * table FafOnline_Party(): the matchmaker party: owner (FAF id, "" in none), mine (this player owns it or is in
   * none), members = {{id, login, factions = {...}}}, invites = {{id, login}} (parties this player may join), note.
   */
  int PartyBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    lua_newtable(L);
    SetField(L, "owner", s.partyOwner);
    SetBool(L, "mine", s.partyOwner.empty() || (s.haveMe && s.partyOwner == s.me.id));
    SetField(L, "note", s.partyNote);
    lua_pushstring(L, "members");
    lua_newtable(L);
    int index = 1;
    for (const Service::PartyMember& member : s.partyMembers) {
      lua_newtable(L);
      SetField(L, "id", member.id);
      SetField(L, "login", LoginOf(s, member.id));
      lua_pushstring(L, "factions");
      lua_newtable(L);
      int f = 1;
      for (const std::string& faction : member.factions) {
        lua_pushstring(L, faction.c_str());
        lua_rawseti(L, -2, f++);
      }
      lua_rawset(L, -3);
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    lua_pushstring(L, "invites");
    lua_newtable(L);
    index = 1;
    for (const auto& [id, at] : s.partyInvites) {
      lua_newtable(L);
      SetField(L, "id", id);
      SetField(L, "login", LoginOf(s, id));
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /** The party commands' shared checks: a FAF id (when `needsId`), the lobby signed in, no search running. */
  std::expected<void, std::string> PartyReady(
    const Service& s,
    const std::string& id,
    const bool needsId
  )
  {
    if (needsId && (id.empty() || id.find_first_not_of("0123456789") != std::string::npos)) {
      return std::unexpected(std::string("needs a player's FAF id"));
    }
    if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      return std::unexpected(std::string("not connected to FAF's lobby"));
    }
    if (!s.searching.empty()) {
      return std::unexpected(std::string("stop searching first: a party changes only out of the queue"));
    }
    return {};
  }

  /**
   * ok, why = FafOnline_PartyInvite(id): invites that player into this player's party (making one); only its owner
   * invites. FafOnline_PartyAccept(id): joins the party of the player who invited this one. FafOnline_PartyDecline(id):
   * forgets that invite. FafOnline_PartyKick(id): the owner removes a member. FafOnline_PartyLeave(): leaves the party.
   */
  int PartyInviteBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    auto result = PartyReady(s, id, true);
    if (result && s.haveMe && id == s.me.id) {
      result = std::unexpected(std::string("you're in your own party already"));
    } else if (result && !s.partyOwner.empty() && !(s.haveMe && s.partyOwner == s.me.id)) {
      result = std::unexpected(std::string("only the party's owner invites"));
    }
    if (result) {
      result = s.lobby.Send(JsonObject({{"command", JsonString("invite_to_party")}, {"recipient_id", JsonDigits(id)}}));
      if (result) {
        s.partyNote.clear();
        LogLine(("party: invited " + id).c_str());
      }
    }
    PushResult(L, result);
    return 2;
  }

  int PartyAcceptBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    auto result = PartyReady(s, id, true);
    if (result && !s.partyInvites.contains(id)) {
      result = std::unexpected(std::string("that player hasn't invited you"));
    }
    if (result) {
      result =
        s.lobby.Send(JsonObject({{"command", JsonString("accept_party_invite")}, {"sender_id", JsonDigits(id)}}));
      if (result) {
        s.partyInvites.erase(id);
        s.partyNote.clear();
        LogLine(("party: accepted the invite of " + id).c_str());
      }
    }
    PushResult(L, result);
    return 2;
  }

  int PartyDeclineBody(
    lua_State* const L
  )
  {
    // The lobby has no decline: the invite is forgotten here, and it lapses there after a day.
    Service& s = TheService();
    const std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    s.partyInvites.erase(id);
    PushResult(L, std::expected<void, std::string>{});
    return 2;
  }

  int PartyKickBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    auto result = PartyReady(s, id, true);
    if (result && !(s.haveMe && s.partyOwner == s.me.id)) {
      result = std::unexpected(std::string("only the party's owner removes members"));
    }
    if (result) {
      result = s.lobby.Send(
        JsonObject({{"command", JsonString("kick_player_from_party")}, {"kicked_player_id", JsonDigits(id)}})
      );
      if (result) {
        LogLine(("party: removed " + id).c_str());
      }
    }
    PushResult(L, result);
    return 2;
  }

  int PartyLeaveBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    auto result = PartyReady(s, "", false);
    if (result && s.partyOwner.empty()) {
      result = std::unexpected(std::string("you're in no party"));
    }
    if (result) {
      result = s.lobby.Send(JsonObject({{"command", JsonString("leave_party")}}));
      if (result) {
        // The lobby sends this player no update after a leave; the party is gone from here at once.
        s.partyOwner.clear();
        s.partyMembers.clear();
        s.partyNote = "You left the party.";
        LogLine("party: left");
      }
    }
    PushResult(L, result);
    return 2;
  }

  /** ok, why = FafOnline_SetFactions({'uef', 'aeon', ...}): the factions the matchmaker may give this player. */
  int SetFactionsBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    std::vector<JsonNode> factions;
    if (lua_istable(L, 1)) {
      for (int i = 1;; ++i) {
        lua_rawgeti(L, 1, i);
        if (!lua_isstring(L, -1)) {
          lua_pop(L, 1);
          break;
        }
        factions.push_back(JsonString(Lower(lua_tostring(L, -1))));
        lua_pop(L, 1);
      }
    }
    std::expected<void, std::string> result;
    if (factions.empty()) {
      result = std::unexpected(std::string("pick a faction at least"));
    } else if (s.lobby.GetState() != FafLobby::State::SignedIn) {
      result = std::unexpected(std::string("not connected to FAF's lobby"));
    } else {
      result = s.lobby.Send(
        JsonObject({{"command", JsonString("set_party_factions")}, {"factions", JsonArray(std::move(factions))}})
      );
    }
    PushResult(L, result);
    return 2;
  }

  /** table FafOnline_Server(): the chosen server (name, title) and every server there is (servers = {{name, title}}).
   */
  int ServerBody(
    lua_State* const L
  )
  {
    lua_newtable(L);
    SetField(L, "name", CurrentServer().name);
    SetField(L, "title", CurrentServer().title);
    lua_pushstring(L, "servers");
    lua_newtable(L);
    int index = 1;
    for (const FafServer& server : kServers) {
      lua_newtable(L);
      SetField(L, "name", server.name);
      SetField(L, "title", server.title);
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /**
   * ok, why = FafOnline_SetServer(name): plays on that FAF server from now on (kept for the next start). The online
   * service starts again on it: signed out of the old one's lobby, signed in with the new one's own saved sign-in
   * when there is one. Refused while a game runs.
   */
  int SetServerBody(
    lua_State* const L
  )
  {
    const std::string name = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    const FafServer* wanted = nullptr;
    for (const FafServer& server : kServers) {
      if (name == server.name) {
        wanted = &server;
      }
    }
    if (wanted == nullptr) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, "no such server");
      return 2;
    }
    if (gService && gService->match != MatchState::Idle && gService->match != MatchState::Failed) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, "leave the game first");
      return 2;
    }
    if (name != CurrentServer().name) {
      std::error_code ignored;
      std::filesystem::create_directories(DataFolder(), ignored);
      std::ofstream(DataFolder() / "server.txt", std::ios::binary | std::ios::trunc) << name << "\n";
      LogLine((std::string("server: ") + CurrentServer().name + " -> " + name).c_str());
      moho::LIBRARY_Shutdown(); // its searches and downloads sign in to the old server
      gService.reset();         // the next call makes it again, on the new server
      gServerName = name;
    }
    lua_pushboolean(L, 1);
    lua_pushnil(L);
    return 2;
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

  /** Why this build can't join a game on our servers from the launcher, or empty when it can. */
  std::string ServerJoinUnavailable()
  {
#if FAF_SERVER_MODE
    if (!moho::SERVERLOBBY_GamesOn()) {
      return "Games on our servers are turned off (net_ServerGames 0).";
    }
    return {};
#else
    return "This build of the game can't play on our servers (it was built without server mode).";
#endif
  }

  /** Why the player can't join `lobby` now, or empty. */
  std::string WhyNotJoinable(
    const ServerLobby& lobby
  )
  {
    if (std::string why = ServerJoinUnavailable(); !why.empty()) {
      return why;
    }
    if (lobby.join.empty()) {
      return lobby.watch.empty() ? "You have no seat in this game." : "You may only watch this game.";
    }
    if (lobby.state != "starting" && lobby.state != "lobby" && lobby.state != "game") {
      return "This game is over.";
    }
    if (gServerRequest && gServerRequest->left.load()) {
      const std::lock_guard<std::mutex> lock(gServerRequest->lock);
      if (gServerRequest->lobbyKey == lobby.key) {
        return "You left this game: the server took you out of it.";
      }
    }
    return {};
  }

#if FAF_SERVER_MODE
  /**
   * A join line as our servers hand it out: `/connectserver <address> /servertoken <token> /serveruid <uid>`; the
   * address, token and uid in `out`, false when one is missing.
   */
  bool ReadJoinLine(
    const std::string& line,
    std::string& address,
    std::string& token,
    long long& uid
  )
  {
    std::vector<std::string> words;
    std::string word;
    for (const char c : line) {
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        if (!word.empty()) {
          words.push_back(std::move(word));
          word.clear();
        }
      } else {
        word += c;
      }
    }
    if (!word.empty()) {
      words.push_back(std::move(word));
    }
    bool haveUid = false;
    for (std::size_t i = 0; i + 1 < words.size(); ++i) {
      if (words[i] == "/connectserver") {
        address = words[i + 1];
      } else if (words[i] == "/servertoken") {
        token = words[i + 1];
      } else if (words[i] == "/serveruid") {
        char* end = nullptr;
        uid = std::strtoll(words[i + 1].c_str(), &end, 10);
        haveUid = end != nullptr && *end == 0 && uid > 0;
      }
    }
    return !address.empty() && !token.empty() && haveUid;
  }
#endif

  /**
   * Starts the game on our server whose lobby is `key`, with the player's own join line from its control service:
   * the channel opens here, the server's answer comes in ONLINE_Frame (PollServerGame). The join line (the player's
   * credential) never reaches Lua.
   */
  std::expected<void, std::string> JoinServerGame(
    Service& s,
    const std::string& key
  )
  {
    if (std::string why = ServerJoinUnavailable(); !why.empty()) {
      return std::unexpected(why);
    }
#if FAF_SERVER_MODE
    if (s.match == MatchState::Preparing || s.match == MatchState::Running || s.match == MatchState::Ending) {
      return std::unexpected(std::string("a game is already running"));
    }
    if (moho::WLD_GetActiveSession() != nullptr) {
      return std::unexpected(std::string("a game is already running"));
    }
    const ServerLobby* found = nullptr;
    std::vector<ServerLobby> lobbies;
    for (const auto& control : s.controls) {
      for (ServerLobby& lobby : control->Lobbies()) {
        lobbies.push_back(std::move(lobby));
      }
    }
    for (const ServerLobby& lobby : lobbies) {
      if (lobby.key == key) {
        found = &lobby;
      }
    }
    ServerLobby fromRequest;
    if (found == nullptr && gServerRequest) {
      // The player's own request: its lobby may be here before the service's event stream lists it.
      const std::lock_guard<std::mutex> lock(gServerRequest->lock);
      if (gServerRequest->lobbyKey == key && !gServerRequest->join.empty()) {
        fromRequest.key = key;
        fromRequest.state = gServerRequest->state;
        fromRequest.join = gServerRequest->join;
        found = &fromRequest;
      }
    }
    if (found == nullptr) {
      return std::unexpected(std::string("no such game on our servers"));
    }
    if (std::string why = WhyNotJoinable(*found); !why.empty()) {
      return std::unexpected(why);
    }
    std::string address;
    std::string token;
    long long uid = 0;
    if (!ReadJoinLine(found->join, address, token, uid) || uid > 0x7FFFFFFFll) {
      return std::unexpected(std::string("the server's join line for this seat doesn't read"));
    }
    faf::remote::SServerConnectRequest request;
    if (
      auto made = faf::remote::MakeServerConnectRequest(address, token, static_cast<std::int32_t>(uid), request); !made
    ) {
      return std::unexpected(made.error());
    }
    std::string error;
    if (!faf::remote::BeginServerSession(request, error)) {
      return std::unexpected(error);
    }
    if (gServerRequest) {
      const std::lock_guard<std::mutex> lock(gServerRequest->lock);
      if (gServerRequest->lobbyKey == key) {
        gServerRequest->joined = true;
      }
    }
    s.serverGame = true;
    s.serverGameKey = key;
    s.endedFromLobby = false;
    s.match = MatchState::Preparing;
    s.matchMessage = "Connecting to the game server";
    LogLine(("server game " + key + ": connecting to " + address).c_str());
    return {};
#else
    (void)s;
    (void)key;
    return std::unexpected(std::string("no server mode"));
#endif
  }

#if FAF_SERVER_MODE
  /** The lobby UI of a launcher's server game: FAF's lobby modules load again (their switches), then the task. */
  bool StartLauncherServerLobby()
  {
    if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
      (void)moho::SCR_LuaDoString(
        "if __modules then __modules['/lua/ui/lobby/lobby.lua'] = nil __modules['/lua/ui/lobby/autolobby.lua'] = nil "
        "__modules['/lua/multiplayer/gpgnet.lua'] = nil end",
        state
      );
    }
    return moho::SERVERLOBBY_StartForLauncher();
  }
#endif

  /** Each frame while a server game starts or runs: the server's answer, and a channel lost outside the game. */
  void PollServerGame(
    Service& s
  )
  {
#if FAF_SERVER_MODE
    if (!s.serverGame) {
      return;
    }
    if (s.match == MatchState::Preparing) {
      std::string error;
      switch (faf::remote::PollServerSession(&StartLauncherServerLobby, error)) {
      case faf::remote::EServerSessionStart::NotRequested:
        return;
      case faf::remote::EServerSessionStart::Started:
        s.match = MatchState::Running;
        s.matchMessage = "On the game server: waiting for its lobby";
        LogLine(("server game " + s.serverGameKey + ": connected").c_str());
        return;
      case faf::remote::EServerSessionStart::Failed:
        moho::SERVERLOBBY_End();
        s.serverGame = false;
        Fail(s, error);
        LogLine(("server game " + s.serverGameKey + ": " + error).c_str());
        return;
      }
    }
    if (s.match == MatchState::Running && moho::WLD_GetActiveSession() == nullptr && !faf::remote::ServerSessionUp()) {
      // The channel is gone before a game began (in the lobby or while it waited): back to the launcher, saying so. A
      // game's own end goes through the session's (ONLINE_ReturnToLauncherInsteadOfQuitting).
      LogLine(("server game " + s.serverGameKey + ": the connection to the game server was lost").c_str());
      s.endedFromLobby = true;
      FinishMatch(s);
      Fail(s, "The connection to the game server was lost.");
    }
#else
    (void)s;
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
        const std::string why = WhyNotJoinable(lobby);
        SetBool(L, "joinable", why.empty());
        SetField(L, "why", why);
        lua_rawseti(L, -2, index++);
      }
    }
    return 1;
  }

  /** One host request record (`request` in the service's answers) into `job`, under its lock. */
  void ReadRequestRecord(
    ServerRequestJob& job,
    const JsonNode& record,
    const std::string& myUid
  )
  {
    const std::lock_guard<std::mutex> lock(job.lock);
    if (const std::string ref = record.String("ref"); !ref.empty()) {
      job.ref = ref;
    }
    if (const std::string state = record.String("state"); !state.empty()) {
      job.state = state;
    }
    const JsonNode* const position = record.Get("position");
    job.position =
      position != nullptr && position->kind == JsonNode::Kind::Number ? static_cast<int>(position->number) : 0;
    job.message = record.String("reason");
    const JsonNode* const lobby = record.Get("lobby");
    if (lobby == nullptr || lobby->kind != JsonNode::Kind::Object) {
      return;
    }
    const std::string host = record.String("host");
    if (const std::string id = lobby->String("id"); !id.empty() && !host.empty()) {
      job.lobbyKey = host + "/" + id;
    }
    // The player's seat: their FAF id, else seat 1 (the service makes the requesting player seat 1).
    if (const JsonNode* const seats = lobby->Get("seats"); seats != nullptr && seats->kind == JsonNode::Kind::Array) {
      std::string first;
      for (const JsonNode& seat : seats->items) {
        const JsonNode* const uid = seat.Get("uid");
        const std::string join = seat.String("join");
        if (!myUid.empty() && uid != nullptr && uid->text == myUid && !join.empty()) {
          job.join = join;
          return;
        }
        if (seat.Number("seat") == 1 && !join.empty()) {
          first = join;
        }
      }
      if (!first.empty()) {
        job.join = first;
      }
    }
  }

  [[nodiscard]] bool RequestOver(
    const std::string& state
  )
  {
    return state == "ended" || state == "refused" || state == "cancelled" || state == "failed";
  }

  /**
   * ok, why = FafOnline_RequestServerGame{map, seats = {"human" | an AI's name ...} (after the player's own),
   * options = {key = value}, host, region, byPing}: asks the first of our control services for a game the player
   * hosts, followed by FafOnline_ServerRequest. One at a time.
   */
  int RequestServerGameBody(
    lua_State* const L
  )
  {
    Service& s = TheService();
    const auto fail = [L](std::string why) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, why.c_str());
      return 2;
    };
    if (std::string why = ServerJoinUnavailable(); !why.empty()) {
      return fail(why);
    }
    if (s.controls.empty()) {
      return fail("no control service of ours is set up (control-services.txt)");
    }
    if (gServerRequest && !gServerRequest->done.load()) {
      return fail("a request of yours is still on its way: cancel it first");
    }
    if (!lua_istable(L, 1)) {
      return fail("FafOnline_RequestServerGame takes a table");
    }
    ServerGameRequest request;
    request.map = TableString(L, 1, "map");
    if (request.map.empty()) {
      return fail("the request needs a map");
    }
    lua_pushstring(L, "seats");
    lua_gettable(L, 1);
    if (lua_istable(L, -1)) {
      const int seats = lua_gettop(L);
      for (int i = 1; i <= 16; ++i) {
        lua_rawgeti(L, seats, i);
        const bool more = lua_isstring(L, -1) != 0;
        if (more) {
          request.otherSeats.emplace_back(lua_tostring(L, -1));
        }
        lua_pop(L, 1);
        if (!more) {
          break;
        }
      }
    }
    lua_pop(L, 1);
    lua_pushstring(L, "options");
    lua_gettable(L, 1);
    if (lua_istable(L, -1)) {
      const int options = lua_gettop(L);
      lua_pushnil(L);
      while (lua_next(L, options) != 0) {
        // A number key would be turned into a string in place and break lua_next: strings only.
        if (lua_type(L, -2) == LUA_TSTRING && lua_isstring(L, -1)) {
          request.options[lua_tostring(L, -2)] = lua_tostring(L, -1);
        }
        lua_pop(L, 1);
      }
    }
    lua_pop(L, 1);
    request.host = TableString(L, 1, "host");
    request.region = TableString(L, 1, "region");
    request.byPing = TableBool(L, 1, "byPing");

    if (gServerRequest && gServerRequest->worker.joinable()) {
      gServerRequest->worker.join(); // done: it has returned
    }
    auto job = std::make_shared<ServerRequestJob>();
    job->service = s.controls.front()->Address();
    const std::string myUid = s.haveMe ? s.me.id : std::string();
    auto client =
      std::make_shared<ControlServiceClient>(job->service, std::string("faf-re-client/") + gpg::diag::BuildVersion());
    client->SetTokens(s.Tokens());
    job->worker = std::thread([job, client, request, myUid] {
      const auto finish = [&job](const char* state, std::string why) {
        {
          const std::lock_guard<std::mutex> lock(job->lock);
          job->state = state;
          job->message = std::move(why);
        }
        job->done = true;
      };
      auto answer = client->RequestGame(request);
      if (!answer) {
        // A host takes one request per player: one still open (the game left without its end, a restart) is the
        // player's to rejoin or cancel, so it is followed instead.
        bool adopted = false;
        if (auto mine = client->PlayerRequests(); mine) {
          if (
            const JsonNode* const list = mine->Get("requests"); list != nullptr && list->kind == JsonNode::Kind::Array
          ) {
            for (const JsonNode& record : list->items) {
              const std::string state = record.String("state");
              if (!state.empty() && state != "unknown" && !RequestOver(state)) {
                ReadRequestRecord(*job, record, myUid);
                // Not joined by itself: the player asked for a new game; this one is theirs to join from the list or
                // cancel.
                job->joined = true;
                adopted = true;
                break;
              }
            }
          }
        }
        if (!adopted) {
          LogLine(("server request for " + request.map + " failed: " + answer.error()).c_str());
          finish("failed", answer.error());
          return;
        }
        LogLine(
          ("server request: following the player's open request " + job->ref + " (" + answer.error() + ")").c_str()
        );
      } else {
        if (const JsonNode* const record = answer->Get("request")) {
          ReadRequestRecord(*job, *record, myUid);
        }
        LogLine(("server request " + job->ref + " sent: " + request.map).c_str());
      }
      auto next = std::chrono::steady_clock::now();
      while (!job->stop.load()) {
        if (job->cancel.load()) {
          std::string ref;
          {
            const std::lock_guard<std::mutex> lock(job->lock);
            ref = job->ref;
          }
          auto cancelled = client->CancelRequest(ref);
          finish(cancelled ? "cancelled" : "failed", cancelled ? std::string() : cancelled.error());
          LogLine(
            ("server request " + ref + (cancelled ? " cancelled" : " not cancelled: " + cancelled.error())).c_str()
          );
          return;
        }
        {
          const std::lock_guard<std::mutex> lock(job->lock);
          if (RequestOver(job->state)) {
            break;
          }
        }
        if (std::chrono::steady_clock::now() >= next) {
          next = std::chrono::steady_clock::now() + std::chrono::seconds(2);
          std::string ref;
          {
            const std::lock_guard<std::mutex> lock(job->lock);
            ref = job->ref;
          }
          if (auto followed = client->FollowRequest(ref); followed) {
            if (const JsonNode* const record = followed->Get("request")) {
              ReadRequestRecord(*job, *record, myUid);
            }
          }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      job->done = true;
    });
    gServerRequest = job;
    lua_pushboolean(L, 1);
    lua_pushnil(L);
    return 2;
  }

  /**
   * table FafOnline_ServerRequest(): the player's request (state, message, position, ref, lobbyKey, ready: its lobby
   * has the player's seat to join, service), or nil without one.
   */
  int ServerRequestBody(
    lua_State* const L
  )
  {
    if (!gServerRequest) {
      lua_pushnil(L);
      return 1;
    }
    ServerRequestJob& job = *gServerRequest;
    const std::lock_guard<std::mutex> lock(job.lock);
    lua_newtable(L);
    SetField(L, "state", job.state);
    SetField(L, "message", job.message);
    SetField(L, "position", static_cast<double>(job.position));
    SetField(L, "ref", job.ref);
    SetField(L, "lobbyKey", job.lobbyKey);
    SetField(L, "service", job.service);
    SetBool(L, "ready", !job.join.empty() && !job.lobbyKey.empty() && !RequestOver(job.state) && !job.joined.load());
    SetBool(L, "joined", job.joined.load());
    SetBool(L, "left", job.left.load());
    SetBool(L, "cancelling", job.cancel.load() && !job.done.load());
    return 1;
  }

  /** ok, why = FafOnline_CancelServerRequest(): cancels the player's request; FafOnline_ServerRequest says when. */
  int CancelServerRequestBody(
    lua_State* const L
  )
  {
    if (!gServerRequest || gServerRequest->done.load()) {
      PushResult(L, std::unexpected(std::string("no request of yours is on its way")));
      return 2;
    }
    gServerRequest->cancel = true;
    PushResult(L, {});
    return 2;
  }

  /** FafOnline_ForgetServerRequest(): the launcher has shown a finished request's end; it goes. */
  int ForgetServerRequestBody(
    lua_State* const L
  )
  {
    (void)L;
    if (gServerRequest && gServerRequest->done.load()) {
      if (gServerRequest->worker.joinable()) {
        gServerRequest->worker.join();
      }
      gServerRequest.reset();
    }
    return 0;
  }

  /** ok, why = FafOnline_JoinServer(key): joins the game on our server whose lobby is `key` (<host>/<id>). */
  int JoinServerBody(
    lua_State* const L
  )
  {
    const char* const key = lua_tostring(L, 1);
    PushResult(L, JoinServerGame(TheService(), key != nullptr ? key : ""));
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
    static CScrLuaBinder player(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Player",
      &Binding<&PlayerBody>,
      nullptr,
      "<global>",
      "table FafOnline_Player(login) - what FAF's lobby said about a player: id, country, clan, ratings; or nil."
    );
    static CScrLuaBinder players(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Players",
      &Binding<&PlayersBody>,
      nullptr,
      "<global>",
      "list, number FafOnline_Players(text, limit) - the players online in FAF's lobby whose login holds the text."
    );
    static CScrLuaBinder contacts(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Contacts",
      &Binding<&ContactsBody>,
      nullptr,
      "<global>",
      "table FafOnline_Contacts() - friends and foes: online ones with login, country, clan and rating, others by id."
    );
    static CScrLuaBinder setFoe(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_SetFoe",
      &Binding<&SetFoeBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_SetFoe(id, on) - adds that FAF player to the foes, or removes them."
    );
    static CScrLuaBinder social(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Social",
      &Binding<&SocialBody>,
      nullptr,
      "<global>",
      "table FafOnline_Social() - the player's FAF friends and foes: {friends = {[id] = true}, foes = {...}}."
    );
    static CScrLuaBinder setFriend(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_SetFriend",
      &Binding<&SetFriendBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_SetFriend(id, on) - adds that FAF player to the friends, or removes them."
    );
    static CScrLuaBinder chatStart(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Start",
      &Binding<&ChatStartBody>,
      nullptr,
      "<global>",
      "bool, string FafChat_Start() - signs in to the FAF server's chat."
    );
    static CScrLuaBinder chatStatus(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Status",
      &Binding<&ChatStatusBody>,
      nullptr,
      "<global>",
      "table FafChat_Status() - the chat's state, nick and channels."
    );
    static CScrLuaBinder chatLines(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Lines",
      &Binding<&ChatLinesBody>,
      nullptr,
      "<global>",
      "table FafChat_Lines(channel, from) - a channel's lines from a number on."
    );
    static CScrLuaBinder chatChannel(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Channel",
      &Binding<&ChatChannelBody>,
      nullptr,
      "<global>",
      "table FafChat_Channel(channel) - a channel's topic and users."
    );
    static CScrLuaBinder chatSay(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Say",
      &Binding<&ChatSayBody>,
      nullptr,
      "<global>",
      "bool, string FafChat_Say(channel, text) - says it in the channel."
    );
    static CScrLuaBinder chatJoin(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Join",
      &Binding<&ChatJoinBody>,
      nullptr,
      "<global>",
      "bool, string FafChat_Join(channel) - joins a channel."
    );
    static CScrLuaBinder chatLeave(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Leave",
      &Binding<&ChatLeaveBody>,
      nullptr,
      "<global>",
      "bool, string FafChat_Leave(channel) - leaves a channel."
    );
    static CScrLuaBinder chatPrivate(
      moho::SCR_UserLuaInitSet(),
      "FafChat_Private",
      &Binding<&ChatPrivateBody>,
      nullptr,
      "<global>",
      "FafChat_Private(nick) - a private conversation with that player among the channels."
    );
    static CScrLuaBinder queues(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Queues",
      &Binding<&QueuesBody>,
      nullptr,
      "<global>",
      "table FafOnline_Queues() - FAF's matchmaker queues and this player's search."
    );
    static CScrLuaBinder search(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Search",
      &Binding<&SearchBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_Search(queue, on) - starts or stops searching in a matchmaker queue."
    );
    static CScrLuaBinder setFactions(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_SetFactions",
      &Binding<&SetFactionsBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_SetFactions(list) - the factions the matchmaker may give this player."
    );
    static CScrLuaBinder party(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Party",
      &Binding<&PartyBody>,
      nullptr,
      "<global>",
      "table FafOnline_Party() - this player's matchmaker party: owner, members, invites."
    );
    static CScrLuaBinder partyInvite(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_PartyInvite",
      &Binding<&PartyInviteBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_PartyInvite(id) - invites a player into this player's matchmaker party."
    );
    static CScrLuaBinder partyAccept(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_PartyAccept",
      &Binding<&PartyAcceptBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_PartyAccept(id) - joins the party of the player who invited this one."
    );
    static CScrLuaBinder partyDecline(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_PartyDecline",
      &Binding<&PartyDeclineBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_PartyDecline(id) - forgets a party invite."
    );
    static CScrLuaBinder partyKick(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_PartyKick",
      &Binding<&PartyKickBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_PartyKick(id) - the party's owner removes a member."
    );
    static CScrLuaBinder partyLeave(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_PartyLeave",
      &Binding<&PartyLeaveBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_PartyLeave() - leaves the matchmaker party."
    );
    static CScrLuaBinder server(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_Server",
      &Binding<&ServerBody>,
      nullptr,
      "<global>",
      "table FafOnline_Server() - the FAF server played on (name, title) and the servers there are."
    );
    static CScrLuaBinder setServer(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_SetServer",
      &Binding<&SetServerBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_SetServer(name) - plays on FAF's main or test server from now on."
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
      "bool, string FafOnline_JoinServer(key) - joins a game on our servers, or says why not."
    );
    static CScrLuaBinder requestServerGame(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_RequestServerGame",
      &Binding<&RequestServerGameBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_RequestServerGame(table) - asks our control service for a game the player hosts."
    );
    static CScrLuaBinder serverRequest(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_ServerRequest",
      &Binding<&ServerRequestBody>,
      nullptr,
      "<global>",
      "table FafOnline_ServerRequest() - the player's request for a game on our servers, or nil."
    );
    static CScrLuaBinder cancelServerRequest(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_CancelServerRequest",
      &Binding<&CancelServerRequestBody>,
      nullptr,
      "<global>",
      "bool, string FafOnline_CancelServerRequest() - cancels the player's request for a game on our servers."
    );
    static CScrLuaBinder forgetServerRequest(
      moho::SCR_UserLuaInitSet(),
      "FafOnline_ForgetServerRequest",
      &Binding<&ForgetServerRequestBody>,
      nullptr,
      "<global>",
      "FafOnline_ForgetServerRequest() - drops a finished request once shown."
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
      TestSetting("FAF_ONLINE_AUTOTEST").starts_with("join:") ||
      TestSetting("FAF_ONLINE_AUTOTEST").starts_with("server:");
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
    // A kick (the same account signed in elsewhere) waits for the player's Try again: connecting at once would sign
    // the other session out in turn.
    s.lobbyStarted && s.lobby.GetState() == FafLobby::State::Failed && !s.lobby.Kicked() &&
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
    if (!s.askedQueues) {
      s.askedQueues = true;
      (void)s.lobby.Send(JsonObject({{"command", JsonString("matchmaker_info")}}));
    }
  }
  if (s.lobby.GetState() != FafLobby::State::SignedIn && s.askedQueues) {
    s.askedQueues = false;
    s.searching.clear();
    s.matchmaking = "idle";
    // The lobby drops a party member whose connection ends (party_service.py on_connection_lost).
    s.partyOwner.clear();
    s.partyMembers.clear();
    s.partyInvites.clear();
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
          // A player who left FAF: the lobby says so with state "offline" (Java commons' Player.State).
          if (player.String("state") == "offline") {
            s.players.erase(record.login);
            continue;
          }
          if (record.login == s.me.login) {
            s.me = record; // the ratings after a game
          }
          if (!record.login.empty()) {
            s.players[record.login] = std::move(record);
          }
        }
      }
    } else if (command == "social") {
      // Sent after sign-in; a message without a list leaves that list as it was.
      const auto read = [&](const char* const key, std::set<std::string>& into) {
        const JsonNode* const ids = message.Get(key);
        if (ids == nullptr || ids->kind != JsonNode::Kind::Array) {
          return;
        }
        into.clear();
        for (const JsonNode& id : ids->items) {
          if (id.kind == JsonNode::Kind::Number || id.kind == JsonNode::Kind::String) {
            into.insert(id.text);
          }
        }
      };
      read("friends", s.friends);
      read("foes", s.foes);
      LogLine(
        ("social: " + std::to_string(s.friends.size()) + " friends, " + std::to_string(s.foes.size()) + " foes").c_str()
      );
    } else if (command == "matchmaker_info") {
      // Every queue with how many search in it and when it next makes matches (lobby_ws.rs, Java MatchmakerInfo).
      if (const JsonNode* const list = message.Get("queues"); list != nullptr && list->kind == JsonNode::Kind::Array) {
        const auto now = std::chrono::steady_clock::now();
        for (const JsonNode& queue : list->items) {
          const std::string name = queue.String("queue_name");
          if (name.empty()) {
            continue;
          }
          Service::MatchQueue& kept = s.queues[name];
          kept.name = name;
          if (const JsonNode* const size = queue.Get("team_size"); size != nullptr) {
            kept.teamSize = static_cast<int>(size->number);
          }
          if (const JsonNode* const players = queue.Get("num_players"); players != nullptr) {
            kept.players = static_cast<int>(players->number);
          }
          if (const JsonNode* const pop = queue.Get("queue_pop_time_delta"); pop != nullptr) {
            kept.popAt = now + std::chrono::milliseconds(static_cast<long long>(pop->number * 1000.0));
          }
        }
      }
    } else if (command == "search_info") {
      const std::string name = message.String("queue_name");
      if (message.String("state") == "start") {
        s.searching.insert(name);
      } else {
        s.searching.erase(name);
      }
      // A late "stop" doesn't take back a match already found (lobby_ws.rs update_search).
      if (s.matchmaking != "found") {
        s.matchmaking = s.searching.empty() ? "idle" : "searching";
      }
    } else if (command == "match_found") {
      s.matchmaking = "found";
      s.matchedQueue = message.String("queue_name");
      LogLine(("matchmaker: match found in " + s.matchedQueue).c_str());
      // Ready at once, as FAF's clients answer; the game_launch that follows starts the match.
      (void)s.lobby.Send(JsonObject({{"command", JsonString("match_ready")}}));
    } else if (command == "match_cancelled") {
      LogLine("matchmaker: the match was cancelled");
      s.matchmaking = "cancelled";
      s.searching.clear();
    } else if (command == "update_party") {
      // The whole party each time: its owner and members with their factions; one member or none when it broke up.
      s.partyMembers.clear();
      if (
        const JsonNode* const members = message.Get("members");
        members != nullptr && members->kind == JsonNode::Kind::Array
      ) {
        for (const JsonNode& member : members->items) {
          Service::PartyMember kept;
          if (const JsonNode* const id = member.Get("player"); id != nullptr) {
            kept.id = id->text;
          }
          if (
            const JsonNode* const factions = member.Get("factions");
            factions != nullptr && factions->kind == JsonNode::Kind::Array
          ) {
            for (const JsonNode& faction : factions->items) {
              kept.factions.push_back(Lower(faction.text));
            }
          }
          if (!kept.id.empty()) {
            s.partyMembers.push_back(std::move(kept));
          }
        }
      }
      const JsonNode* const owner = message.Get("owner");
      s.partyOwner = s.partyMembers.size() > 1 && owner != nullptr ? owner->text : "";
      if (s.partyMembers.size() <= 1) {
        s.partyMembers.clear();
      }
      s.partyInvites.erase(s.partyOwner);
      LogLine(("party: " + std::to_string(s.partyMembers.size()) + " members, owner " +
               (s.partyOwner.empty() ? std::string("none") : s.partyOwner))
                .c_str());
    } else if (command == "party_invite") {
      if (const JsonNode* const sender = message.Get("sender"); sender != nullptr && !sender->text.empty()) {
        s.partyInvites[sender->text] = std::chrono::steady_clock::now();
        LogLine(("party: invited by " + sender->text).c_str());
      }
    } else if (command == "kicked_from_party") {
      s.partyOwner.clear();
      s.partyMembers.clear();
      s.partyNote = "You were removed from the party.";
      LogLine("party: removed from the party");
    } else if (command == "notice") {
      s.notice = message.String("text");
    } else if (command == "game_launch") {
      // A matched game starts as any other; the search is over.
      s.matchmaking = "idle";
      s.searching.clear();
      BeginLaunch(s, message);
    }
  }
  PollServerGame(s);
  if (s.match == MatchState::Preparing && !s.serverGame && s.iceReady.load()) {
    if (moho::WLD_GetActiveSession() != nullptr) {
      // The launcher's background battle (a sandbox game behind it, battle.lua) ends first; FAF's lobby takes the UI
      // once no game runs. Asked once; the next polls wait for the session to go.
      if (!s.battleEnding) {
        s.battleEnding = true;
        LogLine("a match is ready while the launcher's battle runs; ending the battle first");
        if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
          (void)moho::SCR_LuaDoString(
            "local ok, battle = pcall(import, '/fafengine/modules/lua/ui/launcher/battle.lua') "
            "if ok and battle.EndForMatch then battle.EndForMatch() end",
            state
          );
        }
      }
    } else {
      s.battleEnding = false;
      if (s.iceThread.joinable()) {
        s.iceThread.join();
      }
      StartMatch(s);
    }
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
    } else if (s.autotestStep == 0 && s.autotestServer) {
      // Our server: the launcher's Create game dialog, Our server, AI seats, the map, Create (launcher.lua
      // TestServerHost), tried every 2 s until the control service's lobbies are live; the launcher joins by itself.
      if (s.match != MatchState::Idle) {
        s.autotestStep = 1;
      } else if (now - s.autotestSince > std::chrono::seconds(2)) {
        s.autotestSince = now;
        const bool live = !s.controls.empty() && s.controls.front()->GetState() == ControlServiceClient::State::Live;
        if (LuaPlus::LuaState* const state = moho::USER_GetLuaState(); state != nullptr && live) {
          (void)moho::SCR_LuaDoString(
            ("local launcher = __modules and __modules['/fafengine/modules/lua/ui/launcher/launcher.lua'] "
             "if launcher and launcher.TestServerHost then launcher.TestServerHost('" +
             s.autotestMap + "') end")
              .c_str(),
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
    } else if (
      s.autotestStep == 3 && s.autotestThenPreview && s.match == MatchState::Idle &&
      now - s.autotestSince > std::chrono::seconds(8)
    ) {
      // The next game in this process is a lockstep one: the changelog's unit preview, a single-player session.
      LogLine("autotest: back in the launcher; starting a single-player session (the unit preview)");
      if (LuaPlus::LuaState* const state = moho::USER_GetLuaState()) {
        (void)moho::SCR_LuaDoString(
          "local launcher = __modules and __modules['/fafengine/modules/lua/ui/launcher/launcher.lua'] "
          "if launcher and launcher.TestPreviewNow then launcher.TestPreviewNow() end",
          state
        );
      }
      s.autotestThenPreview = false;
      s.autotestStep = 7;
      s.autotestSince = now;
    } else if (s.autotestStep == 7 && moho::WLD_GetActiveSession() != nullptr) {
      LogLine("autotest: the single-player session runs");
      s.autotestStep = 8;
      s.autotestSince = now;
    } else if (s.autotestStep == 8 && moho::WLD_GetActiveSession() == nullptr) {
      LogLine("autotest: the single-player session ended");
      s.autotestStep = 3;
      s.autotestSince = now;
    } else if (s.autotestStep == 7 && now - s.autotestSince > std::chrono::seconds(60)) {
      LogLine("autotest: no single-player session 60 s after the preview");
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

std::filesystem::path moho::ONLINE_DataFolder()
{
  return DataFolder();
}

std::string moho::ONLINE_ApiBase()
{
  return GameEndpoints().apiUrl;
}

std::string moho::ONLINE_ContentBase()
{
  return CurrentServer().content;
}

std::string moho::ONLINE_ReplayBase()
{
  return CurrentServer().replay;
}

std::string moho::ONLINE_WebsiteBase()
{
  return CurrentServer().website;
}

std::expected<std::string, std::string> moho::ONLINE_AccessToken()
{
  // Made on the game's thread by the launcher's first call; a worker only reads it.
  if (!gService || !gService->SignedIn()) {
    return std::unexpected(std::string("not signed in to FAF"));
  }
  return gService->Tokens()();
}

std::filesystem::path moho::ONLINE_InitFile()
{
  return TheService().realInit;
}

void moho::ONLINE_Shutdown()
{
  moho::LIBRARY_Shutdown();
  if (gService && gService->match != MatchState::Idle && gService->match != MatchState::Failed) {
    gService->lobby.SetGameHandler({});
    moho::CFG_ClearLaunchArgs();
  }
  gService.reset();
}
