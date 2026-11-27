// Engine addition (in-game launcher plan, WP2): FAF's lobby client (src/online/FafLobby.h).

#include "online/FafLobby.h"

#include <chrono>

#include "platform/Process.h"

namespace faf::online
{
  namespace
  {
    constexpr std::size_t kMaxWaitingMessages = 1000;

    /** The host part of a link ("wss://ws.faforever.com/?verify=x" -> "ws.faforever.com"). */
    std::string HostOf(
      const std::string& url
    )
    {
      const std::size_t start = url.find("://");
      const std::size_t from = start == std::string::npos ? 0 : start + 3;
      const std::size_t end = url.find_first_of(":/?", from);
      return url.substr(from, end == std::string::npos ? std::string::npos : end - from);
    }

    bool IsFafHost(
      const std::string& host
    )
    {
      return host == "faforever.com" || host.ends_with(".faforever.com");
    }

    std::optional<double> OptionalNumber(
      const JsonNode& node,
      const std::string& key
    )
    {
      const JsonNode* const value = node.Get(key);
      if (value == nullptr || value->kind != JsonNode::Kind::Number) {
        return std::nullopt;
      }
      return value->number;
    }

    FafGame ReadGame(
      const JsonNode& node
    )
    {
      FafGame game;
      if (const JsonNode* const uid = node.Get("uid")) {
        game.uid = uid->kind == JsonNode::Kind::Number || uid->kind == JsonNode::Kind::String ? uid->text : "";
      }
      game.title = node.String("title");
      game.host = node.String("host");
      game.mapname = node.String("mapname");
      game.featuredMod = node.String("featured_mod");
      game.state = node.String("state");
      game.visibility = node.String("visibility");
      game.ratingType = node.String("rating_type");
      game.gameType = node.String("game_type");
      game.numPlayers = static_cast<int>(node.Number("num_players"));
      game.maxPlayers = static_cast<int>(node.Number("max_players"));
      game.passwordProtected = node.Bool("password_protected");
      game.enforceRatingRange = node.Bool("enforce_rating_range");
      game.ratingMin = OptionalNumber(node, "rating_min");
      game.ratingMax = OptionalNumber(node, "rating_max");
      if (const JsonNode* const mods = node.Get("sim_mods"); mods != nullptr && mods->kind == JsonNode::Kind::Object) {
        for (const auto& [uid, name] : mods->members) {
          game.simMods.emplace_back(uid, name.text);
        }
      }
      if (const JsonNode* const teams = node.Get("teams"); teams != nullptr && teams->kind == JsonNode::Kind::Object) {
        for (const auto& [team, players] : teams->members) {
          std::vector<std::string> logins;
          if (players.kind == JsonNode::Kind::Array) {
            for (const JsonNode& player : players.items) {
              if (player.kind == JsonNode::Kind::String) {
                logins.push_back(player.text);
              }
            }
          }
          game.teams.emplace_back(team, std::move(logins));
        }
      }
      return game;
    }
  } // namespace

  FafLobby::FafLobby(
    FafLobbySettings settings
  )
    : mSettings(std::move(settings))
  {}

  FafLobby::~FafLobby()
  {
    Disconnect();
  }

  void FafLobby::SetLog(
    std::function<void(const char*)> log
  )
  {
    mLog = std::move(log);
  }

  void FafLobby::SetGameHandler(
    std::function<void(const JsonNode& message)> handler
  )
  {
    std::lock_guard<std::mutex> lock(mGameHandlerLock);
    mGameHandler = std::move(handler);
  }

  void FafLobby::Log(
    const std::string& line
  ) const
  {
    if (mLog) {
      mLog(("lobby: " + line).c_str());
    }
  }

  void FafLobby::SetMessage(
    std::string text
  )
  {
    Log(text);
    std::lock_guard<std::mutex> lock(mLock);
    mMessage = std::move(text);
  }

  void FafLobby::Fail(
    std::string why
  )
  {
    SetMessage(std::move(why));
    mState = State::Failed;
  }

  std::string FafLobby::Message() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mMessage;
  }

  std::string FafLobby::Login() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mLogin;
  }

  std::string FafLobby::PlayerId() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mPlayerId;
  }

  std::vector<FafGame> FafLobby::Games() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    std::vector<FafGame> games;
    games.reserve(mGames.size());
    for (const auto& [uid, game] : mGames) {
      games.push_back(game);
    }
    return games;
  }

  std::vector<JsonNode> FafLobby::TakeMessages()
  {
    std::lock_guard<std::mutex> lock(mLock);
    std::vector<JsonNode> taken;
    taken.swap(mMessages);
    return taken;
  }

  std::map<std::string, int> FafLobby::Counts() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mCounts;
  }

  void FafLobby::Connect(
    TokenSource tokens
  )
  {
    Disconnect();
    mStop = false;
    mAuthSent = false;
    mKicked = false;
    mState = State::Connecting;
    {
      std::lock_guard<std::mutex> lock(mLock);
      mGames.clear();
      mMessages.clear();
      mCounts.clear();
      mLogin.clear();
      mPlayerId.clear();
    }
    mThread = std::thread([this, tokens = std::move(tokens)] {
      Run(tokens);
    });
  }

  void FafLobby::Disconnect()
  {
    mStop = true;
    mSocket.Close();
    if (mThread.joinable()) {
      mThread.join();
    }
    if (mState.load() == State::SignedIn || mState.load() == State::Connecting) {
      mState = State::Disconnected;
    }
  }

  std::expected<void, std::string> FafLobby::Send(
    const JsonNode& message
  )
  {
    std::lock_guard<std::mutex> lock(mSendLock);
    return mSocket.SendText(ToJson(message) + "\n");
  }

  std::expected<void, std::string> FafLobby::HostGame(
    const FafHostRequest& request
  )
  {
    std::vector<std::pair<std::string, JsonNode>> members{
      {"command", JsonString("game_host")},
      {"title", JsonString(request.title)},
      {"mod", JsonString(request.featuredMod)},
      {"mapname", JsonString(request.mapname)},
      {"visibility", JsonString(request.visibility)},
      {"enforce_rating_range", JsonBool(request.enforceRatingRange)},
    };
    if (!request.password.empty()) {
      members.emplace_back("password", JsonString(request.password));
    }
    if (request.ratingMin) {
      members.emplace_back("rating_min", JsonNumber(*request.ratingMin));
    }
    if (request.ratingMax) {
      members.emplace_back("rating_max", JsonNumber(*request.ratingMax));
    }
    return Send(JsonObject(std::move(members)));
  }

  std::expected<void, std::string> FafLobby::JoinGame(
    const std::string& uid,
    const std::string& password
  )
  {
    std::vector<std::pair<std::string, JsonNode>> members{
      {"command", JsonString("game_join")},
      {"uid", JsonDigits(uid)},
    };
    if (!password.empty()) {
      members.emplace_back("password", JsonString(password));
    }
    return Send(JsonObject(std::move(members)));
  }

  void FafLobby::Run(
    TokenSource tokens
  )
  {
    const auto token = tokens();
    if (!token) {
      Fail("no FAF sign-in: " + token.error());
      return;
    }
    std::string url = mSettings.webSocketUrl;
    if (url.empty()) {
      platform::http::Call call;
      call.url = mSettings.userServiceUrl + "/lobby/access";
      call.headers = "Accept: application/json\r\nAuthorization: Bearer " + *token + "\r\n";
      call.userAgent = mSettings.userAgent + "/" + mSettings.version;
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body); !sent) {
        Fail("the lobby's address: " + sent.error());
        return;
      }
      const auto answer = ParseJson(body);
      if (status != 200 || !answer || answer->String("accessUrl").empty()) {
        Fail("the user service answered " + std::to_string(status) + " for the lobby's address");
        return;
      }
      url = answer->String("accessUrl");
    }
    if (!mSettings.testUniqueId.empty() && IsFafHost(HostOf(url))) {
      Fail("a test unique_id is never sent to FAF's own servers");
      return;
    }
    if (mSettings.testUniqueId.empty() && mSettings.uidProgram.empty()) {
      Fail("no faf-uid program set");
      return;
    }
    Log("connecting to " + HostOf(url));
    if (const auto opened = mSocket.Open(url, {}, mSettings.userAgent + "/" + mSettings.version); !opened) {
      Fail("the lobby: " + opened.error());
      return;
    }
    if (
      const auto sent = Send(JsonObject({
        {"command", JsonString("ask_session")},
        {"version", JsonString(mSettings.version)},
        {"user_agent", JsonString(mSettings.userAgent)},
      }));
      !sent
    ) {
      Fail("the lobby: " + sent.error());
      return;
    }
    std::string buffer;
    while (!mStop.load()) {
      std::string text;
      const auto received = mSocket.Receive(text);
      if (!received || *received == platform::http::WebSocket::Received::Closed) {
        if (mStop.load()) {
          break;
        }
        // The lobby's last notice says why it closed (signed in elsewhere, an admin); a close after sign-in is a
        // failure too, so the launcher tries again (unless it was a kick) and says why.
        std::string notice;
        {
          std::lock_guard<std::mutex> lock(mLock);
          notice = mLastNotice;
        }
        std::string why = received ? std::string("the lobby closed the connection") : received.error();
        if (mKicked.load()) {
          why = "FAF signed this session out" + (notice.empty() ? std::string() : ": " + notice);
        } else if (!notice.empty()) {
          why += " (" + notice + ")";
        }
        // A refused sign-in already said why (the lobby closes right after it): that reason stays.
        if (mState.load() != State::Failed) {
          Fail(why);
        }
        break;
      }
      buffer += text;
      for (std::size_t end; (end = buffer.find('\n')) != std::string::npos;) {
        const std::string line = buffer.substr(0, end);
        buffer.erase(0, end + 1);
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
          continue;
        }
        const auto message = ParseJson(line);
        if (!message) {
          Log("a message that isn't JSON: " + message.error());
          continue;
        }
        Handle(*message, *token);
      }
    }
  }

  void FafLobby::Handle(
    const JsonNode& message,
    const std::string& token
  )
  {
    const std::string command = message.String("command");
    {
      std::lock_guard<std::mutex> lock(mLock);
      ++mCounts[command];
    }
    if (message.String("target") == "game") {
      std::lock_guard<std::mutex> lock(mGameHandlerLock);
      if (mGameHandler) {
        mGameHandler(message);
        return;
      }
    }
    if (command == "session") {
      if (mAuthSent) {
        return;
      }
      const JsonNode* const session = message.Get("session");
      const std::string digits = session != nullptr ? session->text : std::string();
      if (digits.empty()) {
        Fail("the lobby's session has no number");
        return;
      }
      std::string uniqueId = mSettings.testUniqueId;
      if (uniqueId.empty()) {
        const auto uid = platform::process::Run(mSettings.uidProgram, {digits}, std::chrono::seconds(60));
        if (!uid || uid->exitCode != 0) {
          Fail("faf-uid failed: " + (uid ? "exit " + std::to_string(uid->exitCode) + " " + uid->err : uid.error()));
          return;
        }
        uniqueId = uid->out;
        while (!uniqueId.empty() && (uniqueId.back() == '\n' || uniqueId.back() == '\r' || uniqueId.back() == ' ')) {
          uniqueId.pop_back();
        }
      }
      mAuthSent = true;
      Log("session received; signing in");
      if (
        const auto sent = Send(JsonObject({
          {"command", JsonString("auth")},
          {"token", JsonString(token)},
          {"unique_id", JsonString(uniqueId)},
          {"session", JsonDigits(digits)},
        }));
        !sent
      ) {
        Fail("the lobby: " + sent.error());
      }
      return;
    }
    if (command == "ping") {
      std::vector<std::pair<std::string, JsonNode>> pong{{"command", JsonString("pong")}};
      if (const JsonNode* const id = message.Get("request_id")) {
        pong.emplace_back("request_id", *id);
      }
      (void)Send(JsonObject(std::move(pong)));
      return;
    }
    if (command == "game_info") {
      std::lock_guard<std::mutex> lock(mLock);
      const JsonNode* const list = message.Get("games");
      const auto apply = [this](const JsonNode& node) {
        FafGame game = ReadGame(node);
        if (game.uid.empty()) {
          return;
        }
        if (game.state == "closed") {
          mGames.erase(game.uid);
        } else {
          mGames[game.uid] = std::move(game);
        }
      };
      if (list != nullptr && list->kind == JsonNode::Kind::Array) {
        for (const JsonNode& item : list->items) {
          apply(item);
        }
      } else {
        apply(message);
      }
      return;
    }
    if (command == "welcome") {
      std::string login;
      std::string id;
      if (const JsonNode* const me = message.Get("me")) {
        login = me->String("login");
        if (const JsonNode* const number = me->Get("id")) {
          id = number->text;
        }
      }
      {
        std::lock_guard<std::mutex> lock(mLock);
        mLogin = login;
        mPlayerId = id;
      }
      mState = State::SignedIn;
      SetMessage("signed in to FAF's lobby as " + login);
    } else if (
      command == "authentication_failed" || command == "authentication_failure" || command == "login_failure"
    ) {
      Fail("the lobby refused the sign-in: " + message.String("text"));
    } else if (command == "notice") {
      SetMessage("notice (" + message.String("style") + "): " + message.String("text"));
      {
        std::lock_guard<std::mutex> lock(mLock);
        mLastNotice = message.String("text");
      }
      if (message.String("style") == "kick") {
        mKicked = true;
      }
    }
    std::lock_guard<std::mutex> lock(mLock);
    mMessages.push_back(message);
    if (mMessages.size() > kMaxWaitingMessages) {
      mMessages.erase(mMessages.begin());
    }
  }
} // namespace faf::online
