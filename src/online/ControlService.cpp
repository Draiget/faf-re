// Engine addition (in-game launcher plan, WP3): the control-service client (src/online/ControlService.h).

#include "online/ControlService.h"

#include <chrono>

namespace faf::online
{
  ServerLobby ReadServerLobby(
    const JsonNode& node
  )
  {
    ServerLobby lobby;
    lobby.key = node.String("key");
    lobby.host = node.String("host");
    lobby.name = node.String("name");
    lobby.state = node.String("state");
    lobby.kind = node.String("kind");
    lobby.origin = node.String("origin");
    lobby.tournament = node.String("tournament");
    lobby.map = node.String("map");
    lobby.stale = node.Bool("stale");
    if (const JsonNode* const seats = node.Get("seats"); seats != nullptr && seats->kind == JsonNode::Kind::Array) {
      for (const JsonNode& item : seats->items) {
        ServerSeat seat;
        seat.seat = static_cast<int>(item.Number("seat"));
        seat.kind = item.String("kind");
        seat.name = item.String("name");
        if (const JsonNode* const uid = item.Get("uid"); uid != nullptr && uid->kind == JsonNode::Kind::Number) {
          seat.uid = uid->text;
        }
        seat.ai = item.String("ai");
        lobby.seats.push_back(std::move(seat));
      }
    }
    if (const JsonNode* const you = node.Get("you"); you != nullptr && you->kind == JsonNode::Kind::Object) {
      lobby.join = you->String("join");
      lobby.watch = you->String("watch");
    }
    return lobby;
  }

  ControlServiceClient::ControlServiceClient(
    std::string baseUrl,
    std::string userAgent
  )
    : mBaseUrl(std::move(baseUrl))
    , mUserAgent(std::move(userAgent))
  {}

  ControlServiceClient::~ControlServiceClient()
  {
    Stop();
  }

  void ControlServiceClient::SetLog(
    std::function<void(const char*)> log
  )
  {
    mLog = std::move(log);
  }

  void ControlServiceClient::Log(
    const std::string& line
  ) const
  {
    if (mLog) {
      mLog(("control service: " + line).c_str());
    }
  }

  void ControlServiceClient::SetMessage(
    std::string text
  )
  {
    Log(text);
    std::lock_guard<std::mutex> lock(mLock);
    mMessage = std::move(text);
  }

  std::string ControlServiceClient::Message() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mMessage;
  }

  std::vector<ServerLobby> ControlServiceClient::Lobbies() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    std::vector<ServerLobby> lobbies;
    lobbies.reserve(mLobbies.size());
    for (const auto& [key, lobby] : mLobbies) {
      lobbies.push_back(lobby);
    }
    return lobbies;
  }

  void ControlServiceClient::SetTokens(
    TokenSource tokens
  )
  {
    mTokens = std::move(tokens);
  }

  void ControlServiceClient::Start()
  {
    Stop();
    mStop = false;
    mState = State::Connecting;
    mThread = std::thread([this] {
      Run();
    });
  }

  void ControlServiceClient::Stop()
  {
    mStop = true;
    mStream.Close();
    if (mThread.joinable()) {
      mThread.join();
    }
    mState = State::Stopped;
  }

  void ControlServiceClient::Event(
    const std::string& name,
    const std::string& data
  )
  {
    const auto parsed = ParseJson(data);
    if (!parsed) {
      Log("an event that isn't JSON: " + name);
      return;
    }
    std::lock_guard<std::mutex> lock(mLock);
    if (name == "snapshot") {
      mLobbies.clear();
      if (
        const JsonNode* const lobbies = parsed->Get("lobbies");
        lobbies != nullptr && lobbies->kind == JsonNode::Kind::Array
      ) {
        for (const JsonNode& item : lobbies->items) {
          ServerLobby lobby = ReadServerLobby(item);
          if (!lobby.key.empty()) {
            mLobbies[lobby.key] = std::move(lobby);
          }
        }
      }
    } else if (name == "lobby") {
      ServerLobby lobby = ReadServerLobby(*parsed);
      if (!lobby.key.empty()) {
        mLobbies[lobby.key] = std::move(lobby);
      }
    } else if (name == "lobby_removed") {
      mLobbies.erase(parsed->String("key"));
    }
  }

  void ControlServiceClient::Run()
  {
    bool first = true;
    while (!mStop.load()) {
      if (!first) {
        for (int i = 0; i < 50 && !mStop.load(); ++i) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (mStop.load()) {
          break;
        }
      }
      first = false;
      const auto token =
        mTokens ? mTokens() : std::expected<std::string, std::string>(std::unexpected("no tokens set"));
      if (!token) {
        mState = State::Failed;
        SetMessage("no FAF sign-in: " + token.error());
        continue;
      }
      platform::http::Call call;
      call.url = mBaseUrl + "/api/v1/events";
      call.headers = "Accept: text/event-stream\r\nAuthorization: Bearer " + *token + "\r\n";
      call.userAgent = mUserAgent;
      const auto status = mStream.Open(call);
      if (!status || *status != 200) {
        mState = State::Failed;
        SetMessage(status ? "the service answered " + std::to_string(*status) : status.error());
        continue;
      }
      mState = State::Live;
      SetMessage("following " + mBaseUrl);
      // Server-Sent Events: "event:" and "data:" lines, a blank line ends one; ":" lines keep the stream open.
      std::string buffer;
      std::string event = "message";
      std::string data;
      while (!mStop.load()) {
        const auto part = mStream.Read();
        if (!part || part->empty()) {
          if (!mStop.load()) {
            mState = State::Connecting;
            SetMessage(part ? "the event stream ended" : part.error());
          }
          break;
        }
        buffer += *part;
        for (std::size_t end; (end = buffer.find('\n')) != std::string::npos;) {
          std::string line = buffer.substr(0, end);
          buffer.erase(0, end + 1);
          if (!line.empty() && line.back() == '\r') {
            line.pop_back();
          }
          if (line.empty()) {
            if (!data.empty()) {
              Event(event, data);
            }
            event = "message";
            data.clear();
          } else if (line.starts_with("event:")) {
            event = line.substr(line.size() > 6 && line[6] == ' ' ? 7 : 6);
          } else if (line.starts_with("data:")) {
            data += (data.empty() ? "" : "\n") + line.substr(line.size() > 5 && line[5] == ' ' ? 6 : 5);
          }
        }
      }
      mStream.Close();
    }
  }

  std::expected<JsonNode, std::string> ControlServiceClient::RequestGame(
    const ServerGameRequest& request
  )
  {
    const auto token = mTokens ? mTokens() : std::expected<std::string, std::string>(std::unexpected("no tokens set"));
    if (!token) {
      return std::unexpected("no FAF sign-in: " + token.error());
    }
    std::vector<JsonNode> seats{JsonObject({{"kind", JsonString("human")}})};
    for (const std::string& other : request.otherSeats) {
      seats.push_back(
        other == "human" ? JsonObject({{"kind", JsonString("human")}})
                         : JsonObject({{"kind", JsonString("ai")}, {"ai", JsonString(other)}})
      );
    }
    std::vector<std::pair<std::string, JsonNode>> options;
    for (const auto& [key, value] : request.options) {
      options.emplace_back(key, JsonString(value));
    }
    const JsonNode body = JsonObject({
      {"map", JsonString(request.map)},
      {"seats", JsonArray(std::move(seats))},
      {"options", JsonObject(std::move(options))},
      {"host", JsonString(request.host)},
      {"region", JsonString(request.region)},
      {"placement", JsonString(request.byPing ? "ping" : "load")},
    });
    platform::http::Call call;
    call.method = "POST";
    call.url = mBaseUrl + "/api/v1/requests";
    call.headers =
      "Content-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer " + *token + "\r\n";
    call.body = ToJson(body);
    call.userAgent = mUserAgent;
    long status = 0;
    std::string text;
    if (const auto sent = platform::http::Request(call, status, text); !sent) {
      return std::unexpected(sent.error());
    }
    auto answer = ParseJson(text);
    if (!answer) {
      return std::unexpected("the service answered " + std::to_string(status) + " with text that isn't JSON");
    }
    if (status != 200 || !answer->Bool("ok")) {
      const std::string why = answer->String("error");
      return std::unexpected("the service answered " + std::to_string(status) + (why.empty() ? "" : ": " + why));
    }
    return std::move(*answer);
  }
} // namespace faf::online
