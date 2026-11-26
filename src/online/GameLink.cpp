// Engine addition (in-game launcher plan, WP4): the launcher's GPGNet side of a match (src/online/GameLink.h).

#include "online/GameLink.h"

#include <cmath>

namespace faf::online
{
  using netbridge::GpgArg;
  using netbridge::GpgMessage;

  namespace
  {
    /** The game writes a tab as "/t" and a newline as "/n" (faf-netbridge Bridge.cpp GameString). */
    std::string GameString(
      std::string text
    )
    {
      for (const auto& [from, to] : {std::pair<const char*, const char*>{"/t", "\t"}, {"/n", "\n"}}) {
        std::size_t at = 0;
        while ((at = text.find(from, at)) != std::string::npos) {
          text.replace(at, 2, to);
          at += 1;
        }
      }
      return text;
    }
  } // namespace

  GpgMessage LobbyToGpg(
    const JsonNode& message
  )
  {
    GpgMessage out;
    out.command = message.String("command");
    if (const JsonNode* const args = message.Get("args"); args != nullptr && args->kind == JsonNode::Kind::Array) {
      for (const JsonNode& arg : args->items) {
        if (arg.kind == JsonNode::Kind::Number) {
          out.args.push_back(GpgArg::Int(static_cast<std::int32_t>(std::llround(arg.number))));
        } else if (arg.kind == JsonNode::Kind::Bool) {
          out.args.push_back(GpgArg::Int(arg.boolean ? 1 : 0)); // GPGNet has no booleans
        } else if (arg.kind == JsonNode::Kind::String) {
          out.args.push_back(GpgArg::Str(arg.text));
        } else {
          out.args.push_back(GpgArg::Str(ToJson(arg)));
        }
      }
    }
    return out;
  }

  JsonNode GpgToLobby(
    const GpgMessage& message
  )
  {
    std::vector<JsonNode> args;
    for (const GpgArg& arg : message.args) {
      args.push_back(arg.kind == GpgArg::Kind::Int ? JsonNumber(arg.number) : JsonString(GameString(arg.text)));
    }
    return JsonObject({
      {"command", JsonString(message.command)},
      {"target", JsonString("game")},
      {"args", JsonArray(std::move(args))},
    });
  }

  GameLink::GameLink()
  {
    (void)netbridge::SocketsInit();
  }

  GameLink::~GameLink()
  {
    Stop();
  }

  void GameLink::SetLog(
    std::function<void(const char*)> log
  )
  {
    mLog = std::move(log);
  }

  void GameLink::Log(
    const std::string& line
  ) const
  {
    if (mLog) {
      mLog(("game link: " + line).c_str());
    }
  }

  std::string GameLink::GameState() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mGameState;
  }

  std::expected<std::uint16_t, std::string> GameLink::Listen()
  {
    if (mListener == netbridge::kInvalidSocket) {
      mListener = netbridge::ListenTcp("127.0.0.1", 0);
      if (mListener == netbridge::kInvalidSocket) {
        return std::unexpected(
          "no GPGNet listener on 127.0.0.1 (error " + std::to_string(netbridge::LastSocketError()) + ")"
        );
      }
    }
    return netbridge::LocalPort(mListener);
  }

  void GameLink::Start(
    GameLinkSettings settings,
    ToLobby toLobby
  )
  {
    mSettings = std::move(settings);
    mToLobby = std::move(toLobby);
    mStop = false;
    mThread = std::thread([this] {
      Run();
    });
  }

  void GameLink::Stop()
  {
    mStop = true;
    {
      std::lock_guard<std::mutex> lock(mLock);
      netbridge::CloseSocket(mListener); // ends a waiting accept
      netbridge::CloseSocket(mGame);     // ends a waiting recv
    }
    if (mThread.joinable()) {
      mThread.join();
    }
    mConnected = false;
  }

  void GameLink::Run()
  {
    const netbridge::SocketHandle game = ::accept(mListener, nullptr, nullptr);
    if (game == netbridge::kInvalidSocket) {
      if (!mStop.load()) {
        Log("the game didn't connect");
      }
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mLock);
      mGame = game;
    }
    mConnected = true;
    Log("the game connected");
    netbridge::GpgDecoder decoder;
    char buffer[16384];
    while (!mStop.load()) {
      const int got = ::recv(game, buffer, sizeof(buffer), 0);
      if (got <= 0) {
        break;
      }
      decoder.Feed(buffer, static_cast<std::size_t>(got));
      bool bad = false;
      while (auto message = decoder.Next(&bad)) {
        Handle(*message);
      }
      if (bad) {
        Log("the game sent a broken GPGNet message");
        break;
      }
    }
    mConnected = false;
    {
      std::lock_guard<std::mutex> lock(mLock);
      netbridge::CloseSocket(mGame); // no-op when Stop closed it
      mInLobby = false;
    }
    if (!mStop.load()) {
      Log("the game's GPGNet connection closed");
    }
  }

  void GameLink::Handle(
    const GpgMessage& message
  )
  {
    if (message.command == "GameState" && !message.args.empty()) {
      const std::string state = message.args[0].text;
      std::vector<GpgMessage> held;
      {
        std::lock_guard<std::mutex> lock(mLock);
        mGameState = state;
        if (state == "Lobby") {
          mInLobby = true;
          held.swap(mHeld);
        }
      }
      if (state == "Idle") {
        Write({"IceServers", {GpgArg::Str(mSettings.iceServersJson)}});
        Write(
          {"CreateLobby",
           {GpgArg::Int(mSettings.initMode),
            GpgArg::Int(0),
            GpgArg::Str(mSettings.login),
            GpgArg::Int(mSettings.playerId),
            GpgArg::Int(1)}}
        );
      }
      for (const GpgMessage& out : held) {
        Write(out);
      }
    }
    if (mToLobby) {
      mToLobby(GpgToLobby(message));
    }
  }

  void GameLink::FromLobby(
    const JsonNode& message
  )
  {
    GpgMessage out = LobbyToGpg(message);
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (!mInLobby) {
        mHeld.push_back(std::move(out));
        return;
      }
    }
    Write(out);
  }

  void GameLink::Write(
    const GpgMessage& message
  )
  {
    const std::string bytes = netbridge::EncodeGpg(message);
    std::lock_guard<std::mutex> lock(mLock);
    if (mGame == netbridge::kInvalidSocket || !netbridge::SendAll(mGame, bytes.data(), bytes.size())) {
      return;
    }
    Log("to game: " + netbridge::DescribeGpg(message));
  }
} // namespace faf::online
