#pragma once

// Engine addition (in-game launcher plan, WP4): the launcher's GPGNet side of one FAF match, as
// docs/LAUNCHER_NATIVE_NETWORK.md asks of a launcher with no ICE adapter. A listener on 127.0.0.1 the game connects
// to (its /gpgnet); on the game's GameState Idle, IceServers then CreateLobby (tools/seat native.go, faf-netbridge
// Bridge::HandleGame); the lobby's messages for the game held until the game's GameState Lobby, as FAF's adapter
// holds them; every game message passed to the lobby as {"command", "target": "game", "args"}.

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "netbridge/GpgNet.h"
#include "netbridge/Socket.h"
#include "online/Json.h"

namespace faf::online
{
  struct GameLinkSettings
  {
    std::string login;
    std::int32_t playerId = 0;
    /** CreateLobby's first argument: 1 for matchmaker games, else 0. */
    int initMode = 0;
    /** IceServers' text: the API's ICE session object or a list of {urls, username, credential}. */
    std::string iceServersJson = "[]";
  };

  class GameLink
  {
  public:
    using ToLobby = std::function<void(const JsonNode& message)>;

    GameLink();
    ~GameLink();
    GameLink(const GameLink&) = delete;
    GameLink& operator=(const GameLink&) = delete;

    void SetLog(std::function<void(const char*)> log);
    /** Opens the listener on 127.0.0.1; its port, for the game's /gpgnet 127.0.0.1:<port>. */
    [[nodiscard]] std::expected<std::uint16_t, std::string> Listen();
    /** Waits for the game on a thread of its own; its messages go to `toLobby`. */
    void Start(GameLinkSettings settings, ToLobby toLobby);
    /** A lobby message for the game ("target": "game"): sent once the game's lobby is up, held until then. */
    void FromLobby(const JsonNode& message);
    void Stop();

    [[nodiscard]] bool Connected() const noexcept
    {
      return mConnected.load();
    }
    [[nodiscard]] std::string GameState() const;

  private:
    void Run();
    void Handle(const netbridge::GpgMessage& message);
    void Write(const netbridge::GpgMessage& message);
    void Log(const std::string& line) const;

    GameLinkSettings mSettings;
    ToLobby mToLobby;
    std::function<void(const char*)> mLog;
    netbridge::SocketHandle mListener = netbridge::kInvalidSocket;
    netbridge::SocketHandle mGame = netbridge::kInvalidSocket;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<bool> mConnected{false};
    mutable std::mutex mLock; ///< mGame's sends, the state, the held messages
    std::string mGameState;
    bool mInLobby = false;
    std::vector<netbridge::GpgMessage> mHeld;
  };

  /** A lobby message for the game as GPGNet: its args' numbers as ints, the rest as strings. */
  [[nodiscard]] netbridge::GpgMessage LobbyToGpg(const JsonNode& message);
  /** A game's GPGNet message as the lobby takes it, the game's "/t" and "/n" as a tab and a newline (the adapter's). */
  [[nodiscard]] JsonNode GpgToLobby(const netbridge::GpgMessage& message);
} // namespace faf::online
