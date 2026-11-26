#pragma once

// Engine addition (in-game launcher plan, WP2): FAF's lobby, as the official client and the Rust client speak it.
// GET <user service>/lobby/access for a one-time WebSocket address; ask_session; FAF's faf-uid run with the session
// for `unique_id`; auth; then newline-separated JSON messages (FAForeverRustClient lobby_ws.rs, faf-message-broker's
// SessionHandler, FAForever/server lobbyconnection.py). Checked live on 2026-11-26 (tmp/claude/ingame-client/wp0).

#include <atomic>
#include <expected>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "online/Json.h"
#include "platform/Http.h"

namespace faf::online
{
  struct FafLobbySettings
  {
    std::string userServiceUrl = "https://user.faforever.com";
    /** A WebSocket address used as it is, instead of asking the user service (a local FAF stack). */
    std::string webSocketUrl;
    /** What the lobby stores and shows for this program (ask_session's user_agent). */
    std::string userAgent = "faf-re-client";
    std::string version = "0.0.0";
    /** FAF's faf-uid program, run with the session number; its output is auth's `unique_id`. */
    std::string uidProgram;
    /**
     * Sent as `unique_id` instead of faf-uid's output, for a local FAF stack only. Refused for an address on
     * faforever.com: FAF's policy server judges that value (tmp/claude/ingame-client/wp0, plan section 4).
     */
    std::string testUniqueId;
  };

  /** One game, from `game_info` (FAForever/server game.py to_dict). */
  struct FafGame
  {
    std::string uid; ///< the id's digits
    std::string title;
    std::string host;
    std::string mapname;
    std::string featuredMod;
    std::string state; ///< open, playing (closed games are dropped)
    std::string visibility;
    std::string ratingType;
    std::string gameType;
    int numPlayers = 0;
    int maxPlayers = 0;
    bool passwordProtected = false;
    bool enforceRatingRange = false;
    std::optional<double> ratingMin;
    std::optional<double> ratingMax;
    std::vector<std::pair<std::string, std::string>> simMods; ///< uid, name
  };

  /** What `game_host` takes (lobbyconnection.py command_game_host). */
  struct FafHostRequest
  {
    std::string title;
    std::string mapname;
    std::string featuredMod = "faf";
    std::string visibility = "public";
    std::string password; ///< empty: none
    std::optional<double> ratingMin;
    std::optional<double> ratingMax;
    bool enforceRatingRange = false;
  };

  class FafLobby
  {
  public:
    enum class State
    {
      Disconnected,
      Connecting,
      SignedIn,
      Failed,
    };

    /** A current access token (with the `lobby` scope). */
    using TokenSource = std::function<std::expected<std::string, std::string>()>;

    explicit FafLobby(FafLobbySettings settings);
    ~FafLobby();
    FafLobby(const FafLobby&) = delete;
    FafLobby& operator=(const FafLobby&) = delete;

    /** Where lines for a log go ("lobby: ..."); never a token or unique_id. */
    void SetLog(std::function<void(const char*)> log);
    /**
     * Where the lobby's messages for the game go ("target": "game": HostGame, JoinGame, ConnectToPeer, IceMsg...),
     * on the lobby's thread, instead of TakeMessages. Set before Connect, or while no match runs.
     */
    void SetGameHandler(std::function<void(const JsonNode& message)> handler);
    /** Signs in on a thread of its own; GetState says how it goes. */
    void Connect(TokenSource tokens);
    void Disconnect();

    [[nodiscard]] State GetState() const noexcept
    {
      return mState.load();
    }
    [[nodiscard]] std::string Message() const;
    /** The login and id `welcome` named, once signed in. */
    [[nodiscard]] std::string Login() const;
    [[nodiscard]] std::string PlayerId() const;
    /** The games the lobby announced and hasn't closed, in no particular order. */
    [[nodiscard]] std::vector<FafGame> Games() const;
    /**
     * The messages other than the handshake's, `ping` and `game_info`, in the order they came (welcome, notice,
     * player_info, social, game_launch, ...). At most 1000 wait; older ones are dropped.
     */
    [[nodiscard]] std::vector<JsonNode> TakeMessages();
    /** How many messages of each command came, all of them included. */
    [[nodiscard]] std::map<std::string, int> Counts() const;

    [[nodiscard]] std::expected<void, std::string> Send(const JsonNode& message);
    [[nodiscard]] std::expected<void, std::string> HostGame(const FafHostRequest& request);
    [[nodiscard]] std::expected<void, std::string> JoinGame(const std::string& uid, const std::string& password = {});

  private:
    void Run(TokenSource tokens);
    void Handle(const JsonNode& message, const std::string& token);
    void Fail(std::string why);
    void Log(const std::string& line) const;
    void SetMessage(std::string text);

    FafLobbySettings mSettings;
    std::function<void(const char*)> mLog;
    std::mutex mGameHandlerLock;
    std::function<void(const JsonNode&)> mGameHandler;
    platform::http::WebSocket mSocket;
    std::thread mThread;
    std::atomic<State> mState{State::Disconnected};
    std::atomic<bool> mStop{false};
    bool mAuthSent = false; ///< the reader thread's own
    /** One send at a time: the reader thread answers ping while the caller hosts or joins. */
    std::mutex mSendLock;
    mutable std::mutex mLock;
    std::string mMessage;
    std::string mLogin;
    std::string mPlayerId;
    std::map<std::string, FafGame> mGames;
    std::vector<JsonNode> mMessages;
    std::map<std::string, int> mCounts;
  };
} // namespace faf::online
