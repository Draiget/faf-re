#pragma once

// Engine addition (in-game launcher plan, WP3): our control service (docs/CONTROL_SERVICE.md) as the launcher sees it:
// the lobbies on our dedicated servers, live from GET /api/v1/events (Server-Sent Events), and a player's request for a
// game they host (POST /api/v1/requests), signed in with the player's FAF access token (accept_access_tokens).

#include <atomic>
#include <expected>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "online/Json.h"
#include "platform/Http.h"

namespace faf::online
{
  /** One seat of a lobby ("A lobby as its viewer sees it"). */
  struct ServerSeat
  {
    int seat = 0;
    std::string kind; ///< human or ai
    std::string name;
    std::string uid; ///< the FAF id's digits; empty for an open seat
    std::string ai;
  };

  /** One lobby on one of our servers. */
  struct ServerLobby
  {
    std::string key; ///< <host>/<id>
    std::string host;
    std::string name;
    std::string state; ///< starting, lobby, game, ended, failed, stopped
    std::string kind;
    std::string origin; ///< organised, hosted, host
    std::string tournament;
    std::string map;
    std::vector<ServerSeat> seats;
    bool stale = false;
    /** The viewer's own join line (`you.join`) or watch line (`you.watch`), when the lobby has a seat for them. */
    std::string join;
    std::string watch;
  };

  /** A game the signed-in player hosts on one of our servers (POST /api/v1/requests). */
  struct ServerGameRequest
  {
    std::string map;
    /** Seats after the player's own: each "human" (open) or an AI's name ("rush", ...). */
    std::vector<std::string> otherSeats;
    std::map<std::string, std::string> options;
    std::string host;   ///< empty: the service picks
    std::string region; ///< empty: any
    bool byPing = false;
  };

  class ControlServiceClient
  {
  public:
    enum class State
    {
      Stopped,
      Connecting,
      Live,
      Failed,
    };
    using TokenSource = std::function<std::expected<std::string, std::string>()>;

    /** `baseUrl`: the service's address, e.g. https://control.example.org (no trailing slash). */
    ControlServiceClient(std::string baseUrl, std::string userAgent);
    ~ControlServiceClient();
    ControlServiceClient(const ControlServiceClient&) = delete;
    ControlServiceClient& operator=(const ControlServiceClient&) = delete;

    void SetLog(std::function<void(const char*)> log);
    /** Where the player's FAF access token comes from, for the stream and for requests. */
    void SetTokens(TokenSource tokens);
    /** Follows the service's event stream on a thread of its own, reconnecting after 5 s when it drops. */
    void Start();
    void Stop();

    [[nodiscard]] State GetState() const noexcept
    {
      return mState.load();
    }
    /** The service's address as given. */
    [[nodiscard]] const std::string& Address() const noexcept
    {
      return mBaseUrl;
    }
    [[nodiscard]] std::string Message() const;
    [[nodiscard]] std::vector<ServerLobby> Lobbies() const;
    /** Asks for a game the player hosts; the service's answer (`request`, `ref`, `placement`) or why not. */
    [[nodiscard]] std::expected<JsonNode, std::string> RequestGame(const ServerGameRequest& request);

  private:
    void Run();
    void Event(const std::string& name, const std::string& data);
    void Log(const std::string& line) const;
    void SetMessage(std::string text);

    std::string mBaseUrl;
    std::string mUserAgent;
    TokenSource mTokens;
    std::function<void(const char*)> mLog;
    platform::http::Stream mStream;
    std::thread mThread;
    std::atomic<State> mState{State::Stopped};
    std::atomic<bool> mStop{false};
    mutable std::mutex mLock;
    std::string mMessage;
    std::map<std::string, ServerLobby> mLobbies;
  };

  /** One lobby object as the service sends it. */
  [[nodiscard]] ServerLobby ReadServerLobby(const JsonNode& node);
} // namespace faf::online
