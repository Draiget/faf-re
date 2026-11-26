#pragma once

// Engine addition (in-game launcher plan, WP4): a match's live replay, passed on to FAF's replay service, as
// FAForeverRustClient's infra/replay_relay.rs and the Python client's fa/replayserver.py do. The game streams its
// replay to /savereplay gpgnet://127.0.0.1:<port>/<uid>/<name>.SCFAreplay, opening with "P/<uid>/<name>\0"; FAF's
// vault entry for the game is built from the streams clients post this way. GET <user service>/replay/access gives
// a one-time WebSocket address; every byte goes there as binary frames, the opening kept. After a drop the whole
// stream is sent again from its start on a new connection: the replay service keeps the longest one it got.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "netbridge/Socket.h"
#include "platform/Http.h"

namespace faf::online
{
  struct ReplayRelaySettings
  {
    std::string userServiceUrl = "https://user.faforever.com";
    /** A WebSocket address used as it is, instead of asking the user service (tests, a local stack). */
    std::string webSocketUrl;
    std::string userAgent = "faf-re-client";
    /** The most a stream may hold (as the Rust client's MAX_REPLAY_BYTES). */
    std::size_t maxBytes = 512u * 1024u * 1024u;
  };

  class ReplayRelay
  {
  public:
    using TokenSource = std::function<std::expected<std::string, std::string>()>;

    explicit ReplayRelay(ReplayRelaySettings settings = {});
    ~ReplayRelay();
    ReplayRelay(const ReplayRelay&) = delete;
    ReplayRelay& operator=(const ReplayRelay&) = delete;

    void SetLog(std::function<void(const char*)> log);
    /** Opens the listener on 127.0.0.1; its port, for the game's /savereplay. */
    [[nodiscard]] std::expected<std::uint16_t, std::string> Listen();
    /** Takes the game's stream on a thread of its own and passes it on. */
    void Start(TokenSource tokens);
    /** Waits until the stream ended and its last bytes were sent (or `limit` passed); true when they were. */
    bool Finish(std::chrono::milliseconds limit);
    void Stop();

    [[nodiscard]] std::uint64_t BytesFromGame() const noexcept
    {
      return mFromGame.load();
    }
    [[nodiscard]] std::uint64_t BytesSent() const noexcept
    {
      return mSent.load();
    }

  private:
    void Run();
    /** Sends what the server hasn't had on this connection, connecting (and sending from the start) first if needed. */
    bool Forward();
    /** A connection that failed: logged when the reason differs from the last one; the next try waits 2 s, doubling up
     *  to 30 s (the game writes many times a second, and each write would try again). */
    void Failed(const std::string& why);
    void Log(const std::string& line) const;

    ReplayRelaySettings mSettings;
    TokenSource mTokens;
    std::function<void(const char*)> mLog;
    netbridge::SocketHandle mListener = netbridge::kInvalidSocket;
    netbridge::SocketHandle mGame = netbridge::kInvalidSocket;
    platform::http::WebSocket mSocket;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<std::uint64_t> mFromGame{0};
    std::atomic<std::uint64_t> mSent{0};
    std::string mStream;       ///< the reader thread's own: every byte the game sent
    std::size_t mSentHere = 0; ///< how much of mStream went out on the current connection
    bool mConnected = false;
    std::chrono::steady_clock::time_point mNextTry{}; ///< no new connection before this, after a failure
    std::chrono::seconds mBackoff{0};
    std::string mLastFailure;
    std::mutex mDoneLock;
    std::condition_variable mDoneSignal;
    bool mDone = false; ///< the stream ended and the relay stopped trying
    bool mAllSent = false;
  };
} // namespace faf::online
