#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "remote/net/UdpSocket.h"
#include "server/ReplayLog.h"

// Engine addition, dedicated server (plan WP13.1; design research/WP13.1-observer-stream.md): observers watch the game
// as a live replay. A game client opens `gpgnet://<server>:<port>/<token>` with `/replay` (the engine's replay reader,
// `OpenGPGNetSocket`): it connects, sends `'G'` and the path with its NUL, and reads the replay's bytes. This listener
// answers those requests from its own thread: an allowed token gets the replay log from its start, each byte no sooner
// than the observer delay after the server wrote it; when the game is over and everything has gone, the connection
// closes. Linux only, as the server.

namespace faf::server
{
  class CObserverListener
  {
  public:
    using Clock = std::function<std::uint64_t()>; // microseconds, the same steady clock as the replay log's

    CObserverListener(std::shared_ptr<const CReplayLog> log, Clock clock, double delaySeconds);
    ~CObserverListener();
    CObserverListener(const CObserverListener&) = delete;
    CObserverListener& operator=(const CObserverListener&) = delete;

    /** Listens and starts the thread. */
    [[nodiscard]] bool Start(const remote::net::SEndpoint& at, std::string& error);
    void Stop();

    /** From any thread: a token an observer may watch with (the match file's, or one the organiser approved). */
    void AllowToken(std::string token);
    /** Plan WP13.2: a referee's token (the match file's `MatchReferees`): it watches with no delay. */
    void AllowReferee(std::string token);
    /** Plan WP17.9: the organiser said no: a request held with this token closes, and a later one is refused. */
    void RefuseToken(std::string token);
    /**
     * Plan WP17.9, before `Start`: a request with a token not allowed yet is held, not refused, until the organiser
     * answers (`AllowToken`, `RefuseToken`) or 5 minutes pass. Each one is reported once (`TakeRequests`).
     */
    void HoldUnknownTokens() noexcept { mHoldUnknown = true; }
    struct SRequest
    {
      std::string token;
      std::string from;
    };
    [[nodiscard]] std::vector<SRequest> TakeRequests();
    /** Watching now. */
    [[nodiscard]] std::size_t Observers() const noexcept { return mObservers.load(std::memory_order_relaxed); }
    /** The game's replay is finished and every observer has had all of it (or none is watching). */
    [[nodiscard]] bool AllSent() const noexcept { return mAllSent.load(std::memory_order_relaxed); }
    /** Lines worth the console: who started watching, a refused request, who has seen it all. */
    [[nodiscard]] std::vector<std::string> TakeNews();

  private:
    struct SConnection;
    void Run();
    void Say(std::string line);

    std::shared_ptr<const CReplayLog> mLog;
    Clock mClock;
    std::uint64_t mDelayUs;
    int mListenSocket = -1;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<std::size_t> mObservers{0};
    std::atomic<bool> mAllSent{false};
    std::mutex mLock;           // the tokens and the news
    std::set<std::string> mTokens;
    std::set<std::string> mRefused;
    std::set<std::string> mReferees;
    std::vector<SRequest> mRequests;
    bool mHoldUnknown = false;
    std::vector<std::string> mNews;
  };
} // namespace faf::server
