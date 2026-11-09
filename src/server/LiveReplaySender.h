#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "server/ReplayLog.h"

// Engine addition, dedicated server (plan WP15.3; design research/WP13.1-observer-stream.md): the game's live replay to
// FAF's replay service, as a game client sends its own (`VCR_OpenGPGNetURI` with a `gpgnet://` address in write mode:
// `OpenGPGNetSocket` connects, sends `'P'` and the path with its NUL, then the replay's bytes). A thread of its own sends
// the replay log, each byte no sooner than the delay after the server wrote it; a dropped connection is made again and
// the replay sent from its start, as the service takes whole replays. Linux only, as the server.

namespace faf::server
{
  /** `gpgnet://host[:port]/path` (port 15000 without one, as the engine's): host, port and path (from its `/`). */
  struct SGpgNetAddress
  {
    std::string host;
    std::uint16_t port = 15000;
    std::string path;
  };
  [[nodiscard]] std::optional<SGpgNetAddress> ParseGpgNetAddress(const std::string& uri);

  class CLiveReplaySender
  {
  public:
    using Clock = std::function<std::uint64_t()>; // microseconds, the replay log's clock

    CLiveReplaySender(std::shared_ptr<const CReplayLog> log, Clock clock, double delaySeconds, SGpgNetAddress to);
    ~CLiveReplaySender();
    CLiveReplaySender(const CLiveReplaySender&) = delete;
    CLiveReplaySender& operator=(const CLiveReplaySender&) = delete;

    void Start();
    void Stop();
    /** The whole replay has gone (the log is finished and every byte sent), or the sender gave up. */
    [[nodiscard]] bool Done() const noexcept { return mDone.load(std::memory_order_relaxed); }
    [[nodiscard]] std::vector<std::string> TakeNews();

  private:
    void Run();
    void Say(std::string line);

    std::shared_ptr<const CReplayLog> mLog;
    Clock mClock;
    std::uint64_t mDelayUs;
    SGpgNetAddress mTo;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<bool> mDone{false};
    std::mutex mLock;
    std::vector<std::string> mNews;
  };
} // namespace faf::server
