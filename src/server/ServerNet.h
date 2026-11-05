#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "remote/net/GameLinks.h"

// Engine addition, dedicated server (plan WP1.1, WP3.5, WP10.1, WP10.5): the players' network. Its own
// thread takes what arrives on the socket and hands each player's commands to their seat, so a slow
// sim beat delays nobody's connection and a burst of datagrams delays no beat.
//
// A player who hasn't joined when the wait is over, or who stays away past the reconnect window, is
// ejected as a lockstep game would eject them. A game whose seats nobody ever sat in has no reason to run.

namespace moho
{
  class CClientManagerImpl;
}

namespace faf::remote
{
  class CServerClient;
}

namespace faf::server
{
  struct SServerNetConfig
  {
    remote::net::SEndpoint listen;
    double joinSeconds = 120.0;
    double reconnectSeconds = 60.0;
  };

  class CServerNet final : private remote::net::CServerLinks::IEvents
  {
  public:
    explicit CServerNet(const SServerNetConfig& config);
    ~CServerNet() override;
    CServerNet(const CServerNet&) = delete;
    CServerNet& operator=(const CServerNet&) = delete;

    void AddSeat(std::int32_t uid, const char* name, const std::string& token, remote::CServerClient& seat);

    /** Binds the socket and starts the thread. */
    [[nodiscard]] bool Start(std::string& error);
    /** Stops the thread; no seat is touched after this returns. */
    void Stop();

    /** The newest beat, for the players. */
    void NoteBeat(std::int32_t beat) noexcept { mBeat.store(beat, std::memory_order_relaxed); }

    /** Lines for the console since the last call. */
    [[nodiscard]] std::vector<std::string> TakeNews();
    /** The wait is over and nobody ever joined. */
    [[nodiscard]] bool NobodyCame() const noexcept { return mNobodyCame.load(std::memory_order_relaxed); }

    [[nodiscard]] remote::net::SEndpoint Local() const noexcept { return mLinks.Local(); }

  private:
    struct SSeat
    {
      std::string name;
      remote::CServerClient* seat = nullptr;
      bool joinedEver = false;
      bool loaded = false;
      bool lost = false;
      bool gone = false;
      std::uint64_t lostAtUs = 0;
    };

    void Run();
    void Tick(std::uint64_t nowUs);
    void Remove(std::int32_t uid, SSeat& seat, const std::string& why);
    void Say(std::string line);

    void OnJoined(std::int32_t uid, const remote::net::SEndpoint& from, bool returning) override;
    void OnMessage(std::int32_t uid, const std::vector<std::uint8_t>& message) override;
    void OnLost(std::int32_t uid) override;

    SServerNetConfig mConfig;
    remote::net::CServerLinks mLinks;
    std::map<std::int32_t, SSeat> mSeats;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<bool> mNobodyCame{false};
    std::atomic<std::int32_t> mBeat{-1};
    std::int32_t mBeatSent = -1;
    std::uint64_t mStartUs = 0;
    std::uint64_t mNowUs = 0;
    bool mJoinWaitOver = false;
    std::uint64_t mRefusedCommands = 0;
    std::uint64_t mBadMessages = 0;
    // `OnMessage` runs inside the links' pass over their players, so they go once it's over.
    std::vector<std::int32_t> mToUnlink;

    std::mutex mNewsLock;
    std::vector<std::string> mNews;
  };
} // namespace faf::server
