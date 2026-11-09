#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "moho/net/CMessage.h"
#include "remote/ServerClient.h"

// Engine addition, server mode (plan WP3.1, WP3.3): headless's `--seats`. A recorded game played
// through the game server's seats: each command source becomes a seat, its commands go through the
// seat's filter, a source that ended is ejected there, and the server's own client issues the beats.
// If the recorded checksums still hold, a seat gives the sim what a lockstep client gave it.

namespace gpg
{
  class Stream;
}

namespace moho
{
  class CClientManagerImpl;
  class LaunchInfoBase;
} // namespace moho

namespace faf::headless
{
  class CReplaySeatFeed
  {
  public:
    /** Reads the whole recording and makes `manager`: one seat per command source, then the server's client. */
    CReplaySeatFeed(
      const moho::LaunchInfoBase& launchInfo, std::unique_ptr<gpg::Stream> recording, moho::CClientManagerImpl*& manager
    );

    /** One per command source, in their order; the manager owns them. */
    [[nodiscard]] const std::vector<remote::CServerClient*>& Seats() const noexcept { return mSeats; }

    /** The last beat the recording holds. */
    [[nodiscard]] std::int32_t LastBeat() const noexcept { return mLastBeat; }

    /** What went through the seats, on one line. */
    [[nodiscard]] std::string Report() const;

  private:
    struct SOp
    {
      std::int32_t beat;
      moho::CMessage message;
    };

    void Deliver(remote::CServerClient& seat, std::int32_t beat);

    std::vector<remote::CServerClient*> mSeats;
    std::vector<std::vector<SOp>> mOps; // per seat, in the recording's order
    std::vector<std::size_t> mNext;
    std::int32_t mLastBeat = 0;
    bool mEndSent = false;

    std::atomic<std::uint64_t> mAccepted{0};
    std::atomic<std::uint64_t> mFromServer{0};
    std::atomic<std::uint64_t> mEjected{0};
    std::atomic<std::uint64_t> mLostToEject{0};
    std::array<std::atomic<std::uint64_t>, remote::CServerClient::kOpCount> mRefused{};
  };
} // namespace faf::headless
