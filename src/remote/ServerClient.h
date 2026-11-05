#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "moho/net/CClientBase.h"
#include "moho/net/ECmdStreamOp.h"

// Engine addition, server mode (plan WP3.1, WP3.3): one player's seat on the game server.
//
// A lockstep game waits for every player's beats. A seat can't make the sim wait: each beat the
// server issues is queued on every seat at once, whatever its player has sent, so a slow or lost
// player holds nobody up. What the player sent since the last beat goes in that beat. From there on
// a seat is an ordinary client: `CClientBase::UpdateState` merges it into the sim's stream under its
// command source, and `Eject` ends it as a lockstep ejection does.
//
// Nothing the sim side sends reaches the player through here: views go out on their own channel.

namespace moho
{
  struct CMessage;
}

namespace faf::remote
{
  /** Whether a player may send this op. The beats, the checksums and who's playing are the server's, and cheats aren't allowed. */
  [[nodiscard]] bool SeatMaySend(moho::ECmdStreamOp op) noexcept;

  class CServerClient final : public moho::CClientBase
  {
  public:
    inline static constexpr std::size_t kOpCount = static_cast<std::size_t>(moho::ECmdStreamOp::CMDST_EndGame) + 1u;

    /** Called under the manager's lock before each beat is queued: what arrives now goes in `beat`. */
    using BeatHook = std::function<void(CServerClient& seat, std::int32_t beat)>;

    /** Installs a seat in slot `index`, with `sourceId` as its only command source. The manager owns it. */
    static CServerClient& Create(
      moho::CClientManagerImpl& manager, const char* name, std::int32_t index, std::int32_t ownerId, std::uint32_t sourceId
    );

    float GetStatusMetricA() override { return 0.0f; }
    float GetStatusMetricB() override { return 0.0f; }

    /** What the server's side sends to every client: a beat is queued here too, an ack noted, the rest isn't for a seat. */
    void Process(moho::CMessage& message) override;

    void Debug() override;

    /**
     * A command from this seat's player. False: refused, as the op isn't allowed or the seat has ended.
     * `beat`, if given: the beat it went in.
     */
    [[nodiscard]] bool ReceiveCommand(moho::CMessage& message, std::int32_t* beat = nullptr);

    /** A message the server itself puts in this seat's stream, never one a player sent. */
    void AppendFromServer(moho::CMessage& message);

    /** The player has loaded the game (`CLIMSG_Ready`). */
    void MarkLoaded();

    void SetBeatHook(BeatHook hook);

    [[nodiscard]] std::uint64_t Refused(moho::ECmdStreamOp op) const noexcept
    {
      const auto index = static_cast<std::size_t>(op);
      return index < mRefused.size() ? mRefused[index] : 0u;
    }

  private:
    CServerClient(
      moho::CClientManagerImpl& manager, const char* name, std::int32_t index, std::int32_t ownerId, moho::BVIntSet& sources,
      std::uint32_t sourceId
    );

    BeatHook mBeatHook;
    std::array<std::uint64_t, kOpCount> mRefused{};
  };
} // namespace faf::remote
