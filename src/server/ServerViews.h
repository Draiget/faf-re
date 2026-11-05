#pragma once

#include <cstddef>
#include <cstdint>
#include <map>

#include "remote/ViewLanes.h"

// Engine addition, dedicated server (plan WP5, WP10.4): each player's view of the game, every beat,
// on its way to them. Views are built only for armies with a player, with ids of their own, on threads
// of their own so the sim goes on to its next beat meanwhile.
//
// A frame is encoded against the one before it, so the player must have received that one: they go on
// the reliable stream. A lost datagram then costs a resend's wait, never a wrong picture. Sending frames
// unreliably against the newest acknowledged one would cost no wait, and needs the held frames to encode
// against an older frame, which they don't do.

namespace faf::server
{
  class CServerNet;

  class CServerViews final : public remote::CViewLanes
  {
  public:
    /** `players`: army to uid. */
    CServerViews(
      const remote::wire::SContentTables& tables, float mapSizeX, float mapSizeZ, CServerNet& net, std::map<std::size_t, std::int32_t> players,
      unsigned int threads
    );
    ~CServerViews() override;

    void Install();
    /** Call with the sim stopped. */
    void Uninstall();

    [[nodiscard]] std::uint64_t Failures() const noexcept { return mFailures; }

  protected:
    void OnLanesEncoded(std::size_t army, const SLanes& lanes) override;
    void OnViewsFinished() override;

  private:
    CServerNet& mNet;
    std::map<std::size_t, std::int32_t> mPlayers;
    std::uint64_t mFailures = 0;
    bool mInstalled = false;
  };
} // namespace faf::server
