#pragma once

#include <cstdint>
#include <span>

#include "remote/FrameWindow.h"
#include "remote/wire/EntityFrame.h"

// Engine addition, server mode (plan WP11; research/WP11-network-client-map.md step 3): a server's `View` carries
// two frames, each encoded against its own last one (net/GameLinks.h): the player's own (their army's real units)
// and their team's (plain entities, props and blips, worked out once for the team, ViewPackets.h). The client holds
// both and shows them as one, less the team's blips of the player's own units, which the blip id's army byte tells
// (ViewFrames.cpp, `DumpViews`). An empty team frame means none: a player cut from their team drops what they held.

namespace faf::remote::client
{
  class CViewFrameMerger
  {
  public:
    /** The player's army (`GameInfo`), whose own units' blips in the team frame are left out; -1: none. */
    void SetArmy(std::int32_t army) noexcept { mArmy = army; }

    /**
     * Decodes one view's own and team frames against what each kept, and merges them into `merged` (ascending ids,
     * the own frame's beat and stamps). False when either doesn't decode; the kept frames then stay as they were.
     */
    [[nodiscard]] bool Decode(
      std::span<const std::uint8_t> own, std::span<const std::uint8_t> team, const wire::SFrameCodec& codec, wire::SViewFrame& merged
    );

    /** Team blips of the player's own units left out, over every merge. */
    [[nodiscard]] std::uint64_t BlipsLeftOut() const noexcept { return mBlipsLeftOut; }

    /** True for a blip of `army`'s unit: a blip id (kind 3 in the top 4 bits) with that army in bits 20-27. */
    [[nodiscard]] static bool IsBlipOfArmy(std::uint32_t id, std::int32_t army) noexcept
    {
      return army >= 0 && (id >> 28u) == 3u && ((id >> 20u) & 0xFFu) == static_cast<std::uint32_t>(army);
    }

    /** The merge alone (both frames decoded): own records and the team's, less its blips of `army`'s units. */
    static void Merge(const wire::SViewFrame& own, const wire::SViewFrame* team, std::int32_t army, wire::SViewFrame& merged, std::uint64_t& blipsLeftOut);

  private:
    CClientFrameWindow mOwn;
    CClientFrameWindow mTeam;
    bool mHasTeam = false;
    std::int32_t mArmy = -1;
    std::uint64_t mBlipsLeftOut = 0;
  };
} // namespace faf::remote::client
