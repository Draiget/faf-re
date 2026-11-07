#include "remote/client/ViewMerge.h"

#include <utility>

// Engine addition, server mode: see ViewMerge.h.

namespace faf::remote::client
{
  void CViewFrameMerger::Merge(
    const wire::SViewFrame& own, const wire::SViewFrame* const team, const std::int32_t army, wire::SViewFrame& merged, std::uint64_t& blipsLeftOut
  )
  {
    merged.frameId = own.frameId;
    merged.beat = own.beat;
    merged.simRate = own.simRate;
    merged.serverMs = own.serverMs;
    merged.entities.clear();
    merged.entities.reserve(own.entities.size() + (team != nullptr ? team->entities.size() : 0u));
    auto mine = own.entities.begin();
    if (team != nullptr) {
      // Both in ascending id order: one walk. The own frame wins an id both hold.
      for (const wire::SEntityRecord& record : team->entities) {
        while (mine != own.entities.end() && mine->id < record.id) {
          merged.entities.push_back(*mine++);
        }
        if (mine != own.entities.end() && mine->id == record.id) {
          merged.entities.push_back(*mine++);
          continue;
        }
        if (IsBlipOfArmy(record.id, army)) {
          ++blipsLeftOut;
          continue;
        }
        merged.entities.push_back(record);
      }
    }
    merged.entities.insert(merged.entities.end(), mine, own.entities.end());
  }

  bool CViewFrameMerger::Decode(
    const std::span<const std::uint8_t> own, const std::span<const std::uint8_t> team, const wire::SFrameCodec& codec, wire::SViewFrame& merged
  )
  {
    wire::SViewFrame ownFrame;
    if (!mOwn.Decode(own, codec, ownFrame)) {
      return false;
    }
    if (team.empty()) {
      if (mHasTeam) {
        mTeam = CClientFrameWindow{}; // cut from the team: what it held of the team's view goes
        mHasTeam = false;
      }
      Merge(ownFrame, nullptr, mArmy, merged, mBlipsLeftOut);
      return true;
    }
    wire::SViewFrame teamFrame;
    if (!mTeam.Decode(team, codec, teamFrame)) {
      return false;
    }
    mHasTeam = true;
    Merge(ownFrame, &teamFrame, mArmy, merged, mBlipsLeftOut);
    return true;
  }
} // namespace faf::remote::client
