#pragma once

#include <cstdint>
#include <memory>
#include <unordered_set>
#include <vector>

#include "remote/FrameBuilder.h"
#include "remote/ViewIdMap.h"
#include "remote/ViewPackets.h"
#include "remote/wire/EntityFrame.h"

// Engine addition, server mode (plan WP5.2): per view and beat, the frame the server sends one
// army. Each army's rebuilt packet (remote/ViewPackets.h, equal to the lockstep client's) is
// applied to that army's own `CViewFrameBuilder`, whose world then holds what that client holds:
// an entity the beat's walk did not sync keeps its record from the beat it last changed, so
// unchanged entities carry the same packed data as the previous frame (a unit's detail and
// stats are shared values). The frame is that world less what the visibility oracle withholds:
// a plain entity in mode ReconGrid out of the view's sight (`CanViewSee`, plan §6). Records the
// sim no longer has (orphaned props, kept until the client sees their spot) stay.
//
// With `EnableIdMaps` (plan WP5.9) every frame then goes through its view's `CViewIdMap`: blips,
// foreign projectiles and foreign command ids are renumbered per view. Off until inbound
// translation (WP5.10) exists, because a client would otherwise send back ids the sim lacks.

namespace faf::remote
{
  class CViewFrames : public CViewPackets
  {
  public:
    CViewFrames(const wire::SContentTables& tables, const wire::SFrameCodec& codec);
    ~CViewFrames() override;

    /** Renumbers the frames' ids per view from the next beat on (remote/ViewIdMap.h). */
    void EnableIdMaps() noexcept { mIdMapsOn = true; }
    [[nodiscard]] bool IdMapsOn() const noexcept { return mIdMapsOn; }
    /** `army`'s id map (with `EnableIdMaps`, once a beat has been built). */
    [[nodiscard]] const CViewIdMap& IdMap(std::int32_t army) const { return *mIdMaps[static_cast<std::size_t>(army)]; }
    /** The views built so far (0 before the first beat). */
    [[nodiscard]] std::size_t ViewCount() const noexcept { return mIdMaps.size(); }
    /** The sim of the last beat built (null before it); for checks that run on the sim thread. */
    [[nodiscard]] moho::Sim* LastSim() const noexcept { return mLastSim; }

    /** The last beat's frame for `army`. */
    [[nodiscard]] const wire::SViewFrame& Frame(std::int32_t army) const { return mFrames[static_cast<std::size_t>(army)]; }
    /** Records `army`'s client holds that its last frame withheld. */
    [[nodiscard]] std::uint32_t Withheld(std::int32_t army) const { return mWithheld[static_cast<std::size_t>(army)]; }

  protected:
    void OnViewPackets(moho::Sim& sim) override;

    /** The views' frames of a sealed beat are ready (`Frame`). */
    virtual void OnViewFrames(moho::Sim& sim) { (void)sim; }

  private:
    /** References to entities `frame` does not hold become the sim's "none" (plan WP5.12). */
    static void ClearUnheldReferences(wire::SViewFrame& frame);

    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    std::vector<std::unique_ptr<CViewFrameBuilder>> mBuilders;
    std::vector<wire::SViewFrame> mFrames;
    std::vector<std::uint32_t> mWithheld;
    bool mIdMapsOn = false;
    moho::Sim* mLastSim = nullptr;
    std::vector<std::unique_ptr<CViewIdMap>> mIdMaps;
    std::vector<std::unordered_set<std::uint32_t>> mRetiring; // per view: deleted or erased, still held
    std::vector<std::vector<std::uint32_t>> mRetired;         // per view: no longer held; retired next beat
  };
} // namespace faf::remote
