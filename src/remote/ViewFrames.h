#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "remote/FrameBuilder.h"
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

namespace faf::remote
{
  class CViewFrames : public CViewPackets
  {
  public:
    CViewFrames(const wire::SContentTables& tables, const wire::SFrameCodec& codec);
    ~CViewFrames() override;

    /** The last beat's frame for `army`. */
    [[nodiscard]] const wire::SViewFrame& Frame(std::int32_t army) const { return mFrames[static_cast<std::size_t>(army)]; }
    /** Records `army`'s client holds that its last frame withheld. */
    [[nodiscard]] std::uint32_t Withheld(std::int32_t army) const { return mWithheld[static_cast<std::size_t>(army)]; }

  protected:
    void OnViewPackets(moho::Sim& sim) override;

    /** The views' frames of a sealed beat are ready (`Frame`). */
    virtual void OnViewFrames(moho::Sim& sim) { (void)sim; }

  private:
    const wire::SContentTables& mTables;
    wire::SFrameCodec mCodec;
    std::vector<std::unique_ptr<CViewFrameBuilder>> mBuilders;
    std::vector<wire::SViewFrame> mFrames;
    std::vector<std::uint32_t> mWithheld;
  };
} // namespace faf::remote
