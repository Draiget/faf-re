#include "moho/effects/rendering/EffectHost.h"

#include "moho/effects/rendering/CHostedEffectManager.h"
#include "moho/particles/SWorldBeam.h"

// Engine addition (server mode, plan WP9.3): see EffectHost.h.

namespace moho
{
  CEffectWorld::CEffectWorld(
    const IEffectManager& manager
  ) noexcept
    : mSim(manager.GetSim())
  {
    if (mSim == nullptr) {
      if (const CHostedEffectManager* const hosted = manager.AsHosted(); hosted != nullptr) {
        mHost = &hosted->Host();
      }
    }
  }

  bool CEffectWorld::FocusArmySeesBeam(
    const SWorldBeam& beam
  ) const
  {
    if (mSim != nullptr) {
      return mFocusArmy->GetReconDB()->BeamIsVisible(beam);
    }
    // `CAiReconDBImpl::BeamIsVisible` (0x00655610): the probe at the far end `mFromStart` selects.
    if (beam.mFromStart) {
      return mHost->FocusArmyDetects(beam.mCurEnd.pos_);
    }
    const Wm3::Vec3f beamEndProbe{
      beam.mCurStart.pos_.x + beam.mEnd.x,
      beam.mCurStart.pos_.y + beam.mEnd.y,
      beam.mCurStart.pos_.z + beam.mEnd.z,
    };
    return mHost->FocusArmyDetects(beamEndProbe);
  }

  CEffectFollow::CEffectFollow(
    const CEffectImpl& effect,
    const SEntAttachInfo& slot,
    const bool beamEnd
  ) noexcept
    : mEntity(slot.GetAttachTargetEntity())
  {
    // Only an attached effect with no sim entity asks: a sim's point emitters and detached effects pay nothing more.
    if (mEntity == nullptr && effect.mNewAttachment != 0u && effect.mManager != nullptr) {
      if (const CHostedEffectManager* const hosted = effect.mManager->AsHosted(); hosted != nullptr) {
        mTarget = hosted->Follows(effect, beamEnd);
      }
    }
  }
} // namespace moho
