#include "moho/effects/rendering/EffectHost.h"

#include <cstring>

#include "moho/effects/rendering/CHostedEffectManager.h"
#include "moho/effects/rendering/EffectTickObserver.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/particles/SWorldBeam.h"

// Engine addition (server mode, plan WP9.3): see EffectHost.h.

namespace moho
{
  // Plan WPR.10 (EffectTickObserver.h): null in the game.
  IEffectTickObserver* gEffectTickObserver = nullptr;
  bool gEffectCurveSpreadCentred = false;

  CEffectTickScope::CEffectTickScope(
    const CEffectImpl& effect
  )
    : mEffect(effect)
  {
    if (gEffectTickObserver == nullptr || effect.mManager == nullptr) {
      return;
    }
    const CEffectWorld world(*effect.mManager);
    if (!world) {
      return;
    }
    mBuffer = world.ParticleBuffer();
    // FNV-1a over the parameters' bytes: two runtimes' effects made with the same arguments hash alike.
    std::uint64_t hash = 14695981039346656037ull;
    for (const float* value = effect.mParams.begin(); value != nullptr && value != effect.mParams.end(); ++value) {
      std::uint32_t bits = 0;
      std::memcpy(&bits, value, sizeof(bits));
      for (int shift = 0; shift < 32; shift += 8) {
        hash = (hash ^ ((bits >> shift) & 0xFFu)) * 1099511628211ull;
      }
    }
    mTick.paramsHash = hash;
    if (mBuffer != nullptr) {
      mParticles = mBuffer->mParticles.size();
      mTrails = mBuffer->mTrails.size();
      mBeams = mBuffer->mBeams.size();
    }
  }

  CEffectTickScope::~CEffectTickScope()
  {
    if (mBuffer == nullptr || gEffectTickObserver == nullptr) {
      return;
    }
    mTick.particles = static_cast<std::uint32_t>(mBuffer->mParticles.size() - mParticles);
    mTick.trails = static_cast<std::uint32_t>(mBuffer->mTrails.size() - mTrails);
    mTick.beams = static_cast<std::uint32_t>(mBuffer->mBeams.size() - mBeams);
    gEffectTickObserver->OnEffectTicked(mEffect, mTick);
  }

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
