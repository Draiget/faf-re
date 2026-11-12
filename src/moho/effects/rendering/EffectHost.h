#pragma once

#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"

// Engine addition (server mode, plan WP9.3): what the effect classes (`CEfxEmitter`, `CEfxTrailEmitter`, `CEfxBeam`
// and the manager's lights) read of the world, so they run in a `Sim` as before and, on the server-mode client, which
// has no `Sim`, in a `CHostedEffectManager` (CHostedEffectManager.h) over the client's own state.
//
// The client implements two interfaces: `IEffectHost` (the world: particle buffer, beat, cameras, the focus army's
// sight, the map) and `IEffectFollowTarget` (an entity an effect follows, as the client's views hold it). The effect
// classes read both through two value classes, `CEffectWorld` and `CEffectFollow`: each method's sim branch is the
// expression the effect code had before (same member, same call), so a sim's effects read exactly what they read
// before, in the same order. The sim side is not a virtual interface because `Sim`, `Entity`, `CEffectManagerImpl`,
// `CEffectImpl` and `SEntAttachInfo` keep the binary's layouts (the retail-layout asserts): none has room for a host
// pointer or a vtable of its own.

namespace moho
{
  class CDebugCanvas;
  class CHostedEffectManager;
  struct SParticleBuffer;
  struct SWorldBeam;

  /**
   * An entity a hosted effect follows. The four transforms are what a sim effect reads of its `Entity` in the sim's
   * effect tick, which runs before the tick's `AdvanceCoords`: `Current` is the entity's position at the previous tick
   * (`mVarDat.mCurTransform` then), `Pending` the one it moves to this tick (`mPendingTransform`).
   */
  class IEffectFollowTarget
  {
  public:
    virtual ~IEffectFollowTarget() = default;

    /** The entity is gone, or going (`DestroyQueuedFlag`): an effect that follows it ends. */
    [[nodiscard]] virtual bool Dying() const = 0;
    [[nodiscard]] virtual const VTransform& Current() const = 0;
    [[nodiscard]] virtual const VTransform& Pending() const = 0;
    [[nodiscard]] virtual float PendingVelocityScale() const = 0;
    /** `Entity::GetPositionHistory`: the position `tick` ticks before `Current` (0: `Current`). */
    [[nodiscard]] virtual const VTransform& History(int tick) const = 0;
    /** `Entity::GetBoneLocalTransform`. */
    [[nodiscard]] virtual VTransform BoneLocal(int bone) const = 0;
    /** `Entity::GetBoneWorldTransform` (creates place effects by it). */
    [[nodiscard]] virtual VTransform BoneWorld(int bone) const = 0;
    /** A unit, a projectile or a collision beam: a beam attached to anything else stops updating after its first tick.
     */
    [[nodiscard]] virtual bool UpdatesBeams() const = 0;
    /** `Entity::InitPositionHistory`, which every attach does: the history starts again. */
    virtual void ResetHistory() const = 0;
  };

  /** The world of effects hosted outside a `Sim`. */
  class IEffectHost
  {
  public:
    virtual ~IEffectHost() = default;

    /** Where the effect tick puts its particles, trails and beams (created on first use, as `Sim::GetParticleBuffer`).
     */
    [[nodiscard]] virtual SParticleBuffer* ParticleBuffer() = 0;
    /** The beat, as `Sim::mCurTick`. */
    [[nodiscard]] virtual std::uint32_t CurTick() const = 0;
    /** The session's cameras, as the sim's sync filter has them (`SSyncFilter::geoCams`). */
    [[nodiscard]] virtual const fa::vector<GeomCamera3>& Cameras() const = 0;
    /** Whether a focus army decides what shows; without one everything does. */
    [[nodiscard]] virtual bool HasFocusArmy() const = 0;
    /** As the focus army's `ReconCanDetect(position, RECON_LOSNow) != RECON_None`. */
    [[nodiscard]] virtual bool FocusArmyDetects(const Wm3::Vec3f& position) const = 0;
    /** As `STIMap::GetWaterElevationAt` and the height field's `GetElevation`. */
    [[nodiscard]] virtual float WaterElevationAt(float x, float z) const = 0;
    [[nodiscard]] virtual float TerrainElevationAt(float x, float z) const = 0;
  };

  /** What an effect of `manager` reads of its world: its `Sim`, or the host of a manager without one. */
  class CEffectWorld
  {
  public:
    explicit CEffectWorld(const IEffectManager& manager) noexcept;

    /** A sim, or a host: false only for a manager that has neither (none is made so). */
    [[nodiscard]] explicit operator bool() const noexcept
    {
      return mSim != nullptr || mHost != nullptr;
    }
    [[nodiscard]] SParticleBuffer* ParticleBuffer() const
    {
      return mSim != nullptr ? mSim->GetParticleBuffer() : mHost->ParticleBuffer();
    }
    [[nodiscard]] std::uint32_t CurTick() const noexcept
    {
      return mSim != nullptr ? mSim->mCurTick : mHost->CurTick();
    }
    [[nodiscard]] const fa::vector<GeomCamera3>& Cameras() const noexcept
    {
      return mSim != nullptr ? mSim->mSyncFilter.geoCams : mHost->Cameras();
    }
    /**
     * The sim's focus army as the effect classes resolve it (an army list, a focus index in it, a non-null army),
     * kept for `FocusArmyDetects`; or the host's answer.
     */
    [[nodiscard]] bool HasFocusArmy() noexcept
    {
      if (mSim == nullptr) {
        return mHost != nullptr && mHost->HasFocusArmy();
      }
      CArmyImpl** const armiesBegin = mSim->mArmiesList.begin();
      if (!armiesBegin) {
        return false;
      }
      const int focusArmy = mSim->mSyncFilter.focusArmy;
      if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= mSim->mArmiesList.size()) {
        return false;
      }
      mFocusArmy = armiesBegin[focusArmy];
      return mFocusArmy != nullptr;
    }
    /** After `HasFocusArmy` said yes. */
    [[nodiscard]] bool FocusArmyDetects(
      const Wm3::Vec3f& position
    ) const
    {
      return mSim != nullptr
        ? mFocusArmy->GetReconDB()->ReconCanDetect(position, static_cast<int>(RECON_LOSNow)) != RECON_None
        : mHost->FocusArmyDetects(position);
    }
    /** After `HasFocusArmy` said yes: `CAiReconDBImpl::BeamIsVisible`, the far end's probe. */
    [[nodiscard]] bool FocusArmySeesBeam(const SWorldBeam& beam) const;
    [[nodiscard]] float WaterElevationAt(
      const float x,
      const float z
    ) const
    {
      return mSim != nullptr ? mSim->mMapData->GetWaterElevationAt(x, z) : mHost->WaterElevationAt(x, z);
    }
    [[nodiscard]] float TerrainElevationAt(
      const float x,
      const float z
    ) const
    {
      return mSim != nullptr ? mSim->mMapData->GetHeightField()->GetElevation(x, z) : mHost->TerrainElevationAt(x, z);
    }
    /** The sim's debug canvas; none for a host (the `dbg_` effect lines are the sim's). */
    [[nodiscard]] CDebugCanvas* DebugCanvas() const
    {
      return mSim != nullptr ? mSim->GetDebugCanvas() : nullptr;
    }

  private:
    Sim* mSim = nullptr;
    IEffectHost* mHost = nullptr;
    CArmyImpl* mFocusArmy = nullptr;
  };

  /**
   * What an effect follows through one of its attach slots (`CEffectImpl::mEntityInfo`, or a beam's `mEnd`): the sim
   * `Entity` the slot's weak pointer holds, or, for an attached effect of a hosted manager, the target it follows.
   * Empty when it follows nothing (or its sim entity is gone).
   */
  class CEffectFollow
  {
  public:
    CEffectFollow(const CEffectImpl& effect, const SEntAttachInfo& slot, bool beamEnd) noexcept;

    [[nodiscard]] explicit operator bool() const noexcept
    {
      return mEntity != nullptr || mTarget != nullptr;
    }
    [[nodiscard]] bool Dying() const
    {
      return mEntity != nullptr ? mEntity->DestroyQueuedFlag != 0u : mTarget->Dying();
    }
    [[nodiscard]] const VTransform& Current() const
    {
      return mEntity != nullptr ? mEntity->mVarDat.mCurTransform : mTarget->Current();
    }
    [[nodiscard]] const VTransform& Pending() const
    {
      return mEntity != nullptr ? mEntity->mPendingTransform : mTarget->Pending();
    }
    [[nodiscard]] float PendingVelocityScale() const
    {
      return mEntity != nullptr ? mEntity->mPendingVelocityScale : mTarget->PendingVelocityScale();
    }
    [[nodiscard]] const VTransform& History(
      const int tick
    ) const
    {
      return mEntity != nullptr ? mEntity->GetPositionHistory(tick) : mTarget->History(tick);
    }
    [[nodiscard]] VTransform BoneLocal(
      const int bone
    ) const
    {
      return mEntity != nullptr ? mEntity->GetBoneLocalTransform(bone) : mTarget->BoneLocal(bone);
    }
    /** As `IsCollisionBeam() || IsProjectile() || IsUnit()`, asked in that order. */
    [[nodiscard]] bool UpdatesBeams() const
    {
      return mEntity != nullptr ? (mEntity->IsCollisionBeam() || mEntity->IsProjectile() || mEntity->IsUnit())
                                : mTarget->UpdatesBeams();
    }

  private:
    Entity* mEntity = nullptr;
    const IEffectFollowTarget* mTarget = nullptr;
  };
} // namespace moho
