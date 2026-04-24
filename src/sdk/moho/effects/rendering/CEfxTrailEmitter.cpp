#include "moho/effects/rendering/CEfxTrailEmitter.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/CEfxEmitter.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/render/ETrailParam.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "Wm3Sphere3.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  [[nodiscard]] moho::IEffectManager* ResolveEffectManager(const moho::IEffect* const effect) noexcept
  {
    const std::uintptr_t rawManager = static_cast<std::uintptr_t>(effect->mUnknown3C);
    return reinterpret_cast<moho::IEffectManager*>(rawManager);
  }

  [[nodiscard]] float ProjectViewportDepthRow1(const moho::VMatrix4& viewport, const Wm3::Vec3f& point) noexcept
  {
    return (point.x * viewport.r[1].x) + (point.y * viewport.r[1].y) + (point.z * viewport.r[1].z) + viewport.r[1].w;
  }

  /**
   * Address: 0x00671430 (FUN_00671430)
   *
   * What it does:
   * Computes one interpolated trail-start world position and returns whether
   * the camera depth-row projection stays within the blueprint LOD cutoff.
   */
  [[maybe_unused]] [[nodiscard]] bool TrailEmitterPassesLodCutoffForCamera(
    const moho::GeomCamera3* const camera,
    moho::CEfxTrailEmitter* const emitter
  )
  {
    const float lodCutoff = emitter->mTrailBlueprint->LODCutoff;
    if (!(lodCutoff > 0.0f)) {
      return true;
    }

    moho::VMatrix4 interpolatedMatrix{};
    (void)moho::CEfxEmitter::InterpolatePosition(emitter, &interpolatedMatrix, 0, 0.0f);

    const float* const start = emitter->mParams.start_;
    Wm3::Vec3f trailPosition{};
    trailPosition.x = ((interpolatedMatrix.r[0].x * start[0])
                     + (interpolatedMatrix.r[1].x * start[1])
                     + (interpolatedMatrix.r[2].x * start[2]))
                    + interpolatedMatrix.r[3].x;
    trailPosition.y = ((interpolatedMatrix.r[0].y * start[0])
                     + (interpolatedMatrix.r[1].y * start[1])
                     + (interpolatedMatrix.r[2].y * start[2]))
                    + interpolatedMatrix.r[3].y;
    trailPosition.z = ((interpolatedMatrix.r[0].z * start[0])
                     + (interpolatedMatrix.r[1].z * start[1])
                     + (interpolatedMatrix.r[2].z * start[2]))
                    + interpolatedMatrix.r[3].z;

    return ProjectViewportDepthRow1(camera->viewport, trailPosition) <= lodCutoff;
  }

  /**
   * Address: 0x00672040 (FUN_00672040)
   *
   * What it does:
   * Register-lane thunk that forwards one `(emitter, archive)` pair into
   * `CEfxTrailEmitter::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEfxTrailEmitterMemberThunkA(
    const moho::CEfxTrailEmitter* const emitter,
    gpg::WriteArchive* const archive
  )
  {
    if (emitter == nullptr) {
      return;
    }
    emitter->MemberSerialize(archive);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00671200 (FUN_00671200, Moho::CEfxTrailEmitter::CEfxTrailEmitter)
   *
   * What it does:
   * Default-constructs one trail-emitter: chains to `CEffectImpl::CEffectImpl()`
   * (which publishes the base vtable) and then zero-initializes the trail
   * payload lanes. In the shipped binary the derived vtable is patched in
   * after the base ctor returns; the implicit `CEfxTrailEmitter` vtable binding
   * performed by the compiler reproduces that sequence.
   */
  CEfxTrailEmitter::CEfxTrailEmitter()
    : CEffectImpl()
    , mTrailBlueprint(nullptr)
    , mTrailLength(0)
    , mTotalTicks(0.0f)
    , mLife(0.0f)
    , mLength(0.0f)
    , mSerializedTrailPosition()
    , mCreated(false)
    , mVisible(false)
    , mPad1B2{0, 0}
    , mLastUpdate(0u)
  {}

  /**
   * Address: 0x00671420 (FUN_00671420, Moho::CEfxTrailEmitter::Invalidate1)
   *
   * What it does:
   * No-op invalidation lane used by the trail-emitter vtable.
   */
  void CEfxTrailEmitter::Invalidate(const std::int32_t, const std::int32_t)
  {}

  /**
   * Address: 0x00671550 (FUN_00671550, Moho::CEfxTrailEmitter::CanSeeCam)
   *
   * What it does:
   * Applies trail LOD/frustum checks and focused-army recon visibility probe
   * for one camera.
   */
  bool CEfxTrailEmitter::CanSeeCam(const GeomCamera3* const camera)
  {
    VMatrix4 interpolatedMatrix{};
    (void)CEfxEmitter::InterpolatePosition(this, &interpolatedMatrix, 0, 0.0f);

    const float* const start = mParams.start_;
    const float startX = start[0];
    const float startY = start[1];
    const float startZ = start[2];

    Wm3::Vec3f trailPosition{};
    trailPosition.x = ((interpolatedMatrix.r[0].x * startX)
                     + (interpolatedMatrix.r[1].x * startY)
                     + (interpolatedMatrix.r[2].x * startZ))
                    + interpolatedMatrix.r[3].x;
    trailPosition.y = ((interpolatedMatrix.r[0].y * startX)
                     + (interpolatedMatrix.r[1].y * startY)
                     + (interpolatedMatrix.r[2].y * startZ))
                    + interpolatedMatrix.r[3].y;
    trailPosition.z = ((interpolatedMatrix.r[0].z * startX)
                     + (interpolatedMatrix.r[1].z * startY)
                     + (interpolatedMatrix.r[2].z * startZ))
                    + interpolatedMatrix.r[3].z;

    const float lodCutoff = mTrailBlueprint->LODCutoff;
    Wm3::Sphere3f trailSphere{};
    trailSphere.Center = trailPosition;
    trailSphere.Radius = 5.0f;
    if ((lodCutoff > 0.0f && ProjectViewportDepthRow1(camera->viewport, trailPosition) > lodCutoff)
        || !camera->solid2.Intersects(trailSphere)) {
      mLastUpdate = 0u;
      return false;
    }

    Sim* const sim = ResolveEffectManager(this)->GetSim();
    CArmyImpl** const armiesBegin = sim->mArmiesList.begin();
    const int focusArmy = sim->mSyncFilter.focusArmy;
    if (!armiesBegin) {
      return true;
    }

    if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= sim->mArmiesList.size()) {
      return true;
    }

    CArmyImpl* const army = armiesBegin[focusArmy];
    if (!army) {
      return true;
    }

    if (mLastUpdate != 0u) {
      if (((sim->mCurTick - mLastUpdate) % 5u) != 0u) {
        return mVisible;
      }
    } else {
      mLastUpdate = sim->mCurTick;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    mVisible = reconDb->ReconCanDetect(trailPosition, static_cast<int>(RECON_LOSNow)) != RECON_None;
    return mVisible;
  }

  /**
   * Address: 0x006717E0 (FUN_006717E0, Moho::CEfxTrailEmitter::ProcessLifetime)
   *
   * What it does:
   * Destroys the trail effect when lifetime expires, or when an attached
   * parent entity is required and has been detached/destroyed.
   */
  bool CEfxTrailEmitter::ProcessLifetime()
  {
    const float lifetime = mParams.start_[TRAIL_LIFETIME];
    if (!(lifetime < 0.0f || (static_cast<float>(mTrailLength) + mTotalTicks) < lifetime)) {
      ResolveEffectManager(this)->DestroyEffect(this);
      return true;
    }

    if (mNewAttachment == 0u) {
      return false;
    }

    const Entity* const attachedEntity = mEntityInfo.GetAttachTargetEntity();
    if (attachedEntity != nullptr && attachedEntity->DestroyQueuedFlag == 0u) {
      return false;
    }

    ResolveEffectManager(this)->DestroyEffect(this);
    return true;
  }

  /**
   * Address: 0x00672820 (FUN_00672820, sub_672820)
   *
   * What it does:
   * Serializes trail-emitter payload after base `CEffectImpl` state:
   * blueprint pointer, timing lanes, one Vector3 lane, and live flags.
   */
  void CEfxTrailEmitter::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CEffectImpl::StaticGetClass(), static_cast<const CEffectImpl*>(this), nullOwner);

    gpg::RRef trailBlueprintRef{};
    gpg::RRef_RTrailBlueprint(&trailBlueprintRef, mTrailBlueprint);
    gpg::WriteRawPointer(archive, trailBlueprintRef, gpg::TrackedPointerState::Unowned, nullOwner);

    archive->WriteInt(mTrailLength);
    archive->WriteFloat(mTotalTicks);
    archive->WriteFloat(mLife);
    archive->WriteFloat(mLength);
    archive->Write(CachedVector3fType(), &mSerializedTrailPosition, nullOwner);
    archive->WriteBool(mCreated);
    archive->WriteBool(mVisible);
    archive->WriteUInt(mLastUpdate);
  }
} // namespace moho
