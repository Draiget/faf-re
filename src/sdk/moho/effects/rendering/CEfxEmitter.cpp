#include "moho/effects/rendering/CEfxEmitter.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/gal/Matrix.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/EEmitterParam.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "Wm3Sphere3.h"

namespace
{
  struct EmbeddedDwordVectorHeaderOffset10RuntimeView
  {
    std::byte pad00_0F[0x10];
    std::uint32_t* begin = nullptr; // +0x10
    std::uint32_t* end = nullptr; // +0x14
    std::uint32_t* capacityEnd = nullptr; // +0x18
    std::uint32_t* metadata = nullptr; // +0x1C
  };
  static_assert(
    offsetof(EmbeddedDwordVectorHeaderOffset10RuntimeView, begin) == 0x10,
    "EmbeddedDwordVectorHeaderOffset10RuntimeView::begin offset must be 0x10"
  );
  static_assert(
    offsetof(EmbeddedDwordVectorHeaderOffset10RuntimeView, end) == 0x14,
    "EmbeddedDwordVectorHeaderOffset10RuntimeView::end offset must be 0x14"
  );
  static_assert(
    offsetof(EmbeddedDwordVectorHeaderOffset10RuntimeView, capacityEnd) == 0x18,
    "EmbeddedDwordVectorHeaderOffset10RuntimeView::capacityEnd offset must be 0x18"
  );
  static_assert(
    offsetof(EmbeddedDwordVectorHeaderOffset10RuntimeView, metadata) == 0x1C,
    "EmbeddedDwordVectorHeaderOffset10RuntimeView::metadata offset must be 0x1C"
  );

  /**
   * Address: 0x0065DD90 (FUN_0065DD90)
   *
   * What it does:
   * Initializes one embedded dword-vector header at offset `+0x10` with inline
   * storage at `+0x20` and 6-word capacity.
   */
  [[maybe_unused]] EmbeddedDwordVectorHeaderOffset10RuntimeView* InitializeEmbeddedDwordVectorHeaderOffset10Capacity6(
    EmbeddedDwordVectorHeaderOffset10RuntimeView* const outView
  ) noexcept
  {
    auto* const inlineStorage = reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::byte*>(outView) + 0x20u);
    outView->begin = inlineStorage;
    outView->end = inlineStorage;
    outView->capacityEnd = inlineStorage + 6u;
    outView->metadata = inlineStorage;
    return outView;
  }

  void RecomputeCurveYBoundsFromKeys(moho::SEfxCurve* const curve) noexcept
  {
    curve->mBoundsMin.y = std::numeric_limits<float>::infinity();
    curve->mBoundsMax.y = -std::numeric_limits<float>::infinity();

    for (Wm3::Vector3f* key = curve->mKeys.begin(); key != curve->mKeys.end(); ++key) {
      if (curve->mBoundsMin.y > key->y) {
        curve->mBoundsMin.y = key->y;
      }
      if (key->y > curve->mBoundsMax.y) {
        curve->mBoundsMax.y = key->y;
      }
    }
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
   * Address: 0x0065C3B0 (FUN_0065C3B0)
   *
   * What it does:
   * Returns whether emitter LOD depth check passes for the provided camera
   * viewport row (`lodCutoff <= 0 || projectedDepth <= lodCutoff`).
   */
  [[nodiscard]] bool PassesEmitterLodDepthCutoffForViewport(
    const float lodCutoff,
    const Wm3::Vec3f& emitterPosition,
    const moho::VMatrix4& viewport
  ) noexcept
  {
    return lodCutoff <= 0.0f || ProjectViewportDepthRow1(viewport, emitterPosition) <= lodCutoff;
  }

  [[nodiscard]] gpg::RType* ResolveCEffectImplType()
  {
    if (!moho::CEffectImpl::sType) {
      moho::CEffectImpl::sType = gpg::LookupRType(typeid(moho::CEffectImpl));
    }

    return moho::CEffectImpl::sType;
  }

  [[nodiscard]] gpg::RType* ResolveEmitterTypeRuntimeType()
  {
    static gpg::RType* sEmitterType = nullptr;
    if (!sEmitterType) {
      sEmitterType = gpg::LookupRType(typeid(moho::EmitterType));
    }

    return sEmitterType;
  }

  [[nodiscard]] gpg::RType* ResolveFastVectorSEfxCurveType()
  {
    static gpg::RType* sFastVectorSEfxCurveType = nullptr;
    if (!sFastVectorSEfxCurveType) {
      sFastVectorSEfxCurveType = gpg::LookupRType(typeid(gpg::fastvector<moho::SEfxCurve>));
    }

    return sFastVectorSEfxCurveType;
  }

  [[nodiscard]] gpg::RType* ResolveSWorldParticleType()
  {
    if (!moho::SWorldParticle::sType) {
      moho::SWorldParticle::sType = gpg::LookupRType(typeid(moho::SWorldParticle));
    }

    return moho::SWorldParticle::sType;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* sVector3fType = nullptr;
    if (!sVector3fType) {
      sVector3fType = gpg::LookupRType(typeid(Wm3::Vector3f));
    }

    return sVector3fType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006593E0 (FUN_006593E0, Moho::CEfxEmitter::InterpolatePosition)
   *
   * What it does:
   * Resolves entity transform history for one effect attachment lane, blends
   * orientation/position at `tick` + `interp`, and writes the resulting world
   * matrix (optionally composed with one parent-bone local transform).
   */
  bool CEfxEmitter::InterpolatePosition(
    const CEffectImpl* const effect,
    VMatrix4* const outMatrix,
    const int tick,
    float interp
  )
  {
    Entity* const attachedEntity = effect->mEntityInfo.GetAttachTargetEntity();
    if (attachedEntity == nullptr) {
      *outMatrix = effect->mMatrix;
      return true;
    }

    Wm3::Quaternionf previousOrientation{};
    Wm3::Vector3f previousPosition{};
    VTransform currentTransform{};

    if (tick <= 0) {
      interp *= attachedEntity->mPendingVelocityScale;
      if (interp > 1.0f) {
        interp = 1.0f;
      }

      currentTransform.orient_.x = attachedEntity->Orientation.x;
      currentTransform.orient_.y = attachedEntity->Orientation.y;
      currentTransform.orient_.z = attachedEntity->Orientation.z;
      currentTransform.orient_.w = attachedEntity->Orientation.w;
      currentTransform.pos_ = attachedEntity->Position;

      previousOrientation.x = attachedEntity->PendingOrientation.x;
      previousOrientation.y = attachedEntity->PendingOrientation.y;
      previousOrientation.z = attachedEntity->PendingOrientation.z;
      previousOrientation.w = attachedEntity->PendingOrientation.w;
      previousPosition = attachedEntity->PendingPosition;
    } else {
      const VTransform& previousHistory = attachedEntity->GetPositionHistory(tick - 1);
      previousOrientation = previousHistory.orient_;
      previousPosition = previousHistory.pos_;
      currentTransform = attachedEntity->GetPositionHistory(tick);
    }

    Wm3::Quaternionf interpolatedOrientation{};
    (void)QuatLERP(&previousOrientation, &currentTransform.orient_, &interpolatedOrientation, interp);

    Wm3::Vector3f interpolatedPosition{};
    interpolatedPosition.x = ((previousPosition.x - currentTransform.pos_.x) * interp) + currentTransform.pos_.x;
    interpolatedPosition.y = ((previousPosition.y - currentTransform.pos_.y) * interp) + currentTransform.pos_.y;
    interpolatedPosition.z = ((previousPosition.z - currentTransform.pos_.z) * interp) + currentTransform.pos_.z;

    outMatrix->Set(interpolatedOrientation, interpolatedPosition);

    const int boneIndex = effect->mEntityInfo.mParentBoneIndex;
    if (boneIndex != -1) {
      const VTransform boneLocalTransform = attachedEntity->GetBoneLocalTransform(boneIndex);
      VMatrix4 boneLocalMatrix{};
      boneLocalMatrix.Set(boneLocalTransform.orient_, boneLocalTransform.pos_);

      VMatrix4 composed{};
      (void)gpg::gal::Math::mul(&composed, &boneLocalMatrix, outMatrix);
      *outMatrix = composed;
    }

    return true;
  }

  /**
   * Address: 0x0065C1A0 (FUN_0065C1A0, Moho::CEfxEmitter::Interpolate)
   *
   * What it does:
   * Samples interpolated attachment matrix at `(tick=0, interp=0.0)` and
   * transforms one emitter start-vector lane into world-space `mPos`.
   */
  void CEfxEmitter::Interpolate()
  {
    VMatrix4 interpolatedMatrix{};
    (void)InterpolatePosition(this, &interpolatedMatrix, 0, 0.0f);

    const float* const start = mParams.start_;
    const float startX = start[0];
    const float startY = start[1];
    const float startZ = start[2];

    const float worldY = ((interpolatedMatrix.r[0].y * startX)
                        + (interpolatedMatrix.r[1].y * startY)
                        + (interpolatedMatrix.r[2].y * startZ))
                      + interpolatedMatrix.r[3].y;

    const float worldZ = ((interpolatedMatrix.r[0].z * startX)
                        + (interpolatedMatrix.r[1].z * startY)
                        + (interpolatedMatrix.r[2].z * startZ))
                      + interpolatedMatrix.r[3].z;

    mPos.x = ((interpolatedMatrix.r[0].x * startX)
            + (interpolatedMatrix.r[1].x * startY)
            + (interpolatedMatrix.r[2].x * startZ))
           + interpolatedMatrix.r[3].x;
    mPos.y = worldY;
    mPos.z = worldZ;
  }

  /**
   * Address: 0x0065C290 (FUN_0065C290, Moho::CEfxEmitter::UpdateCurveMask)
   *
   * What it does:
   * Rebuilds packed Z-curve mask bits by scanning every second emitter curve
   * lane and setting one bit when the lane has exactly one key and near-zero Z.
   */
  void CEfxEmitter::UpdateCurveMask()
  {
    mZCurveMask = 0u;

    SEfxCurve* const curves = mCurves.begin();
    for (std::uint32_t bitIndex = 0u; bitIndex < 21u; ++bitIndex) {
      SEfxCurve& curve = curves[bitIndex * 2u];
      if ((curve.mKeys.end() - curve.mKeys.begin()) != 1) {
        continue;
      }

      if (std::fabs(curve.mKeys.begin()->z) < std::fabs(0.001f)) {
        mZCurveMask |= (1u << bitIndex);
      }
    }
  }

  /**
   * Address: 0x0065C320 (FUN_0065C320, Moho::CEfxEmitter::SetCurveParam)
   *
   * What it does:
   * Copies one source curve bounds lane into the destination emitter slot,
   * recomputes source-curve Y bounds from key payload, and invalidates one
   * emitter parameter lane.
   */
  void CEfxEmitter::SetCurveParam(const std::int32_t paramIndex, const void* const curveData)
  {
    const auto* const sourceCurve = static_cast<const SEfxCurve*>(curveData);
    SEfxCurve& destinationCurve = mCurves.begin()[static_cast<std::size_t>(paramIndex) * 2u];
    destinationCurve.mBoundsMin = sourceCurve->mBoundsMin;
    destinationCurve.mBoundsMax = sourceCurve->mBoundsMax;

    RecomputeCurveYBoundsFromKeys(const_cast<SEfxCurve*>(sourceCurve));
    Invalidate2(paramIndex);
  }

  /**
   * Address: 0x0065C390 (FUN_0065C390, Moho::CEfxEmitter::Invalidate1)
   */
  void CEfxEmitter::Invalidate(const std::int32_t, const std::int32_t)
  {
    mValid = false;
  }

  /**
   * Address: 0x0065C3A0 (FUN_0065C3A0, Moho::CEfxEmitter::Invalidate2)
   */
  void CEfxEmitter::Invalidate2(const std::int32_t)
  {
    mValid = false;
  }

  /**
   * Address: 0x0065C420 (FUN_0065C420, Moho::CEfxEmitter::CanSeeCam)
   *
   * What it does:
   * Applies depth/frustum visibility checks and focused-army recon probes for
   * one camera.
   */
  bool CEfxEmitter::CanSeeCam(const GeomCamera3* const camera)
  {
    if (!camera) {
      mLastUpdate = 0u;
      return false;
    }

    if (!PassesEmitterLodDepthCutoffForViewport(mParams.start_[EFFECT_LODCUTOFF], mPos, camera->viewport)) {
      mLastUpdate = 0u;
      return false;
    }

    Wm3::Sphere3f visibilitySphere{};
    visibilitySphere.Center = mPos;
    visibilitySphere.Radius = 5.0f;
    if (!camera->solid2.Intersects(visibilitySphere)) {
      mLastUpdate = 0u;
      return false;
    }

    Sim* const sim = ResolveEffectManager(this)->GetSim();
    if (!sim) {
      return true;
    }

    CArmyImpl** const armiesBegin = sim->mArmiesList.begin();
    if (!armiesBegin) {
      return true;
    }

    const int focusArmy = sim->mSyncFilter.focusArmy;
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
    mVisible = reconDb->ReconCanDetect(mPos, static_cast<int>(RECON_LOSNow)) != RECON_None;
    return mVisible;
  }

  /**
   * Address: 0x0065C600 (FUN_0065C600, Moho::CEfxEmitter::IsVisible)
   *
   * What it does:
   * Scans sync cameras and returns whether this emitter should be processed
   * for the current tick.
   */
  bool CEfxEmitter::IsVisible()
  {
    if (mParams.start_[EFFECT_EMITIFVISIBLE] > 0.0f) {
      Sim* const sim = ResolveEffectManager(this)->GetSim();
      msvc8::vector<GeomCamera3>& cameras = sim->mSyncFilter.geoCams;
      GeomCamera3* const camerasEnd = cameras.end();
      GeomCamera3* camera = cameras.begin();

      if (camera == camerasEnd) {
        ++mLife;
        return false;
      }

      for (; camera != camerasEnd; ++camera) {
        if (!CanSeeCam(camera)) {
          continue;
        }

        if (!mNewAttachment) {
          break;
        }

        if (PassesEmitterLodDepthCutoffForViewport(mParams.start_[EFFECT_LODCUTOFF], mPos, camera->viewport)) {
          break;
        }
      }

      if (camera == camerasEnd) {
        ++mLife;
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x0065C700 (FUN_0065C700, Moho::CEfxEmitter::ProcessLifetime)
   *
   * What it does:
   * Applies lifetime/attachment visibility gates and destroys the effect
   * when one terminal condition is met.
   */
  bool CEfxEmitter::ProcessLifetime()
  {
    IEffectManager* const effectManager = ResolveEffectManager(this);
    const float* const params = mParams.start_;

    if (params[EFFECT_LIFETIME] >= 0.0f &&
        (static_cast<float>(static_cast<int>(mLife)) + params[EFFECT_TICKCOUNT]) >= params[EFFECT_LIFETIME]) {
      effectManager->DestroyEffect(this);
      return true;
    }

    if (mNewAttachment != 0u) {
      const Entity* const attachedEntity = mEntityInfo.GetAttachTargetEntity();
      if (attachedEntity == nullptr || attachedEntity->DestroyQueuedFlag != 0u) {
        effectManager->DestroyEffect(this);
        return true;
      }
    }

    if (mParams.start_[EFFECT_CREATEIFVISIBLE] > 0.0f) {
      msvc8::vector<GeomCamera3>& cameras = effectManager->GetSim()->mSyncFilter.geoCams;
      for (GeomCamera3* camera = cameras.begin(); camera != cameras.end(); ++camera) {
        if (!CanSeeCam(camera)) {
          continue;
        }

        mParams.start_[EFFECT_CREATEIFVISIBLE] = 0.0f;
        return false;
      }

      effectManager->DestroyEffect(this);
      return true;
    }

    return false;
  }

  /**
   * Address: 0x0065FA10 (FUN_0065FA10)
   *
   * What it does:
   * Thunk lane that forwards into `CEfxEmitter::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEfxEmitterMemberThunkA(
    CEfxEmitter* const emitter,
    gpg::WriteArchive* const archive
  )
  {
    emitter->MemberSerialize(archive);
  }

  /**
   * Address: 0x0065FCE0 (FUN_0065FCE0)
   *
   * What it does:
   * Duplicate thunk lane that forwards into `CEfxEmitter::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEfxEmitterMemberThunkB(
    CEfxEmitter* const emitter,
    gpg::WriteArchive* const archive
  )
  {
    emitter->MemberSerialize(archive);
  }

  /**
   * Address: 0x00660280 (FUN_00660280, Moho::CEfxEmitter::MemberSerialize)
   *
   * What it does:
   * Serializes base effect lanes, emitter metadata, blueprint pointer,
   * particle payload, and visibility/lifetime state.
   */
  void CEfxEmitter::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    gpg::RRef nullOwner{};

    archive->Write(ResolveCEffectImplType(), static_cast<const CEffectImpl*>(this), nullOwner);
    archive->Write(ResolveEmitterTypeRuntimeType(), &mEmitterType, nullOwner);
    archive->Write(ResolveFastVectorSEfxCurveType(), &mCurves, nullOwner);

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_REmitterBlueprint(&blueprintRef, mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, nullOwner);

    archive->WriteFloat(mTotalEmissions);
    archive->WriteInt(static_cast<int>(mLife));
    archive->Write(ResolveSWorldParticleType(), &mParticle, nullOwner);
    archive->WriteBool(mValid);
    archive->WriteInt(static_cast<int>(mZCurveMask));
    archive->WriteInt(mMaxLifetime);
    archive->WriteBool(mVisible);
    archive->WriteUInt(mLastUpdate);
    archive->Write(ResolveVector3fType(), &mPos, nullOwner);
  }
} // namespace moho
