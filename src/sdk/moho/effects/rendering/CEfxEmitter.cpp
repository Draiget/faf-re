#include "moho/effects/rendering/CEfxEmitter.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/gal/Matrix.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/EEmitterCurve.h"
#include "moho/render/EEmitterParam.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "Wm3Sphere3.h"

#include <intrin.h>

#include "moho/misc/Stats.h"
#include "moho/misc/StatItem.h"
#include "moho/math/MathReflection.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/STIMap.h"
#include "moho/ui/SDebugLine.h"

namespace moho
{
  // Debug console flags defined in EffectLuaStartupRegistrations.cpp / CWorldParticles.cpp.
  extern bool dbg_Emitter;
  extern float efx_WaterOffset;
  extern float efx_ParticleWaterSurface;
} // namespace moho

namespace
{
  // Engine-stat handle for "Render_ActiveEmitters", resolved once on first tick.
  moho::StatItem* sEngineStatRenderActiveEmitters = nullptr;

  /**
   * Reproduces the binary's ceil-of-peak idiom (frndint + underflow correction):
   * `(int)nearbyint(x) + (x > nearbyint(x) ? 1 : 0)`.
   */
  [[nodiscard]] int CeilByRint(const float value) noexcept
  {
    const float rounded = std::nearbyint(value);
    return static_cast<int>(rounded) + (value > rounded ? 1 : 0);
  }

  /**
   * Round-toward-negative-infinity via the binary's frndint + underflow
   * correction: `(int)nearbyint(x) - (x < nearbyint(x) ? 1 : 0)`.
   */
  [[nodiscard]] int FloorByRint(const float value) noexcept
  {
    const float rounded = std::nearbyint(value);
    return static_cast<int>(rounded) - (value < rounded ? 1 : 0);
  }

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
   * Address: 0x0065B9B0 (FUN_0065B9B0, Moho::CEfxEmitter::CEfxEmitter)
   *
   * What it does:
   * Default-constructs one emitter on top of the freshly-constructed
   * `CEffectImpl` base. The body matches the binary's per-field
   * initialization at offsets 0x190-0x6F4:
   *
   *   - publishes the `CEfxEmitter` vftable (handled by the C++ ctor chain);
   *   - zeros `mEmitterType` and the `mPad194` reserved gap;
   *   - binds `mCurves` as an empty inline-buffer fastvector over the 21-slot
   *     `mInlineCurveStorage` lane (mFirst/mLast/mOriginalStorage point at
   *     buffer start, mEnd at `&mBlueprint` = inline-buffer capacity-end);
   *   - resets blueprint pointer, emission count, lifetime;
   *   - default-constructs the embedded `mParticle` (`SWorldParticle`);
   *   - zero-initializes mValid + curve mask + max-lifetime + visible + last-
   *     update + position.
   *
   * The inline-buffer base address is `&mInlineCurveStorage[0]` which the
   * binary computes as `this + 0x1A8`; the capacity-end is `&mBlueprint`
   * (= `this + 0x640` = inline-buffer-start + 21*sizeof(SEfxCurve)).
   */
  CEfxEmitter::CEfxEmitter()
    : CEffectImpl()
    , mEmitterType(static_cast<EmitterType>(0))
    , mPad194{}
    , mCurves{}
    , mInlineCurveStorage{}
    , mBlueprint(nullptr)
    , mTotalEmissions(0.0f)
    , mLife(0u)
    , mParticle()
    , mValid(false)
    , mPad6D9{}
    , mZCurveMask(0u)
    , mMaxLifetime(0)
    , mVisible(false)
    , mPad6E5{}
    , mLastUpdate(0u)
    , mPos{0.0f, 0.0f, 0.0f}
  {
    auto* const inlineCurveBase = reinterpret_cast<SEfxCurve*>(&mInlineCurveStorage[0]);
    mCurves.mFirst = inlineCurveBase;
    mCurves.mLast = inlineCurveBase;
    mCurves.mEnd = reinterpret_cast<SEfxCurve*>(&mBlueprint);
    mCurves.mOriginalStorage = inlineCurveBase;
  }

  /**
   * Address: 0x0065BA80 (FUN_0065BA80, Moho::CEfxEmitter::CEfxEmitter)
   *
   * IDA signature:
   * Moho::CEfxEmitter *__stdcall Moho::CEfxEmitter::CEfxEmitter(
   *     Moho::CEfxEmitter *this, _DWORD *position, int scriptObjectToken,
   *     Moho::REmitterBlueprint *blueprint);   // manager passed in ecx
   *
   * What it does:
   * Blueprint-driven emitter constructor. Chains the manager-bound `CEffectImpl`
   * base ctor, binds `mCurves` to its inline buffer and fills its 21 default
   * curves, sizes the param/texture/string lanes, seeds the emit position plus
   * three fixed defaults, and (when a blueprint is present) rebuilds the 21
   * emitter curves and publishes the 20 blueprint scalar params + two texture
   * names. Ends by interpolating the initial attachment transform. The binary's
   * direct param writes + vtable-slot Invalidate calls are expressed here as the
   * equivalent SetNParam / SetFloatParam virtual helpers (write + invalidate).
   */
  CEfxEmitter::CEfxEmitter(
    CEffectManagerImpl* const manager,
    const Wm3::Vector3<float>& position,
    const int scriptObjectToken,
    const REmitterBlueprint* const blueprint
  )
    : CEffectImpl(manager, scriptObjectToken)
    , mEmitterType(static_cast<EmitterType>(0))
    , mPad194{}
    , mCurves{}
    , mInlineCurveStorage{}
    , mBlueprint(nullptr)
    , mTotalEmissions(0.0f)
    , mLife(0u)
    , mParticle()
    , mValid(false)
    , mPad6D9{}
    , mZCurveMask(0u)
    , mMaxLifetime(0)
    , mVisible(false)
    , mPad6E5{}
    , mLastUpdate(0u)
    , mPos{0.0f, 0.0f, 0.0f}
  {
    // Bind mCurves to the 21-slot inline buffer (mEnd = &mBlueprint sentinel).
    auto* const inlineCurveBase = reinterpret_cast<SEfxCurve*>(&mInlineCurveStorage[0]);
    mCurves.mFirst = inlineCurveBase;
    mCurves.mEnd = reinterpret_cast<SEfxCurve*>(&mBlueprint);
    mCurves.mOriginalStorage = inlineCurveBase;

    // Fill the inline buffer with 21 default curves (binary: fastvector<SEfxCurve>
    // resize(21, defaultCurve); capacity is exactly 21 so no heap growth occurs).
    for (std::size_t i = 0; i < kInlineCurveCapacity; ++i) {
      new (&inlineCurveBase[i]) SEfxCurve();
    }
    mCurves.mLast = inlineCurveBase + kInlineCurveCapacity;

    // Size the effect runtime lanes.
    mParams.resize(EFFECT_LASTPARAM, 0.0f);   // 26 param floats
    mParticleTextures.resize(2, nullptr);
    {
      const msvc8::string emptyString;
      mStrings.resize(2, emptyString);
    }

    // Seed emit position and the three fixed defaults.
    SetNParam(EFFECT_POSITION, static_cast<const float*>(position), 3);
    SetFloatParam(EFFECT_TICKINCREMENT, 1.0f);
    SetFloatParam(EFFECT_TICKCOUNT, 0.0f);
    SetFloatParam(EFFECT_SCALE, 1.0f);

    mBlueprint = const_cast<REmitterBlueprint*>(blueprint);
    if (blueprint != nullptr) {
      SEfxCurve* const curves = mCurves.begin();
      BuildEmitterCurveFromBlueprint(curves[EMITTER_XDIR_CURVE], blueprint->XDirectionCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_YDIR_CURVE], blueprint->YDirectionCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_ZDIR_CURVE], blueprint->ZDirectionCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_EMITRATE_CURVE], blueprint->EmitRateCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_LIFETIME_CURVE], blueprint->LifetimeCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_VELOCITY_CURVE], blueprint->VelocityCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_X_ACCEL_CURVE], blueprint->XAccelCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_Y_ACCEL_CURVE], blueprint->YAccelCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_Z_ACCEL_CURVE], blueprint->ZAccelCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_RESISTANCE_CURVE], blueprint->ResistanceCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_SIZE_CURVE], blueprint->SizeCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_X_POSITION_CURVE], blueprint->XPosCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_Y_POSITION_CURVE], blueprint->YPosCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_Z_POSITION_CURVE], blueprint->ZPosCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_BEGINSIZE_CURVE], blueprint->StartSizeCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_ENDSIZE_CURVE], blueprint->EndSizeCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_ROTATION_CURVE], blueprint->InitialRotationCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_ROTATION_RATE_CURVE], blueprint->RotationRateCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_FRAMERATE_CURVE], blueprint->FrameRateCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_TEXTURESELECTION_CURVE], blueprint->TextureSelectionCurve);
      BuildEmitterCurveFromBlueprint(curves[EMITTER_RAMPSELECTION_CURVE], blueprint->RampSelectionCurve);

      SetFloatParam(EFFECT_LIFETIME, blueprint->Lifetime);
      SetFloatParam(EFFECT_REPEATTIME, blueprint->RepeatTime);
      SetFloatParam(EFFECT_FRAMECOUNT, blueprint->TextureFrameCount);
      SetFloatParam(EFFECT_BLENDMODE, static_cast<float>(blueprint->BlendMode));
      SetFloatParam(EFFECT_LODCUTOFF, blueprint->LODCutoff);
      SetFloatParam(EFFECT_USE_LOCAL_VELOCITY, blueprint->LocalVelocity ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_USE_LOCAL_ACCELERATION, blueprint->LocalAcceleration ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_USE_GRAVITY, blueprint->Gravity ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_ALIGN_ROTATION, blueprint->AlignRotation ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_INTERPOLATE_EMISSION, blueprint->InterpolateEmission ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_TEXTURE_STRIPCOUNT, blueprint->TextureStripCount);
      SetFloatParam(EFFECT_ALIGN_TO_BONE, blueprint->AlignToBone ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_SORTORDER, blueprint->SortOrder);
      SetFloatParam(EFFECT_FLAT, static_cast<float>(blueprint->Flat));
      SetFloatParam(EFFECT_EMITIFVISIBLE, blueprint->EmitIfVisible ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_CATCHUPEMIT, blueprint->CatchupEmit ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_CREATEIFVISIBLE, blueprint->CreateIfVisible ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_SNAPTOWATERLINE, blueprint->SnapToWaterline ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_ONLYEMITONWATER, blueprint->OnlyEmitOnWater ? 1.0f : 0.0f);
      SetFloatParam(EFFECT_PARTICLERESISTANCE, blueprint->ParticleResistance ? 1.0f : 0.0f);

      OnInit(0, blueprint->TextureName.c_str());
      OnInit(1, blueprint->RampTextureName.c_str());
    }

    mValid = false;
    mZCurveMask = 0u;
    Interpolate();
  }

  /**
   * Address: 0x0065DE10 (FUN_0065DE10, Moho::CEfxEmitter::~CEfxEmitter body)
   *
   * What it does:
   * Tears down one emitter: destroys any live `SEfxCurve` entries in the
   * `mCurves` range, then releases the heap-grown curve storage when the
   * vector escaped its inline buffer (the binary compares
   * `mCurves.mFirst != mCurves.mOriginalStorage`). Member dtor for
   * `mParticle` runs automatically via the C++ destructor chain, as does
   * the `CEffectImpl` base dtor.
   *
   * Note: the binary additionally re-reads `*mOriginalStorage` into
   * `mCurves.mEnd` after the delete. This is meaningless after the dtor
   * since the object is being destroyed; we elide it.
   */
  CEfxEmitter::~CEfxEmitter()
  {
    for (SEfxCurve* curve = mCurves.mFirst; curve != mCurves.mLast; ++curve) {
      curve->~SEfxCurve();
    }

    if (mCurves.mFirst != mCurves.mOriginalStorage) {
      ::operator delete[](mCurves.mFirst);
      mCurves.mFirst = mCurves.mOriginalStorage;
    }
    mCurves.mLast = mCurves.mFirst;
  }

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
   * Address: 0x0065FA00 (FUN_0065FA00)
   *
   * What it does:
   * Thunk lane that forwards into `CEfxEmitter::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEfxEmitterMemberThunkA(
    CEfxEmitter* const emitter,
    gpg::ReadArchive* const archive
  )
  {
    emitter->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0065FCD0 (FUN_0065FCD0)
   *
   * What it does:
   * Duplicate thunk lane that forwards into `CEfxEmitter::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEfxEmitterMemberThunkB(
    CEfxEmitter* const emitter,
    gpg::ReadArchive* const archive
  )
  {
    emitter->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006600D0 (FUN_006600D0, Moho::CEfxEmitter::MemberDeserialize)
   *
   * What it does:
   * Inverse of `CEfxEmitter::MemberSerialize`: reads base `CEffectImpl`
   * payload, emitter metadata, curves vector, blueprint pointer, total
   * emissions, lifetime, particle payload, and visibility/lifetime state
   * from one read archive lane. The binary's read sequence mirrors the
   * write sequence one-to-one.
   */
  void CEfxEmitter::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef nullOwner{};

    archive->Read(ResolveCEffectImplType(), static_cast<CEffectImpl*>(this), nullOwner);
    archive->Read(ResolveEmitterTypeRuntimeType(), &mEmitterType, nullOwner);
    archive->Read(ResolveFastVectorSEfxCurveType(), &mCurves, nullOwner);

    const gpg::RRef blueprintOwner{};
    (void)archive->ReadPointer_REmitterBlueprint(&mBlueprint, &blueprintOwner);

    archive->ReadFloat(&mTotalEmissions);
    archive->ReadInt(reinterpret_cast<int*>(&mLife));
    archive->Read(ResolveSWorldParticleType(), &mParticle, nullOwner);
    archive->ReadBool(&mValid);
    archive->ReadInt(reinterpret_cast<int*>(&mZCurveMask));
    archive->ReadInt(&mMaxLifetime);
    archive->ReadBool(&mVisible);
    archive->ReadUInt(&mLastUpdate);
    archive->Read(ResolveVector3fType(), &mPos, nullOwner);
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

  /**
   * Address: 0x0065C7F0 (FUN_0065C7F0, IDA-mislabeled "Moho::SEfxCurve::UpdateCurve")
   *
   * IDA signature:
   * void __usercall Moho::CEfxEmitter::UpdateCurve(Moho::CEfxEmitter *this@<eax>);
   *
   * What it does:
   * Rebuilds the cached `mParticle` template from the current curve lanes and
   * scalar params: refreshes the Z-curve mask, derives the integer peak lifetime
   * bound, samples every masked curve into the embedded particle payload scaled
   * by EFFECT_SCALE, selects the ramp type-tag string, rebinds the two particle
   * textures, seeds the blend mode, and marks the emitter valid.
   */
  void CEfxEmitter::UpdateCurve()
  {
    UpdateCurveMask();

    SEfxCurve* const curves = mCurves.begin();
    const float* const params = mParams.start_;
    const float scale = params[EFFECT_SCALE];

    // Peak lifetime envelope: max over lifetime-curve keys of (z*0.5 + y),
    // seeded with -infinity.
    float lifetimePeak = -std::numeric_limits<float>::infinity();
    {
      const SEfxCurve& lifetimeCurve = curves[EMITTER_LIFETIME_CURVE];
      for (const Wm3::Vector3f* key = lifetimeCurve.mKeys.begin();
           key != lifetimeCurve.mKeys.end(); ++key) {
        const float sample = (key->z * 0.5f) + key->y;
        if (sample > lifetimePeak) {
          lifetimePeak = sample;
        }
      }
    }
    mMaxLifetime = CeilByRint(lifetimePeak);

    // mEnabled (byte @+0x00) carries the blueprint resistance flag (NOT mResistance).
    mParticle.mEnabled = (mBlueprint != nullptr) && (mBlueprint->ParticleResistance != 0);

    // mResistance (@+0x04) comes from the resistance curve only when masked.
    if ((mZCurveMask & (1u << EMITTER_RESISTANCE_CURVE)) != 0u) {
      mParticle.mResistance = curves[EMITTER_RESISTANCE_CURVE].GetValue(0.0f);
    }

    if ((mZCurveMask & (1u << EMITTER_X_POSITION_CURVE)) != 0u
        && (mZCurveMask & (1u << EMITTER_Y_POSITION_CURVE)) != 0u
        && (mZCurveMask & (1u << EMITTER_Z_POSITION_CURVE)) != 0u) {
      mParticle.mPos.x = curves[EMITTER_X_POSITION_CURVE].GetValue(0.0f) * scale;
      mParticle.mPos.y = curves[EMITTER_Y_POSITION_CURVE].GetValue(0.0f) * scale;
      mParticle.mPos.z = curves[EMITTER_Z_POSITION_CURVE].GetValue(0.0f) * scale;
    }

    if ((mZCurveMask & (1u << EMITTER_X_ACCEL_CURVE)) != 0u
        && (mZCurveMask & (1u << EMITTER_Y_ACCEL_CURVE)) != 0u
        && (mZCurveMask & (1u << EMITTER_Z_ACCEL_CURVE)) != 0u) {
      mParticle.mAccel.x = curves[EMITTER_X_ACCEL_CURVE].GetValue(0.0f) * scale;
      mParticle.mAccel.y = curves[EMITTER_Y_ACCEL_CURVE].GetValue(0.0f) * scale;
      mParticle.mAccel.z = curves[EMITTER_Z_ACCEL_CURVE].GetValue(0.0f) * scale;
    }

    if ((mZCurveMask & (1u << EMITTER_XDIR_CURVE)) != 0u
        && (mZCurveMask & (1u << EMITTER_YDIR_CURVE)) != 0u
        && (mZCurveMask & (1u << EMITTER_ZDIR_CURVE)) != 0u) {
      mParticle.mDir.x = curves[EMITTER_XDIR_CURVE].GetValue(0.0f) * scale;
      mParticle.mDir.y = curves[EMITTER_YDIR_CURVE].GetValue(0.0f) * scale;
      mParticle.mDir.z = curves[EMITTER_ZDIR_CURVE].GetValue(0.0f) * scale;
    }

    if ((mZCurveMask & (1u << EMITTER_LIFETIME_CURVE)) != 0u) {
      const float lifetime = curves[EMITTER_LIFETIME_CURVE].GetValue(0.0f);
      mParticle.mLifetime = (lifetime > 0.0f) ? lifetime : 0.0f;
    }

    if ((mZCurveMask & (1u << EMITTER_BEGINSIZE_CURVE)) != 0u) {
      mParticle.mBeginSize = curves[EMITTER_BEGINSIZE_CURVE].GetValue(0.0f) * scale;
    }
    if ((mZCurveMask & (1u << EMITTER_ENDSIZE_CURVE)) != 0u) {
      mParticle.mEndSize = curves[EMITTER_ENDSIZE_CURVE].GetValue(0.0f) * scale;
    }
    if ((mZCurveMask & (1u << EMITTER_RAMPSELECTION_CURVE)) != 0u) {
      mParticle.mRampSelection = curves[EMITTER_RAMPSELECTION_CURVE].GetValue(0.0f);
    }

    // Sort-order cache + per-frame reciprocals (all unconditional).
    mParticle.mReserved54 = params[EFFECT_SORTORDER];
    mParticle.mValue1 = 1.0f / params[EFFECT_FRAMECOUNT];
    mParticle.mValue3 = 1.0f / params[EFFECT_TEXTURE_STRIPCOUNT];

    // Framerate is sampled unconditionally; texture-selection only when masked.
    mParticle.mFramerate = curves[EMITTER_FRAMERATE_CURVE].GetValue(0.0f);
    if ((mZCurveMask & (1u << EMITTER_FRAMERATE_CURVE)) != 0u) {
      const float texSel = curves[EMITTER_TEXTURESELECTION_CURVE].GetValue(0.0f);
      mParticle.mTextureSelection = std::floor(texSel) * mParticle.mValue3;
    }

    // Ramp type-tag selection.
    if (params[EFFECT_FRAMECOUNT] <= 1.0f && params[EFFECT_TEXTURE_STRIPCOUNT] <= 1.0f) {
      if (params[EFFECT_ALIGN_ROTATION] > 0.0f) {
        mParticle.mTypeTag = "TRampAlign";
      } else if (params[EFFECT_ALIGN_TO_BONE] <= 0.0f) {
        mParticle.mTypeTag = (params[EFFECT_FLAT] <= 0.0f) ? "TRamp" : "TRampFlat";
      } else {
        mParticle.mTypeTag = (params[EFFECT_FLAT] <= 0.0f) ? "TRampAlignToBone" : "TRampFlat";
      }
      mParticle.mTextureSelection = 0.0f;
    } else if (params[EFFECT_ALIGN_ROTATION] > 0.0f) {
      mParticle.mTypeTag = "TRampAnimateAlign";
    } else if (params[EFFECT_ALIGN_TO_BONE] <= 0.0f) {
      mParticle.mTypeTag = (params[EFFECT_FLAT] > 0.0f) ? "TRampAnimateFlat" : "TRampAnimate";
    } else {
      mParticle.mTypeTag = (params[EFFECT_FLAT] > 0.0f) ? "TRampAnimateFlat" : "TRampAnimateAlignToBone";
    }

    if ((mZCurveMask & (1u << EMITTER_ROTATION_RATE_CURVE)) != 0u) {
      mParticle.mRotationCurve =
        curves[EMITTER_ROTATION_RATE_CURVE].GetValue(0.0f) * 0.017453292f;
    }

    AssignCountedParticleTexturePtr(&mParticle.mTexture, mParticleTextures.start_[0]);
    AssignCountedParticleTexturePtr(&mParticle.mRampTexture, mParticleTextures.start_[1]);

    mParticle.mBlendMode = static_cast<SWorldParticle::BlendMode>(
      static_cast<int>(params[EFFECT_BLENDMODE]));
    mValid = true;
  }

  /**
   * Address: 0x0065CE00 (FUN_0065CE00, Moho::CEfxEmitter::Tick)
   *
   * IDA signature:
   * char __userpurge Moho::CEfxEmitter::Tick@<al>(Moho::CEfxEmitter *this@<ebx>, int tick);
   *
   * What it does:
   * Emits the accumulated whole+fractional particle count for one sub-tick,
   * building one SWorldParticle per emission from the emitter curves, attachment
   * matrix, water clamp, and random scatter, then pushing each into the sim
   * particle buffer. Returns false if a per-emission InterpolatePosition fails.
   */
  bool CEfxEmitter::Tick(const std::int32_t tick)
  {
    float* const paramsBase = mParams.start_;
    const float repeatTime = paramsBase[EFFECT_REPEATTIME];
    const float tickFloat = static_cast<float>(tick);

    float ratePhase = std::fmod(paramsBase[EFFECT_TICKCOUNT] - tickFloat, repeatTime);
    if ((ratePhase < 0.0f) != (repeatTime < 0.0f)) {
      ratePhase += repeatTime;
    }

    mTotalEmissions = mCurves.begin()[EMITTER_EMITRATE_CURVE].GetValue(ratePhase) + mTotalEmissions;
    // Whole emission count = floor(mTotalEmissions); the same whole part is then
    // consumed from the accumulator (the binary computes floor twice on the
    // identical value).
    const int newEfx = FloorByRint(mTotalEmissions);
    mTotalEmissions = mTotalEmissions - static_cast<float>(newEfx);

    float emissionCursor = 0.0f;
    float emissionStep = 0.0f;
    bool result = false;
    VMatrix4 attachMatrix{};

    if (paramsBase[EFFECT_INTERPOLATE_EMISSION] <= 0.0f) {
      result = InterpolatePosition(this, &attachMatrix, tick, 0.0f);
    } else {
      emissionStep = 1.0f / static_cast<float>(newEfx);
    }

    const float scale = paramsBase[EFFECT_SCALE];
    if (newEfx <= 0) {
      return result;
    }

    for (int emitted = 0; ; ++emitted) {
      const float* const params = mParams.start_;
      const float repeat = params[EFFECT_REPEATTIME];
      float phase = std::fmod(params[EFFECT_TICKCOUNT] - tickFloat + emissionCursor, repeat);
      if ((phase < 0.0f) != (repeat < 0.0f)) {
        phase += repeat;
      }
      const float curvePhase = phase;

      Wm3::Vec3f localOffset{};
      if ((mZCurveMask & 0x3800u) == 0x3800u) {
        localOffset = mParticle.mPos;
      } else {
        localOffset.x = mCurves.begin()[EMITTER_X_POSITION_CURVE].GetValue(curvePhase) * scale;
        localOffset.y = mCurves.begin()[EMITTER_Y_POSITION_CURVE].GetValue(curvePhase) * scale;
        localOffset.z = mCurves.begin()[EMITTER_Z_POSITION_CURVE].GetValue(curvePhase) * scale;
      }

      if (params[EFFECT_INTERPOLATE_EMISSION] > 0.0f) {
        result = InterpolatePosition(this, &attachMatrix, tick, emissionCursor);
        if (!result) {
          return result;
        }
      }

      SWorldParticle particle(mParticle);
      const float* const p = mParams.start_;
      const float ox = p[EFFECT_POSITION_X] + localOffset.x;
      const float oy = localOffset.y + p[EFFECT_POSITION_Y];
      const float oz = localOffset.z + p[EFFECT_POSITION_Z];

      const float worldX = (((attachMatrix.r[2].x * oz) + (attachMatrix.r[1].x * oy))
                          + (attachMatrix.r[0].x * ox)) + attachMatrix.r[3].x;
      const float worldY = (((attachMatrix.r[2].y * oz) + (attachMatrix.r[1].y * oy))
                          + (attachMatrix.r[0].y * ox)) + attachMatrix.r[3].y;
      const float worldZ = (((attachMatrix.r[2].z * oz) + (attachMatrix.r[1].z * oy))
                          + (attachMatrix.r[0].z * ox)) + attachMatrix.r[3].z;

      float emitY = worldY;
      if (p[EFFECT_SNAPTOWATERLINE] > 0.0f) {
        STIMap* const map = ResolveEffectManager(this)->GetSim()->mMapData;
        const float waterElevation = map->mWaterEnabled ? map->mWaterElevation : -10000.0f;
        if (efx_ParticleWaterSurface <= mParams.start_[EFFECT_SORTORDER]) {
          const float above = waterElevation + efx_WaterOffset;
          emitY = (above > worldY) ? above : worldY;
        } else {
          const float below = waterElevation - efx_WaterOffset;
          emitY = (below <= worldY) ? below : worldY;
        }
      }

      bool skipEmission = false;
      if (mParams.start_[EFFECT_ONLYEMITONWATER] > 0.0f) {
        STIMap* const map = ResolveEffectManager(this)->GetSim()->mMapData;
        const float elevation = map->GetHeightField()->GetElevation(worldX, worldZ);
        const float waterElevation = map->mWaterEnabled ? map->mWaterElevation : -10000.0f;
        if (elevation > waterElevation) {
          skipEmission = true;
        } else {
          emitY = efx_WaterOffset + waterElevation;
        }
      }

      if (!skipEmission) {
        const float sizeSample = mCurves.begin()[EMITTER_SIZE_CURVE].GetValue(curvePhase) * scale;

        const float rand0 = static_cast<float>(MathGlobalRandomUnitSafe());
        const float rand1 = static_cast<float>(MathGlobalRandomUnitSafe());
        Wm3::Vec3f scatter{};
        scatter.y = 0.0f;
        scatter.x = rand1 - 0.5f;
        scatter.z = rand0 - 0.5f;
        (void)Wm3::Vector3f::Normalize(&scatter);
        const float rand2 = static_cast<float>(MathGlobalRandomUnitSafe());
        const float scatterMag = (rand2 - 0.5f) * sizeSample;

        particle.mPos.x = (scatterMag * scatter.x) + worldX;
        particle.mPos.y = emitY + (scatter.y * scatterMag);
        particle.mPos.z = (scatter.z * scatterMag) + worldZ;

        if ((mZCurveMask & 0x1C0u) != 0x1C0u) {
          particle.mAccel.x = mCurves.begin()[EMITTER_X_ACCEL_CURVE].GetValue(curvePhase) * scale;
          particle.mAccel.y = mCurves.begin()[EMITTER_Y_ACCEL_CURVE].GetValue(curvePhase) * scale;
          particle.mAccel.z = mCurves.begin()[EMITTER_Z_ACCEL_CURVE].GetValue(curvePhase) * scale;
        }

        float accelY = particle.mAccel.y;
        if (mParams.start_[EFFECT_USE_LOCAL_ACCELERATION] > 0.0f) {
          accelY = ((particle.mAccel.y * attachMatrix.r[1].y)
                  + (particle.mAccel.z * attachMatrix.r[2].y)) + (attachMatrix.r[0].y * particle.mAccel.x);
          const float accelZ = ((particle.mAccel.y * attachMatrix.r[1].z)
                  + (particle.mAccel.z * attachMatrix.r[2].z)) + (attachMatrix.r[0].z * particle.mAccel.x);
          particle.mAccel.x = ((particle.mAccel.y * attachMatrix.r[1].x)
                  + (particle.mAccel.z * attachMatrix.r[2].x)) + (particle.mAccel.x * attachMatrix.r[0].x);
          particle.mAccel.y = accelY;
          particle.mAccel.z = accelZ;
        }
        particle.mAccel.y = accelY - (mParams.start_[EFFECT_USE_GRAVITY] * 0.02f);

        if ((mZCurveMask & 0x7u) != 0x7u) {
          particle.mDir.x = mCurves.begin()[EMITTER_XDIR_CURVE].GetValue(curvePhase) * scale;
          particle.mDir.y = mCurves.begin()[EMITTER_YDIR_CURVE].GetValue(curvePhase) * scale;
          particle.mDir.z = mCurves.begin()[EMITTER_ZDIR_CURVE].GetValue(curvePhase) * scale;
        }
        if (mParams.start_[EFFECT_USE_LOCAL_VELOCITY] > 0.0f) {
          const float dirY = ((particle.mDir.y * attachMatrix.r[1].y)
                  + (particle.mDir.z * attachMatrix.r[2].y)) + (attachMatrix.r[0].y * particle.mDir.x);
          const float dirZ = ((particle.mDir.y * attachMatrix.r[1].z)
                  + (particle.mDir.z * attachMatrix.r[2].z)) + (attachMatrix.r[0].z * particle.mDir.x);
          particle.mDir.x = ((particle.mDir.y * attachMatrix.r[1].x)
                  + (particle.mDir.z * attachMatrix.r[2].x)) + (particle.mDir.x * attachMatrix.r[0].x);
          particle.mDir.y = dirY;
          particle.mDir.z = dirZ;
        }
        const float velocity = mCurves.begin()[EMITTER_VELOCITY_CURVE].GetValue(curvePhase);
        particle.mDir.x *= velocity;
        particle.mDir.y *= velocity;
        particle.mDir.z *= velocity;

        particle.mResistance = mCurves.begin()[EMITTER_RESISTANCE_CURVE].GetValue(curvePhase);
        particle.mInterop = emissionCursor - tickFloat;

        if ((mZCurveMask & 0x10u) == 0u) {
          const float lifetime = mCurves.begin()[EMITTER_LIFETIME_CURVE].GetValue(curvePhase);
          particle.mLifetime = (lifetime > 0.0f) ? lifetime : 0.0f;
        }
        if ((mZCurveMask & 0x4000u) == 0u) {
          particle.mBeginSize = mCurves.begin()[EMITTER_BEGINSIZE_CURVE].GetValue(curvePhase) * scale;
        }
        if ((mZCurveMask & 0x8000u) == 0u) {
          particle.mEndSize = mCurves.begin()[EMITTER_ENDSIZE_CURVE].GetValue(curvePhase) * scale;
        }
        if ((mZCurveMask & 0x100000u) == 0u) {
          particle.mRampSelection = mCurves.begin()[EMITTER_RAMPSELECTION_CURVE].GetValue(curvePhase);
        }
        if ((mZCurveMask & 0x40000u) == 0u) {
          particle.mFramerate = mCurves.begin()[EMITTER_FRAMERATE_CURVE].GetValue(curvePhase);
        }
        if ((mZCurveMask & 0x80000u) == 0u) {
          const float texSel = mCurves.begin()[EMITTER_TEXTURESELECTION_CURVE].GetValue(curvePhase);
          particle.mTextureSelection = std::floor(texSel) * particle.mValue3;
        }

        if (mParams.start_[EFFECT_ALIGN_TO_BONE] <= 0.0f) {
          particle.mAngle = mCurves.begin()[EMITTER_ROTATION_CURVE].GetValue(curvePhase) * 0.017453292f;
        } else {
          Wm3::Vec3f boneAxis{ attachMatrix.r[2].x, attachMatrix.r[2].y, attachMatrix.r[2].z };
          if (mParams.start_[EFFECT_FLAT] > 0.0f) {
            (void)Wm3::Vector3f::Normalize(&boneAxis);
            particle.mAngle = std::atan2(-boneAxis.x, boneAxis.z);
          } else {
            particle.mDir.x = attachMatrix.r[2].x;
            particle.mDir.y = attachMatrix.r[2].y;
            particle.mDir.z = attachMatrix.r[2].z;
          }
        }

        if ((mZCurveMask & 0x20000u) == 0u) {
          particle.mRotationCurve = mCurves.begin()[EMITTER_ROTATION_RATE_CURVE].GetValue(curvePhase) * 0.017453292f;
        }

        Sim* const sim = ResolveEffectManager(this)->GetSim();
        AppendWorldParticleToVector(sim->GetParticleBuffer()->mParticles, particle);
      }

      emissionCursor += emissionStep;
      result = ((emitted + 1) & 0xFF) != 0;
      if (emitted + 1 >= newEfx) {
        return result;
      }
    }
  }

  /**
   * Address: 0x0065DAC0 (FUN_0065DAC0, Moho::CEfxEmitter::OnTick)
   *
   * IDA signature:
   * void __thiscall Moho::CEfxEmitter::OnTick(Moho::CEfxEmitter *this);
   *
   * What it does:
   * Per-frame emitter tick: refreshes the cached position every third tick (for
   * emit/create-if-visible blueprints), gates on lifetime/visibility, bumps the
   * active-emitter engine stat, rebuilds curves when invalid, then drives the
   * per-sub-tick particle emission loop (Tick), advancing the effect clock.
   */
  void CEfxEmitter::OnTick()
  {
    const float* const start = mParams.start_;
    if ((start[EFFECT_EMITIFVISIBLE] > 0.0f || start[EFFECT_CREATEIFVISIBLE] > 0.0f)
        && (ResolveEffectManager(this)->GetSim()->mCurTick % 3u) == 0u) {
      VMatrix4 attachMatrix{};
      (void)InterpolatePosition(this, &attachMatrix, 0, 0.0f);
      const float* const p = mParams.start_;
      const float sx = p[EFFECT_POSITION_X];
      const float sy = p[EFFECT_POSITION_Y];
      const float sz = p[EFFECT_POSITION_Z];
      const float worldY = (((attachMatrix.r[0].y * sx) + (attachMatrix.r[1].y * sy))
                          + (attachMatrix.r[2].y * sz)) + attachMatrix.r[3].y;
      const float worldZ = (((attachMatrix.r[0].z * sx) + (attachMatrix.r[1].z * sy))
                          + (attachMatrix.r[2].z * sz)) + attachMatrix.r[3].z;
      mPos.x = (((attachMatrix.r[2].x * sz) + (attachMatrix.r[1].x * sy))
              + (attachMatrix.r[0].x * sx)) + attachMatrix.r[3].x;
      mPos.y = worldY;
      mPos.z = worldZ;
    }

    if (ProcessLifetime() || !IsVisible()) {
      return;
    }

    if (sEngineStatRenderActiveEmitters == nullptr) {
      EngineStats* const engineStats = GetEngineStats();
      sEngineStatRenderActiveEmitters = engineStats->GetItem("Render_ActiveEmitters", true);
      (void)sEngineStatRenderActiveEmitters->Release(0);
    }
    _InterlockedExchangeAdd(
      reinterpret_cast<volatile long*>(&sEngineStatRenderActiveEmitters->mPrimaryValueBits), 1);

    if (!mValid) {
      UpdateCurve();
    }

    int life = static_cast<int>(mLife);
    if (life >= 24) {
      life = 24;
    }
    int subTicks = mMaxLifetime;
    mLife = static_cast<std::uint32_t>(life);
    if (life < subTicks) {
      subTicks = life;
    }

    for (mLife = static_cast<std::uint32_t>(subTicks); subTicks > 0; --subTicks) {
      Tick(subTicks);
    }
    mLife = 0u;
    Tick(0);

    mParams.start_[EFFECT_TICKCOUNT] =
      mParams.start_[EFFECT_TICKINCREMENT] + mParams.start_[EFFECT_TICKCOUNT];

    if (dbg_Emitter) {
      Sim* const sim = ResolveEffectManager(this)->GetSim();
      CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
      VMatrix4 startMatrix{};
      VMatrix4 endMatrix{};
      (void)InterpolatePosition(this, &startMatrix, 0, 0.0f);
      (void)InterpolatePosition(this, &endMatrix, 0, 1.0f);
      SDebugLine line{};
      line.p0.x = startMatrix.r[3].x;
      line.p0.y = startMatrix.r[3].y;
      line.p0.z = startMatrix.r[3].z;
      line.p1.x = endMatrix.r[3].x;
      line.p1.y = endMatrix.r[3].y;
      line.p1.z = endMatrix.r[3].z;
      line.depth0 = static_cast<std::int32_t>(0xFF0000FFu);
      line.depth1 = static_cast<std::int32_t>(0xFFFF0000u);
      debugCanvas->DebugDrawLine(line);
    }
  }
} // namespace moho
