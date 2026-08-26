#include "moho/effects/rendering/CEfxTrailEmitter.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
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

#include <cstring>
#include <intrin.h>

#include "moho/misc/Stats.h"
#include "moho/misc/StatItem.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/ui/SDebugLine.h"
#include "moho/resource/CParticleTexture.h"

namespace moho
{
  // Debug console flag defined in EffectLuaStartupRegistrations.cpp
  // (?dbg_Trail@Moho@@3_NA); when set, Tick draws a debug line per segment.
  extern bool dbg_Trail;
} // namespace moho

namespace
{
  // Engine-stat handle for "Render_ActiveEmitters", resolved once on first tick
  // (mirrors the binary's sEngineStat_Render_ActiveEmitters_1 global).
  moho::StatItem* sEngineStatRenderActiveEmitters = nullptr;

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
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
  [[nodiscard]] bool TrailEmitterPassesLodCutoffForCamera(
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
} // namespace

namespace moho
{
  gpg::RType* CEfxTrailEmitter::sType = nullptr;

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
   * Address: 0x00671250 (FUN_00671250, Moho::CEfxTrailEmitter::CEfxTrailEmitter)
   * Mangled: ??0CEfxTrailEmitter@Moho@@QAE@PAVCEffectManagerImpl@1@PBMPAVRTrailBlueprint@1@H@Z
   *
   * IDA signature:
   * Moho::CEfxTrailEmitter *__thiscall Moho::CEfxTrailEmitter::CEfxTrailEmitter(
   *     Moho::CEffectManagerImpl *manager, Moho::CEfxTrailEmitter *this,
   *     const float *position, Moho::RTrailBlueprint *blueprint, int armyIndex);
   *
   * What it does:
   * Blueprint-driven trail ctor. Chains the manager-bound CEffectImpl base ctor,
   * stores the trail blueprint, zero-inits the trail payload lanes, sizes the
   * effect param/texture/string lanes, then seeds the emit position, unit scale
   * (param 5 = 1.0), blueprint lifetime and length, and binds the repeat/ramp
   * textures. CEfxTrailEmitter::Invalidate is a no-op override, so the parameter
   * setters here only publish values into the param lane (matching the binary's
   * inlined writes + no-op invalidate calls).
   */
  CEfxTrailEmitter::CEfxTrailEmitter(
    CEffectManagerImpl* const manager,
    const float* const position,
    RTrailBlueprint* const blueprint,
    const int armyIndex
  )
    : CEffectImpl(manager, armyIndex)
    , mTrailBlueprint(blueprint)
    , mTrailLength(0)
    , mTotalTicks(0.0f)
    , mLife(0.0f)
    , mLength(0.0f)
    , mSerializedTrailPosition()
    , mCreated(false)
    , mVisible(false)
    , mPad1B2{0, 0}
    , mLastUpdate(0u)
  {
    // Size the effect parameter lanes (fastvector_n resize emissions):
    // params -> 6 floats, textures -> 2 null slots, strings -> 2 empty.
    mParams.resize(TRAIL_LASTPARAM, 0.0f);
    mParticleTextures.resize(2, nullptr);
    {
      const msvc8::string emptyString;
      mStrings.resize(2, emptyString);
    }

    // Seed the emit position and blueprint-derived trail parameters.
    SetNParam(TRAIL_POSITION, position, 3);
    SetFloatParam(TRAIL_SCALE, 1.0f);
    SetFloatParam(TRAIL_LIFETIME, blueprint->Lifetime);
    SetFloatParam(TRAIL_LENGTH, blueprint->TrailLength);
    OnInit(0, blueprint->RepeatTexture.c_str());
    OnInit(1, blueprint->RampTexture.c_str());
  }

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

    Sim* const sim = mManager->GetSim();
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
      mManager->DestroyEffect(this);
      return true;
    }

    if (mNewAttachment == 0u) {
      return false;
    }

    const Entity* const attachedEntity = mEntityInfo.GetAttachTargetEntity();
    if (attachedEntity != nullptr && attachedEntity->DestroyQueuedFlag == 0u) {
      return false;
    }

    mManager->DestroyEffect(this);
    return true;
  }

  /**
   * Address: 0x00672710 (FUN_00672710, Moho::CEfxTrailEmitter::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall Moho::CEfxTrailEmitter::MemberDeserialize(
   *     Moho::CEfxTrailEmitter *this@<ecx>, gpg::ReadArchive *archive@<eax>);
   *
   * What it does:
   * Inverse of `MemberSerialize`: reads base `CEffectImpl` state, trail
   * blueprint pointer, timing lanes, one Vector3 lane, and live flags, in
   * the same field order `MemberSerialize` writes them. Every field/offset
   * below is confirmed directly against FUN_00672710's raw disassembly
   * (0x190, 0x194, 0x198, 0x19C, 0x1A0, 0x1A4, 0x1B0, 0x1B1, 0x1B4), not
   * just pattern-matched from the write side.
   */
  void CEfxTrailEmitter::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CEffectImpl::StaticGetClass(), static_cast<CEffectImpl*>(this), nullOwner);
    (void)archive->ReadPointer_RTrailBlueprint(&mTrailBlueprint, &nullOwner);

    archive->ReadInt(&mTrailLength);
    archive->ReadFloat(&mTotalTicks);
    archive->ReadFloat(&mLife);
    archive->ReadFloat(&mLength);
    archive->Read(CachedVector3fType(), &mSerializedTrailPosition, nullOwner);
    archive->ReadBool(&mCreated);
    archive->ReadBool(&mVisible);
    archive->ReadUInt(&mLastUpdate);
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

  /**
   * Address: 0x00671750 (FUN_00671750, Moho::CEfxTrailEmitter::CalculateVisible)
   *
   * IDA signature:
   * char __usercall Moho::CEfxTrailEmitter::CalculateVisible@<al>(
   *     Moho::CEfxTrailEmitter *this@<eax>);
   *
   * What it does:
   * Blueprints that always emit return true. Otherwise scans the sim
   * sync-filter cameras and returns true on the first camera that can see this
   * trail (and, for freshly-attached trails, still passes the LOD depth cutoff).
   * If no camera qualifies, advances mTrailLength by one (catch-up accumulation)
   * and returns false.
   */
  bool CEfxTrailEmitter::CalculateVisible()
  {
    if (!mTrailBlueprint->EmitIfVisible) {
      return true;
    }

    Sim* const sim = mManager->GetSim();
    const msvc8::vector<GeomCamera3>& cameras = sim->mSyncFilter.geoCams;

    for (const GeomCamera3& camera : cameras) {
      if (CanSeeCam(&camera)
          && !(mNewAttachment && !TrailEmitterPassesLodCutoffForCamera(&camera, this))) {
        return true;
      }
    }

    ++mTrailLength;
    return false;
  }

  /**
   * Address: 0x00671850 (FUN_00671850, Moho::CEfxTrailEmitter::Tick)
   *
   * IDA signature:
   * void __usercall Moho::CEfxTrailEmitter::Tick(
   *     Moho::CEfxTrailEmitter *this@<ecx>, int tick@<ebx>);
   *
   * What it does:
   * Builds one STrail payload for tick index `tick` and pushes it into the sim
   * particle buffer's trail lane. Interpolates the trail-start position at the
   * previous and current sub-frame (the latter scaled by the attached entity's
   * pending-velocity reciprocal on the final tick), derives the normalized
   * segment direction, updates the running trail length/position, retains the
   * repeat and ramp textures, and (when dbg_Trail is set) draws a debug line.
   */
  void CEfxTrailEmitter::Tick(const std::int32_t tick)
  {
    // interpScale: 1.0, or 1 / (attached entity pending-velocity scale) on the
    // final (tick == 0) sub-frame when an entity is attached.
    float interpScale = 1.0f;
    if (tick == 0) {
      Entity* const attachedEntity = mEntityInfo.GetAttachTargetEntity();
      if (attachedEntity != nullptr) {
        interpScale = 1.0f / attachedEntity->mPendingVelocityScale;
      }
    }

    VMatrix4 prevMatrix{}; // first interp (tick, 0.0)
    VMatrix4 curMatrix{};  // second interp (tick, interpScale)
    (void)CEfxEmitter::InterpolatePosition(this, &prevMatrix, tick, 0.0f);
    (void)CEfxEmitter::InterpolatePosition(this, &curMatrix, tick, interpScale);

    const float* const start = mParams.start_;
    const float sx = start[TRAIL_POSITION_X];
    const float sy = start[TRAIL_POSITION_Y];
    const float sz = start[TRAIL_POSITION_Z];

    // Trail-start point transformed through each interpolated matrix. Keep the
    // exact parenthesized add ordering the binary emits.
    const float curX = (((curMatrix.r[1].x * sy) + (curMatrix.r[2].x * sz)) + (curMatrix.r[0].x * sx)) + curMatrix.r[3].x;
    const float prevX = (((prevMatrix.r[1].x * sy) + (prevMatrix.r[2].x * sz)) + (prevMatrix.r[0].x * sx)) + prevMatrix.r[3].x;
    const float prevY = (((prevMatrix.r[0].y * sx) + (prevMatrix.r[2].y * sz)) + (prevMatrix.r[1].y * sy)) + prevMatrix.r[3].y;
    const float prevZ = (((prevMatrix.r[0].z * sx) + (prevMatrix.r[1].z * sy)) + (prevMatrix.r[2].z * sz)) + prevMatrix.r[3].z;
    const float curY = (((curMatrix.r[0].y * sx) + (curMatrix.r[1].y * sy)) + (curMatrix.r[2].y * sz)) + curMatrix.r[3].y;
    const float curZ = (((curMatrix.r[0].z * sx) + (curMatrix.r[1].z * sy)) + (curMatrix.r[2].z * sz)) + curMatrix.r[3].z;

    Wm3::Vector3f direction{};
    direction.x = curX - prevX;
    direction.y = curY - prevY;
    direction.z = curZ - prevZ;
    const float newLength = Wm3::Vector3f::Normalize(&direction) + mLength;

    TrailRuntimeView trail{};
    trail.sortScalar = mTrailBlueprint->SortOrder;

    // Retain the repeat texture (mParticleTextures[0]) into texture0.
    CParticleTexture* const repeatTexture = mParticleTextures.start_[0];
    if (repeatTexture != nullptr) {
      trail.texture0 = repeatTexture;
      repeatTexture->AddReferenceAtomic();
    }
    // Swap the ramp texture (mParticleTextures[1]) into texture1 (release-old /
    // retain-new; texture1 is null here so only the retain fires).
    CParticleTexture* const rampTexture = mParticleTextures.start_[1];
    if (trail.texture1 != rampTexture) {
      if (trail.texture1 != nullptr) {
        (void)trail.texture1->ReleaseReferenceAtomic();
      }
      trail.texture1 = rampTexture;
      if (rampTexture != nullptr) {
        rampTexture->AddReferenceAtomic();
      }
    }

    // Endpoints; emit position is the fresh direction on the first tick, else
    // the persisted trail position.
    const bool firstTick = !mCreated;
    const Wm3::Vector3f& emitPosition = firstTick ? direction : mSerializedTrailPosition;
    trail.prevPosX = prevX;
    trail.prevPosY = prevY;
    trail.prevPosZ = prevZ;
    trail.curPosX = curX;
    trail.curPosY = curY;
    trail.curPosZ = curZ;
    trail.emitPosX = emitPosition.x;
    trail.emitPosY = emitPosition.y;
    trail.emitPosZ = emitPosition.z;
    trail.dirX = direction.x;
    trail.dirY = direction.y;
    trail.dirZ = direction.z;

    // Advance running trail state to the new segment endpoint.
    const float previousLength = mLength;
    mLength = newLength;
    mSerializedTrailPosition.x = direction.x;
    mSerializedTrailPosition.y = direction.y;
    mSerializedTrailPosition.z = direction.z;
    mCreated = true;

    const RTrailBlueprint* const bp = mTrailBlueprint;
    trail.textureRepeatRateX = bp->TextureRepeatRate * previousLength;
    trail.textureRepeatRateZ = bp->TextureRepeatRate * newLength;
    trail.endOffset = static_cast<float>(-1 - tick);
    trail.impactOffset = trail.endOffset + interpScale;
    trail.trailLength = bp->TrailLength;

    const float life = mLife;
    trail.lifeOffset = -life;
    trail.size = bp->StartSize;
    trail.tag = "TPolyTrail";
    // 0x5C lane carries the blueprint blend mode as a raw dword.
    std::memcpy(&trail.uvScalar, &bp->BlendMode, sizeof(trail.uvScalar));
    mLife = life + 1.0f;

    Sim* const sim = mManager->GetSim();
    SParticleBuffer* const particleBuffer = sim->GetParticleBuffer();
    AppendTrailToVector(particleBuffer->mTrails, trail);

    if (dbg_Trail) {
      CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
      SDebugLine line{};
      line.p0.x = direction.y;
      line.p0.y = direction.x;
      line.p0.z = prevX;
      line.p1.x = curY;
      line.p1.y = prevY;
      line.p1.z = prevZ;
      line.depth0 = static_cast<std::int32_t>(0xFF0000FFu);
      line.depth1 = static_cast<std::int32_t>(0xFFFF0000u);
      debugCanvas->DebugDrawLine(line);
    }
  }

  /**
   * Address: 0x00671D90 (FUN_00671D90, Moho::CEfxTrailEmitter::OnTick)
   *
   * IDA signature:
   * void __thiscall Moho::CEfxTrailEmitter::OnTick(Moho::CEfxTrailEmitter *this);
   *
   * What it does:
   * Per-frame trail tick: unless lifetime expired and while visible, bumps the
   * active-emitter engine stat, folds accumulated catch-up ticks into
   * mTotalTicks, clamps the pending trail-segment count to
   * min(bp->TrailLength, 24), emits one STrail per pending segment
   * (mLife reset to 0 before the loop), then emits the final segment for the
   * current frame and advances mTotalTicks by one.
   */
  void CEfxTrailEmitter::OnTick()
  {
    if (ProcessLifetime() || !CalculateVisible()) {
      return;
    }

    if (sEngineStatRenderActiveEmitters == nullptr) {
      EngineStats* const engineStats = GetEngineStats();
      sEngineStatRenderActiveEmitters = engineStats->GetItem("Render_ActiveEmitters", true);
      (void)sEngineStatRenderActiveEmitters->Release(0);
    }
    _InterlockedExchangeAdd(
      reinterpret_cast<volatile long*>(&sEngineStatRenderActiveEmitters->mPrimaryValueBits), 1);

    const std::int32_t pendingTicks = mTrailLength;
    const RTrailBlueprint* const bp = mTrailBlueprint;
    mTotalTicks = static_cast<float>(pendingTicks) + mTotalTicks;

    std::int32_t clampedMax = static_cast<std::int32_t>(bp->TrailLength);
    if (clampedMax > 24) {
      clampedMax = 24;
    }
    if (pendingTicks > clampedMax) {
      mTrailLength = clampedMax;
      mCreated = false;
    }

    std::int32_t remaining = mTrailLength;
    if (remaining != 0) {
      mLife = 0.0f;
      for (; remaining > 0; --remaining) {
        Tick(remaining);
      }
    }

    mTrailLength = 0;
    Tick(0);
    mTotalTicks = mTotalTicks + 1.0f;
  }
} // namespace moho

namespace moho
{
  /**
   * VFTABLE: 0x00E2695C (`??_7CEfxTrailEmitterSerializer@Moho@@6B@`)
   *
   * Demangled base: gpg::SerSaveLoadHelper<class Moho::CEfxTrailEmitter>
   * (base VFTABLE: 0x00E26964, `??_7?$SerSaveLoadHelper@VCEfxTrailEmitter@Moho@@@gpg@@6B@`)
   *
   * Confirmed empty derived class -- NOT a `using` alias. Both vtables carry
   * the *same* Init() address (0x006722F0): `CEfxTrailEmitterSerializer`
   * overrides nothing from the base template. The binary still emits two
   * distinct vtable symbols 8 bytes apart in `.rdata` (0x00E2695C and
   * 0x00E26964), which only happens for two distinct C++ types -- a
   * same-address `using CEfxTrailEmitterSerializer =
   * SerSaveLoadHelper<CEfxTrailEmitter>;` alias (the shape already used for
   * `CAniPoseSerializer` et al. in `CAniPose.h`) can only ever produce one
   * vtable symbol, not two, so that shape does not fit this class.
   *
   * Per-instantiation addresses (T = CEfxTrailEmitter):
   *  - ctor / compiler dynamic-initializer (`register_CEfxTrailEmitterSerializer`):
   *    0x00BD4970, global storage 0x010B40C4. `vtable_writers` shows exactly
   *    one writer for the 0x00E2695C vtable head (no dead-duplicate twin).
   *  - dtor / atexit unlink target: 0x00BFC250 (standard `ResetLinks()`
   *    unlink-then-self-link shape). The real ctor's tail is a plain
   *    `return atexit(sub_BFC250);` -- the compiler's own registration for
   *    this global's non-trivial destructor, inherited unchanged from
   *    `SerSaveLoadHelper<T>::~SerSaveLoadHelper()` -- so no destructor is
   *    declared here. `FUN_00672090` and `FUN_006720C0` are duplicate-emission
   *    twins of that exact unlink/reset lane (same `ResetLinks()` shape,
   *    folded to separate addresses); they have no distinct source-level
   *    body of their own.
   *  - Init(): 0x006722F0 (shared with the base template, not overridden).
   *  - Deserialize() thunk: 0x00672030, tail-jumps into
   *    `CEfxTrailEmitter::MemberDeserialize` at 0x00672710.
   *  - Serialize() thunk: 0x00672040, tail-calls
   *    `CEfxTrailEmitter::MemberSerialize` at 0x00672820.
   */
  class CEfxTrailEmitterSerializer : public gpg::SerSaveLoadHelper<CEfxTrailEmitter>
  {
  };
  static_assert(
    sizeof(CEfxTrailEmitterSerializer) == 0x14, "CEfxTrailEmitterSerializer size must be 0x14"
  );
} // namespace moho

namespace
{
  // Address: 0x010B40C4 -- process-global `CEfxTrailEmitterSerializer`
  // singleton. Constructing it runs the compiler-emitted
  // `register_CEfxTrailEmitterSerializer` dynamic initializer (0x00BD4970),
  // which splices this helper into `gpg::SerHelperBase::sNewHelpers`;
  // `gpg::SerHelperBase::InitNewHelpers()` later dispatches `Init()` on it
  // from within the first `ReadArchive`/`WriteArchive` construction.
  moho::CEfxTrailEmitterSerializer gCEfxTrailEmitterSerializer;
} // namespace
