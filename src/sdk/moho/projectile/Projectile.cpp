#include "moho/projectile/Projectile.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityId.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/math/Wm3DistanceFafExtras.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/WeakObject.h"
#include "moho/projectile/CProjectileAttributes.h"
#include "moho/projectile/ProjectileStartupRegistrations.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/EImpactTypeTypeInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"
#include "Wm3Segment3.h"

namespace moho
{
  // `dbg_Projectile` is the recovered `TConVar<bool>` debug toggle registered by
  // ProjectileStartupRegistrations (register_TConVar_dbg_Projectile @0x00BD62F0).
  // MotionTick reads it as `?dbg_Projectile@Moho@@3_NA` at asm 0x0069C570.
  extern bool dbg_Projectile;
} // namespace moho

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  constexpr std::uint32_t kProjectileCollisionBucketFlags = 0x400u;
  constexpr float kProjectileUnsetValue = -1.0f;
  constexpr float kProjectileBounceVelocityDampingDefault = 0.5f;

  struct ProjectileDeserializeRuntimeView
  {
    std::uint8_t mEntityStateStorage[0x270];
    moho::ManyToOneBroadcaster<moho::EProjectileImpactEvent> mImpactEventBroadcaster;
    moho::WeakPtr<moho::Entity> mLauncherWeak;
    Wm3::Vector3f mVelocity;
    Wm3::Vector3f mLocalAngularVelocity;
    Wm3::Vector3f mScaleVelocity;
    float mImpactInterpolation;
    bool mCollideSurface;
    bool mDoCollision;
    bool mTrackTarget;
    bool mVelocityAlign;
    bool mStayUpright;
    bool mLeadTarget;
    bool mStayUnderwater;
    bool mDestroyOnWater;
    float mTurnRateDegrees;
    float mMaxSpeed;
    float mAcceleration;
    Wm3::Vector3f mBallisticAcceleration;
    // Cached homing aim point (asm this+0x30C). Written from GetTargetPosGun
    // while a live target exists; re-used when the "keep last aim" latch is set.
    Wm3::Vector3f mCachedAimPoint;
    // "Keep last aim" latch (asm this+0x318). Set in the launch ctor for ground
    // targets (non-Air/Sub layer); when set, UpdateTracking keeps steering toward
    // the cached aim point after the live target is lost instead of returning.
    bool mKeepLastAimLatch;
    std::uint8_t mKeepLastAimPadding[3];
    float mDamage;
    float mDamageRadius;
    msvc8::string mDamageTypeName;
    moho::CAiTarget mTargetPosData;
    Wm3::Vector3f mImpactPosition;
    moho::WeakPtr<moho::Entity> mCollidedEntityWeak;
    std::uint32_t mLifetimeEnd;
    bool mBelowWater;
    std::uint8_t mBelowWaterPadding[3];
    std::int32_t mBounceLimit;
    std::int32_t mGroundTick;
    bool mDirectAwayFromGround;
    std::uint8_t mGroundDirectionPadding[3];
    Wm3::Vector3f mGroundDirection;
    float mBounceVelocityDamping;
    std::int32_t mZigZagNextTick;
    Wm3::Vector3f mZigZagRandomOffset;
    moho::EImpactType mImpactType;
    moho::CProjectileAttributes mAttributes;
    bool mIsChildProjectile;
    std::uint8_t mTailPadding[3];
  };

  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactEventBroadcaster) == 0x270,
    "ProjectileDeserializeRuntimeView::mImpactEventBroadcaster offset must be 0x270"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mLauncherWeak) == 0x278,
    "ProjectileDeserializeRuntimeView::mLauncherWeak offset must be 0x278"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mVelocity) == 0x280,
    "ProjectileDeserializeRuntimeView::mVelocity offset must be 0x280"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mLocalAngularVelocity) == 0x28C,
    "ProjectileDeserializeRuntimeView::mLocalAngularVelocity offset must be 0x28C"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mScaleVelocity) == 0x298,
    "ProjectileDeserializeRuntimeView::mScaleVelocity offset must be 0x298"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactInterpolation) == 0x2A4,
    "ProjectileDeserializeRuntimeView::mImpactInterpolation offset must be 0x2A4"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mDestroyOnWater) == 0x2AF,
    "ProjectileDeserializeRuntimeView::mDestroyOnWater offset must be 0x2AF"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mTurnRateDegrees) == 0x2B0,
    "ProjectileDeserializeRuntimeView::mTurnRateDegrees offset must be 0x2B0"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mAcceleration) == 0x2B8,
    "ProjectileDeserializeRuntimeView::mAcceleration offset must be 0x2B8"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBallisticAcceleration) == 0x2BC,
    "ProjectileDeserializeRuntimeView::mBallisticAcceleration offset must be 0x2BC"
  );
  // Layout evidence for this mid-structure lane is still being reconciled.
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactPosition) == 0x31C,
    "ProjectileDeserializeRuntimeView::mImpactPosition offset must be 0x31C"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mCollidedEntityWeak) == 0x328,
    "ProjectileDeserializeRuntimeView::mCollidedEntityWeak offset must be 0x328"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mLifetimeEnd) == 0x330,
    "ProjectileDeserializeRuntimeView::mLifetimeEnd offset must be 0x330"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBelowWater) == 0x334,
    "ProjectileDeserializeRuntimeView::mBelowWater offset must be 0x334"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBounceLimit) == 0x338,
    "ProjectileDeserializeRuntimeView::mBounceLimit offset must be 0x338"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mGroundTick) == 0x33C,
    "ProjectileDeserializeRuntimeView::mGroundTick offset must be 0x33C"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mDirectAwayFromGround) == 0x340,
    "ProjectileDeserializeRuntimeView::mDirectAwayFromGround offset must be 0x340"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mGroundDirection) == 0x344,
    "ProjectileDeserializeRuntimeView::mGroundDirection offset must be 0x344"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBounceVelocityDamping) == 0x350,
    "ProjectileDeserializeRuntimeView::mBounceVelocityDamping offset must be 0x350"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mZigZagNextTick) == 0x354,
    "ProjectileDeserializeRuntimeView::mZigZagNextTick offset must be 0x354"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mZigZagRandomOffset) == 0x358,
    "ProjectileDeserializeRuntimeView::mZigZagRandomOffset offset must be 0x358"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactType) == 0x364,
    "ProjectileDeserializeRuntimeView::mImpactType offset must be 0x364"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mAttributes) == 0x368,
    "ProjectileDeserializeRuntimeView::mAttributes offset must be 0x368"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mIsChildProjectile) == 0x37C,
    "ProjectileDeserializeRuntimeView::mIsChildProjectile offset must be 0x37C"
  );
  static_assert(sizeof(ProjectileDeserializeRuntimeView) == 0x380, "ProjectileDeserializeRuntimeView size must be 0x380");

  template <class T>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(T));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* CachedEntityType()
  {
    static gpg::RType* cached = nullptr;
    return CachedType<moho::Entity>(cached);
  }

  [[nodiscard]] gpg::RType* CachedImpactBroadcasterType()
  {
    return CachedType<moho::ManyToOneBroadcaster_EProjectileImpactEvent>(moho::ManyToOneBroadcaster_EProjectileImpactEvent::sType);
  }

  [[nodiscard]] gpg::RType* CachedWeakEntityType()
  {
    return CachedType<moho::WeakPtr<moho::Entity>>(moho::WeakPtr<moho::Entity>::sType);
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    return CachedType<Wm3::Vector3f>(cached);
  }

  [[nodiscard]] gpg::RType* CachedAiTargetType()
  {
    return CachedType<moho::CAiTarget>(moho::CAiTarget::sType);
  }

  [[nodiscard]] gpg::RType* CachedProjectileAttributesType()
  {
    return CachedType<moho::CProjectileAttributes>(moho::CProjectileAttributes::sType);
  }

  [[nodiscard]] [[maybe_unused]] gpg::RType* CachedProjectileType()
  {
    return CachedType<moho::Projectile>(moho::Projectile::sType);
  }

  [[nodiscard]] gpg::RRef MakeProjectileRef(moho::Projectile* const object)
  {
    // Delegates to the recovered gpg::RRef_Projectile (FUN_0069FEA0), which
    // performs the polymorphic derived-type normalization the earlier inline
    // stand-in elided.
    gpg::RRef out{};
    gpg::RRef_Projectile(&out, object);
    return out;
  }

  /**
   * Address: 0x0069F8B0 (FUN_0069F8B0)
   *
   * What it does:
   * Builds one temporary projectile reference and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackProjectileRef(
    gpg::RRef* const out,
    moho::Projectile* const object
  )
  {
    const gpg::RRef ref = MakeProjectileRef(object);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }

#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  void UnlinkImpactBroadcaster(moho::ManyToOneBroadcaster<moho::EProjectileImpactEvent>& broadcaster) noexcept
  {
    // The broadcaster's {ownerLinkSlot@0, nextInOwner@4} pair is the same
    // intrusive prev/next owner-chain shape a WeakPtr link uses; the projectile
    // dtor detaches it from its owner chain (asm 0x0069E144-0x0069E163).
    auto& weakLink = reinterpret_cast<moho::WeakPtr<void>&>(broadcaster);
    weakLink.UnlinkFromOwnerChain();
  }

  // Pops (and, when not auto-owned, destroys) the top task off the entity's own
  // CTask-subobject owner thread. Mirrors the inline teardown the projectile ctor
  // performs after each immediate Entity::Destroy() (asm 0x0069BC0F-0069BC3C and
  // 0x0069BD23-0069BD47). The `[ebp+40h]` receiver is the Entity's CTask subobject
  // `mOwnerThread` (CTask base at Entity+0x34, mOwnerThread at +0x0C -> Entity+0x40).
  void PopOwnedTaskThreadTop(moho::Entity* const entity) noexcept
  {
    moho::CTaskThread* const thread = static_cast<moho::CTask*>(entity)->mOwnerThread;
    if (thread == nullptr) {
      return;
    }

    moho::CTask* const task = thread->mTaskTop;
    if (task == nullptr) {
      return;
    }

    thread->mTaskTop = task->mSubtask;
    const bool autoOwned = task->mAutoDelete;
    task->mSubtask = nullptr;
    task->mOwnerThread = nullptr;
    if (!autoOwned) {
      // Binary calls the task's scalar-deleting destructor lane (`dtr(this, 1)`).
      delete task;
    }
  }

  // Per-tick delta-time scale used throughout MotionTick / CheckCollision:
  // ds:dbl_E4F710+4 == 0.1f (one sim tick == 0.1s of physics integration).
  constexpr float kProjectileTickSeconds = 0.1f;
  // Blend fraction for the 0.05f half-tick position advance (ds:dword_E4F7FC).
  constexpr float kProjectileHalfTickBlend = 0.05f;
  // Degrees->radians (ds:dword_E4F768 == 0.017453292f).
  constexpr float kProjectileDegToRad = 0.017453292f;
  // Terrain-bounce velocity retention on each ground hit (ds:dword_E4F99C == 0.95f).
  constexpr float kProjectileBounceInterpDamp = 0.94999999f;

  // Re-derivation of the file-static FUN_005D1E70 (LimitVectorLengthTo, canonical
  // body lives in CSlideManipulator.cpp as `LimitVectorLengthTo`, not cross-TU
  // linkable). Clamps `vec` to `maxLen` in place, preserving direction; leaves
  // zero-length / already-short vectors untouched. MotionTick's max-speed cap.
  void ClampVectorToMaxLength(Wm3::Vector3f& vec, const float maxLength) noexcept
  {
    if (maxLength <= 0.0f) {
      return;
    }
    const float lengthSq = (vec.x * vec.x) + (vec.y * vec.y) + (vec.z * vec.z);
    if (lengthSq <= maxLength * maxLength) {
      return;
    }
    const float length = std::sqrt(lengthSq);
    if (length > 0.0f) {
      const float scale = maxLength / length;
      vec.x *= scale;
      vec.y *= scale;
      vec.z *= scale;
    }
  }

  // Re-derivation of the file-static FUN_0069A2A0 (canonical
  // `ProjectVectorOntoAxis` in CUnitMotion.cpp, file-static, not cross-TU
  // linkable). Returns the component of `vector` along `axis`
  // (axis * dot(vector,axis)/|axis|^2); zero when `axis` is degenerate. Used by
  // UpdateTracking's velocity-align to snap velocity onto the new forward axis.
  [[nodiscard]] Wm3::Vector3f ProjectVectorOntoAxisLocal(
    const Wm3::Vector3f& axis,
    const Wm3::Vector3f& vector
  ) noexcept
  {
    const float axisLengthSq = (axis.x * axis.x) + (axis.y * axis.y) + (axis.z * axis.z);
    if (axisLengthSq <= 0.0f) {
      return {};
    }
    const float scale =
      ((vector.x * axis.x) + (vector.y * axis.y) + (vector.z * axis.z)) / axisLengthSq;
    return Wm3::Vector3f{axis.x * scale, axis.y * scale, axis.z * scale};
  }

  // Re-derivation of the file-static FUN_0066D1D0 (canonical
  // `FloorScaledByTenFrndintAdjustDown` in GridPos.cpp, file-static, not cross-TU
  // linkable). Converts a seconds interval into a floored per-tick count; used by
  // UpdateTracking's zig-zag re-schedule (asm 0x0069CD5E: call sub_66D1D0).
  [[nodiscard]] int FloorSecondsToTicks(const float seconds) noexcept
  {
    const float scaled = seconds * 10.0f;
    const double rounded = std::nearbyint(static_cast<double>(scaled));
    return static_cast<int>(rounded) + ((static_cast<double>(scaled) < rounded) ? -1 : 0);
  }

  /**
   * Address: 0x0069F6B0 (FUN_0069F6B0, func_OnCollisionCheck)
   *
   * IDA signature:
   * bool __thiscall func_OnCollisionCheck(Moho::Entity *collidedEntity, Moho::CScriptObject **projectile);
   *
   * What it does:
   * Faithful transcription of the entity-side `OnCollisionCheck(self, other)` Lua
   * hook: installs an intrusive weak-link guard on the collided entity, resolves
   * its `OnCollisionCheck` script, and calls it with `(collided.mLuaObj,
   * projectile)`, returning the script's boolean verdict (false when no script is
   * bound). Returns whether the collision should register.
   *
   * NOTE: the canonical home of this function is `Entity`/`CScriptObject`
   * (CScriptObject.cpp). It is recovered here as a file-static because the current
   * recovery pass may only edit `Projectile.*`; its sole caller in the binary is
   * `Projectile::CheckCollision`. Mirrors the recovered
   * `CScriptObject::RunScriptOnCollisionCheckWeapon` idiom (bool-returning hook).
   */
  [[nodiscard]] bool RunProjectileOnCollisionCheckScript(
    moho::Entity* const collidedEntity,
    moho::Entity* const projectile
  )
  {
    if (collidedEntity == nullptr) {
      return false;
    }

    // Intrusive weak-link guard on the collided entity for the duration of the
    // script call (asm 0x0069F6C1-0x0069F6F0 owner-chain register/unregister).
    moho::WeakObject::ScopedWeakLinkGuard weakGuard(static_cast<moho::WeakObject*>(collidedEntity));

    LuaPlus::LuaObject script;
    collidedEntity->FindScript(&script, "OnCollisionCheck");
    if (!script) {
      return false;
    }

    LuaPlus::LuaFunction<bool> callback(script);
    return callback(collidedEntity->mLuaObj, projectile);
  }

  // Ray/water-plane crossing used by CheckCollision Branch A2 (asm
  // 0x0069D336-0x0069D4D7). The binary builds a downward-ish GeomLine3 from the
  // current position and calls the file-static Moho::CColHitResult::PlaneIntersection
  // (FUN_00577540, not cross-TU linkable). This re-derivation reproduces the same
  // horizontal-plane (constant y == waterElevation) crossing: it parametrizes the
  // swept segment curPos->nextPos and solves for the point where y == plane.
  // Returns false (leaving `outHit` untouched) when the segment does not cross the
  // plane within [curPos, nextPos] (parallel or the plane is outside the span).
  [[nodiscard]] bool WaterPlaneIntersection(
    Wm3::Vector3f& outHit,
    const Wm3::Vector3f& curPos,
    const Wm3::Vector3f& nextPos,
    const float waterElevation
  ) noexcept
  {
    const float dy = nextPos.y - curPos.y;
    if (dy == 0.0f) {
      // Segment runs parallel to the water plane: no single crossing point.
      return false;
    }
    const float t = (waterElevation - curPos.y) / dy;
    if (t < 0.0f || t > 1.0f) {
      return false;
    }
    outHit.x = curPos.x + (nextPos.x - curPos.x) * t;
    outHit.y = waterElevation;
    outHit.z = curPos.z + (nextPos.z - curPos.z) * t;
    return true;
  }

  // Squared distance from `point` to the swept `segment`, also emitting the
  // closest point on the segment. Wraps the recovered
  // Wm3::DistVector3Segment3f::GetSquared (FUN_00A484F0) — the same primitive the
  // binary constructs inline in CheckCollision Branch C (asm 0x0069D66C:
  // ??0DistVector3Segment3@Wm3@@; 0x0069D692: GetSquared; 0x0069D706: GetEndPoint).
  // The closest-point-on-segment output is exactly DistVector3Segment3::GetEndPoint.
  [[nodiscard]] float DistPointToSegmentSquared(
    const Wm3::Vector3f& point,
    const Wm3::Segment3f& segment,
    Wm3::Vector3f* closestOnSegment
  ) noexcept
  {
    return Wm3::DistVector3Segment3fGetSquared(point, segment, closestOnSegment);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0069AC30 (FUN_0069AC30, Moho::Projectile::Projectile)
   *
   * What it does:
   * Constructs one archive-owned projectile shell from simulation owner
   * context, initializes runtime lanes, and increments the projectile
   * instance counter stat.
   */
  Projectile::Projectile(Sim* const sim)
    : Entity(sim, kProjectileCollisionBucketFlags)
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    view.mImpactEventBroadcaster = {};

    AddInstanceCounterDelta(InstanceCounter<Projectile>::GetStatItem(), 1L);

    view.mLauncherWeak.ClearLinkState();
    view.mVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mLocalAngularVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mScaleVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactInterpolation = kProjectileUnsetValue;
    view.mCollideSurface = false;
    view.mDoCollision = false;
    view.mTrackTarget = false;
    view.mVelocityAlign = false;
    view.mStayUpright = false;
    view.mLeadTarget = false;
    view.mStayUnderwater = false;
    view.mDestroyOnWater = false;
    view.mTurnRateDegrees = 0.0f;
    view.mMaxSpeed = 0.0f;
    view.mAcceleration = 0.0f;
    view.mBallisticAcceleration = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mDamage = 0.0f;
    view.mDamageRadius = 0.0f;

    view.mTargetPosData.targetType = EAiTargetType::AITARGET_Entity;
    view.mTargetPosData.targetEntity.ClearLinkState();
    view.mTargetPosData.targetPoint = -1;
    view.mTargetPosData.targetIsMobile = false;
    view.mTargetPosData.PickTargetPoint();

    view.mCachedAimPoint = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mKeepLastAimLatch = false;
    view.mImpactPosition = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mCollidedEntityWeak.ClearLinkState();
    view.mLifetimeEnd = 0u;
    view.mBelowWater = false;
    view.mBounceLimit = 0;
    view.mGroundTick = 0;
    view.mDirectAwayFromGround = false;
    view.mGroundDirection = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mBounceVelocityDamping = kProjectileBounceVelocityDampingDefault;
    view.mZigZagNextTick = 0;
    view.mZigZagRandomOffset = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactType = IMPACT_Air;
    view.mAttributes = CProjectileAttributes();
    view.mIsChildProjectile = false;
  }

  namespace
  {
    // Randomized physics scalar: base + symmetric random in [-range, +range].
    // The binary inlines the (-range) + ((range - (-range)) * u32 * 2^-32) form
    // for turn-rate / max-speed / acceleration / lifetime / draw-scale /
    // scale-velocity; keep the exact arithmetic instead of calling the blueprint
    // GetRandom* helpers (the binary does not call them here).
    [[nodiscard]] float RandomSymmetricAround(CRandomStream* const rng, const float base, const float range) noexcept
    {
      const float randomBits = static_cast<float>(rng->twister.NextUInt32());
      return (-range) + ((range - (-range)) * randomBits * 2.3283064e-10f) + base;
    }
  } // namespace

  /**
   * Address: 0x0069AFE0 (FUN_0069AFE0, Moho::Projectile::Projectile)
   * Mangled: ??0Projectile@Moho@@QAE@PBVRProjectileBlueprint@1@PAVSim@1@PAVSimArmy@1@PAVEntity@1@VVTransform@1@MMV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVCAiTarget@1@_N@Z
   *
   * IDA signature:
   * Moho::Projectile *__thiscall Moho::Projectile::Projectile(
   *     Moho::Sim *sim, Moho::Projectile *this, Moho::RProjectileBlueprint *blueprint,
   *     Moho::CArmyImpl *army, Moho::Entity *entity, struct_VecQuat posori,
   *     float damage, int a14, std::string a15, Moho::CAiTarget *a16, int a17);
   *
   * What it does:
   * Constructs one live projectile from runtime launch parameters: reserves a
   * projectile-family entity id in the owning army's source-index lane, runs the
   * base Entity ctor, seeds randomized physics lanes (turn / max-speed / accel /
   * lifetime / draw-scale / scale-velocity) from blueprint spread ranges, splices
   * the launcher and target weak links, computes launch velocity (realistic-
   * ordinance inherits launcher velocity + optional bomb-drop prediction, else a
   * quaternion forward vector scaled by a random initial speed), writes the
   * current / previous / pending transforms, links into the Sim coord list,
   * selects the initial layer (Air / below-water), fires OnPreCreate /
   * OnLayerChange / OnCreate scripts, applies the mesh, and self-destructs when
   * spawned below water with mDestroyOnWater set.
   */
  Projectile::Projectile(
    const RProjectileBlueprint* const blueprint,
    Sim* const sim,
    CArmyImpl* const army,
    Entity* const sourceEntity,
    const VTransform& launchTransform,
    const float damage,
    const float damageRadius,
    const msvc8::string& damageTypeName,
    const CAiTarget& target,
    const bool isChildProjectile
  )
    // Reserve a projectile-family id in this army's source-index lane (index 255
    // when unowned); the base ctor installs it and the projectile collision bucket.
    : Entity(
        const_cast<RProjectileBlueprint*>(blueprint),
        sim,
        static_cast<EntId>(sim->mEntityDB->DoReserveId(
          ((static_cast<std::uint32_t>(army == nullptr ? 255 : army->ArmyId) | 0x100u) << kEntityIdSourceShift)
        )),
        kProjectileCollisionBucketFlags
      )
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);

    // Impact-broadcaster storage (+0x270) cleared to two null dwords.
    view.mImpactEventBroadcaster = {};

    AddInstanceCounterDelta(InstanceCounter<Projectile>::GetStatItem(), 1L);

    // Launcher weak link (+0x278): raw splice to the source entity's owner chain
    // head. The binary binds unlinked + head-inserts here (fresh storage, no
    // detach), then re-Sets to the resolved launcher further below.
    if (sourceEntity != nullptr) {
      view.mLauncherWeak.BindObjectUnlinked(sourceEntity);
      (void)view.mLauncherWeak.LinkIntoOwnerChainHeadUnlinked();
    } else {
      view.mLauncherWeak.ClearLinkState();
    }

    CRandomStream* const rng = sim->mRngState;

    view.mVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mLocalAngularVelocity = blueprint->GetAngularVelocity(rng);

    view.mImpactInterpolation = kProjectileUnsetValue; // flt_E4F6E8 == -1.0

    view.mCollideSurface = blueprint->Physics.CollideSurface != 0;
    view.mDoCollision = blueprint->Physics.CollideEntity != 0;
    view.mTrackTarget = blueprint->Physics.TrackTarget != 0;
    view.mVelocityAlign = blueprint->Physics.VelocityAlign != 0;
    view.mStayUpright = blueprint->Physics.StayUpright != 0;
    view.mLeadTarget = blueprint->Physics.LeadTarget != 0;
    view.mStayUnderwater = blueprint->Physics.StayUnderwater != 0;
    view.mDestroyOnWater = blueprint->Physics.DestroyOnWater != 0;

    view.mTurnRateDegrees = RandomSymmetricAround(rng, blueprint->Physics.TurnRate, blueprint->Physics.TurnRateRange);
    view.mMaxSpeed = RandomSymmetricAround(rng, blueprint->Physics.MaxSpeed, blueprint->Physics.MaxSpeedRange);
    view.mAcceleration = RandomSymmetricAround(rng, blueprint->Physics.Acceleration, blueprint->Physics.AccelerationRange);

    // Ballistic acceleration = UseGravity(0/1) * sim gravity vector.
    {
      const Wm3::Vector3f& gravity = sim->mPhysConstants->mGravity;
      const float useGravity = static_cast<float>(blueprint->Physics.UseGravity);
      view.mBallisticAcceleration =
        Wm3::Vector3f{useGravity * gravity.x, useGravity * gravity.y, useGravity * gravity.z};
    }

    view.mDamage = damage;
    view.mDamageRadius = damageRadius;
    view.mDamageTypeName = damageTypeName;

    // Inline CAiTarget copy from `target` (asm 0x0069B2EB-0069B33B): payload copy
    // plus target-entity weak-link splice (bind source's object slot, head-insert).
    view.mTargetPosData.targetType = target.targetType;
    view.mTargetPosData.targetEntity.BindObjectUnlinked(target.targetEntity.GetObjectPtr());
    (void)view.mTargetPosData.targetEntity.LinkIntoOwnerChainHeadUnlinked();
    view.mTargetPosData.position = target.position;
    view.mTargetPosData.targetPoint = target.targetPoint;
    view.mTargetPosData.targetIsMobile = target.targetIsMobile;

    // Runtime-lane defaults (asm zero-init block 0x0069B33E-0069B432).
    view.mCachedAimPoint = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mKeepLastAimLatch = false;
    view.mImpactPosition = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mCollidedEntityWeak.ClearLinkState();
    view.mBounceLimit = 0;
    view.mGroundTick = 0;
    view.mBelowWater = false;
    view.mDirectAwayFromGround = false;
    view.mGroundDirection = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mBounceVelocityDamping = blueprint->Physics.BounceVelDamp;
    view.mZigZagNextTick = 0;
    view.mZigZagRandomOffset = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactType = IMPACT_Air;

    view.mAttributes.mBlueprint = const_cast<RProjectileBlueprint*>(blueprint);
    view.mAttributes.mMaxZigZag = kProjectileUnsetValue;
    view.mAttributes.mZigZagFrequency = kProjectileUnsetValue;
    view.mAttributes.mDetonateAboveHeight = kProjectileUnsetValue;
    view.mAttributes.mDetonateBelowHeight = kProjectileUnsetValue;

    view.mIsChildProjectile = isChildProjectile;

    // Lifetime end tick = curTick + int((Physics.Lifetime + rand(±LifetimeRange)) * 10).
    {
      const float lifetimeSeconds =
        RandomSymmetricAround(rng, blueprint->Physics.Lifetime, blueprint->Physics.LifetimeRange);
      const std::uint32_t curTick = SimulationRef->mCurTick;
      view.mLifetimeEnd =
        curTick + static_cast<std::uint32_t>(static_cast<std::int32_t>(lifetimeSeconds * 10.0f));
    }

    // Resolve the launcher: chase through a projectile source to its own launcher.
    Entity* resolvedLauncher = sourceEntity;
    if (sourceEntity != nullptr && sourceEntity->IsProjectile() != nullptr) {
      resolvedLauncher = sourceEntity->IsProjectile()->GetLauncherEntity();
    }
    view.mLauncherWeak.Set(resolvedLauncher);

    mQueueRelinkBlocked = 1;   // v3a (Entity+0x1B8)
    mVisibilityState = 1;      // mVarDat.mNotVisibility (Entity+0x110)
    this->RunScript("OnPreCreate");

    // Bounce count uniform pick in [MinBounceCount, MaxBounceCount).
    {
      const std::int32_t minBounce = blueprint->Physics.MinBounceCount;
      const std::int32_t maxBounce = blueprint->Physics.MaxBounceCount;
      const std::uint32_t randomBits = rng->twister.NextUInt32();
      const std::uint32_t scaled = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(static_cast<std::uint32_t>(maxBounce - minBounce)) *
         static_cast<std::uint64_t>(randomBits)) >> 32
      );
      view.mBounceLimit = minBounce + static_cast<std::int32_t>(scaled);
    }

    // Launch velocity.
    Entity* const launcherEntity = view.mLauncherWeak.GetObjectPtr();
    if (blueprint->Physics.RealisticOrdinance != 0 && launcherEntity != nullptr) {
      // Inherit the launcher's velocity (scaled to per-tick units).
      const Wm3::Vec3f launcherVelocity = launcherEntity->GetVelocity();
      view.mVelocity = Wm3::Vector3f{
        launcherVelocity.x * 10.0f,
        launcherVelocity.y * 10.0f,
        launcherVelocity.z * 10.0f,
      };

      if (view.mTargetPosData.HasTarget() && launcherEntity->IsUnit() != nullptr) {
        Wm3::Vec3f aimPoint = view.mTargetPosData.GetTargetPosGun(false);

        Unit* const launcherUnit = launcherEntity->IsUnit();
        if (launcherUnit->GetBlueprint()->Air.PredictAheadForBombDrop > 0.0f && target.targetIsMobile) {
          Unit* const predictUnit = launcherEntity->IsUnit();
          const float precision = predictUnit->GetBlueprint()->Air.PredictAheadForBombDrop;
          Entity* const targetEntity = view.mTargetPosData.GetEntity();
          Wm3::Vec3f predicted{};
          (void)targetEntity->IsUnit()->PredictAheadBomb(&predicted, precision);
          aimPoint = predicted;
        }

        // Steer the inherited horizontal velocity toward the aim point relative
        // to the launcher, preserving the inherited speed. The Y lane is left
        // untouched (steer vector's Y is forced to 0 before VecSetLength).
        Wm3::Vector3f steerHorizontal{
          aimPoint.x - launcherEntity->Position.x,
          0.0f,
          aimPoint.z - launcherEntity->Position.z,
        };
        const float inheritedSpeed = std::sqrt(
          (view.mVelocity.x * view.mVelocity.x) +
          (view.mVelocity.y * view.mVelocity.y) +
          (view.mVelocity.z * view.mVelocity.z)
        );
        (void)moho::VecSetLength(&steerHorizontal, inheritedSpeed);

        view.mVelocity.x += (steerHorizontal.x - view.mVelocity.x);
        view.mVelocity.y += (steerHorizontal.y - view.mVelocity.y);
        view.mVelocity.z += (steerHorizontal.z - view.mVelocity.z);
      }

      // Lateral jitter driven by the entity's collision-bounds Z extent
      // (Entity+0x248 == mCollisionBoundsMin.z): if positive, jitter X and Z.
      const float jitter = mCollisionBoundsMin.z;
      if (jitter > 0.0f) {
        view.mVelocity.x += rng->FRand(-jitter, jitter);
        view.mVelocity.z += rng->FRand(-jitter, jitter);
      }
    } else {
      // Ballistic forward direction derived from the launch quaternion, scaled by
      // a random initial speed (asm 0x0069B85F-0x0069B918). Transcribed 1:1 from the
      // .asm (movaps/mulss/addss/subss chain, flt_DFEB0C == 2.0); the store order
      // (mVelocity.x/y/z <- result.y / result.z / var_10 each * GetRandomInitialSpeed)
      // is confirmed. Lane mapping resolved against the algebra: the four values the
      // asm loads at 0x0069B55C-0x0069B56E (IDA slot labels x/y/z/qx) map to
      // orient_.w / orient_.y / orient_.z / orient_.x respectively, since that is the
      // only binding for which the forward vector R(orient)*(1,0,0) matches
      // result.y = 2(qx*qy + qz*qw), result.z = 2(qx*qz - qy*qw),
      // var_10 = 1 - 2(qz^2 + qy^2). The typed orient_.{x,y,z,w} access below is
      // therefore exact for both realistic and ballistic launches.
      const float qx = launchTransform.orient_.x;
      const float qy = launchTransform.orient_.y;
      const float qz = launchTransform.orient_.z;
      const float qw = launchTransform.orient_.w;

      const float forwardY = ((qx * qy) + (qz * qw)) * 2.0f;
      const float forwardZ = ((qx * qz) - (qy * qw)) * 2.0f;
      const float forwardX = 1.0f - (((qz * qz) + (qy * qy)) * 2.0f);

      const float initialSpeed = blueprint->GetRandomInitialSpeed(rng);
      view.mVelocity = Wm3::Vector3f{forwardY * initialSpeed, forwardZ * initialSpeed, forwardX * initialSpeed};
    }

    // Draw scale = Display.UniformScale + rand(±Display.MeshScaleRange).
    {
      const float scale =
        RandomSymmetricAround(rng, blueprint->Display.UniformScale, blueprint->Display.MeshScaleRange);
      mDrawScaleX = scale;
      mDrawScaleY = scale;
      mDrawScaleZ = scale;
    }

    // Splice the coord node into Sim::mCoordEntities at the FRONT: the binary
    // self-inits the node to a singleton then inserts it immediately after the
    // list sentinel (ListLinkAfter unlinks-first, matching that exactly).
    mCoordNode.ListLinkAfter(&sim->mCoordEntities);

    // Scale velocity = Display.MeshScaleVelocity + rand(±Display.MeshScaleVelocityRange).
    {
      const float scaleVelocity = RandomSymmetricAround(
        rng, blueprint->Display.MeshScaleVelocity, blueprint->Display.MeshScaleVelocityRange
      );
      view.mScaleVelocity = Wm3::Vector3f{scaleVelocity, scaleVelocity, scaleVelocity};
    }

    // Write current / previous / pending transforms verbatim from the launch
    // transform. Orientation is copied as the raw quaternion tuple (m_afTuple order
    // w,x,y,z) to match the binary's straight 4-float lane copy.
    const Vector4f launchOrientation{
      launchTransform.orient_[0],
      launchTransform.orient_[1],
      launchTransform.orient_[2],
      launchTransform.orient_[3],
    };
    PendingOrientation = launchOrientation;
    PendingPosition = launchTransform.pos_;
    Orientation = launchOrientation;
    Position = launchTransform.pos_;
    PrevOrientation = launchOrientation;
    PrevPosition = launchTransform.pos_;

    bool skipLayerAndMesh = false;
    if (view.mTrackTarget) {
      if (view.mTargetPosData.HasTarget()) {
        // v207 (mKeepLastAimLatch) := 1 unless the target's current layer is
        // Air (0x10) or Sub (0x04).
        Entity* const trackedEntity = view.mTargetPosData.targetEntity.GetObjectPtr();
        if (trackedEntity != nullptr) {
          const ELayer trackedLayer = trackedEntity->mCurrentLayer;
          if (trackedLayer != LAYER_Air && trackedLayer != LAYER_Sub) {
            view.mKeepLastAimLatch = true;
          }
        }
        const Wm3::Vec3f gunPos = view.mTargetPosData.GetTargetPosGun(false);
        view.mCachedAimPoint = Wm3::Vector3f{gunPos.x, gunPos.y, gunPos.z};
      } else {
        // Tracking with no live target: destroy immediately and skip layer/mesh.
        this->Destroy();
        PopOwnedTaskThreadTop(this);
        skipLayerAndMesh = true;
      }
    }

    if (!skipLayerAndMesh) {
      // Initial layer selection from map water level vs launch height (pos.y).
      const float currentHeight = launchTransform.pos_.y;
      STIMap* const mapData = SimulationRef->mMapData;
      const float waterElevation = mapData->mWaterEnabled ? mapData->mWaterElevation : -10000.0f;
      const ELayer previousLayer = mCurrentLayer;

      if (waterElevation <= currentHeight) {
        mCurrentLayer = LAYER_Air;
        if (previousLayer != LAYER_Air) {
          const char* newLayerName = Entity::LayerToString(LAYER_Air);
          const char* oldLayerName = Entity::LayerToString(previousLayer);
          this->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
        }
      } else {
        view.mBelowWater = true;
        mCurrentLayer = LAYER_Water;
        if (previousLayer != LAYER_Water) {
          const char* newLayerName = Entity::LayerToString(LAYER_Water);
          const char* oldLayerName = Entity::LayerToString(previousLayer);
          this->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
        }
      }

      this->SetMesh(blueprint->Display.MeshBlueprint, nullptr, true);

      if (view.mBelowWater && view.mDestroyOnWater) {
        this->Destroy();
        PopOwnedTaskThreadTop(this);
      } else {
        this->RunScriptWithBool("OnCreate", view.mBelowWater);
      }

      /* UNRESOLVED (2 of 2 remaining): camera-follow sync-vector push, asm
       * 0x0069BD56-0x0069BD8E.
       * When Display.CameraFollowsProjectile != 0 the binary pushes a 12-byte lane
       * {this->id_, <sim field @ +0x68>, Display.CameraFollowTimeout} into
       * SimulationRef->mSyncSerializeGroup1 (Sim+0x9B8) via sub_69E6D0. The only
       * recovered expression of this push is the offset-magic helper
       * AppendProjectileLaneFromOwnerOffsetRuntime in SimRecoveryRuntime.cpp, which
       * is outside this task's editable file set, and the lane's middle field
       * (read as [ecx+0x68]) is not yet identified. Omitted rather than fabricating
       * raw offset arithmetic; wire to the recovered Sim sync-push helper in a
       * follow-up pass. */
    }
  }

  /**
   * Address: 0x0069AED0 (FUN_0069AED0, Moho::Projectile::~Projectile)
   *
   * What it does:
   * Unlinks intrusive weak/broadcaster lanes owned by this projectile and
   * decrements the projectile instance-counter stat before member/base
   * destructors run.
   */
  Projectile::~Projectile()
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    // Unlink the collided-entity weak ref (asm this+0x328). It lives in the opaque
    // mUnknown030C region and WeakPtr's destructor is trivial, so nothing unlinks it
    // automatically -- without this it dangles in the collided entity's weak-ref
    // chain and faults when that entity later traverses/destroys the chain. The
    // binary unlinks it first (reverse-declaration order), before the CAiTarget ref.
    view.mCollidedEntityWeak.UnlinkFromOwnerChain();
    view.mTargetPosData.targetEntity.UnlinkFromOwnerChain();
    view.mLauncherWeak.UnlinkFromOwnerChain();

    AddInstanceCounterDelta(InstanceCounter<Projectile>::GetStatItem(), -1L);
    UnlinkImpactBroadcaster(view.mImpactEventBroadcaster);
  }

  /**
   * Address: 0x0069A610 (FUN_0069A610, Moho::Projectile::IsProjectile)
   *
   * What it does:
   * Returns this projectile pointer through the RTTI/downcast lane.
   */
  Projectile* Projectile::IsProjectile()
  {
    return this;
  }

  /**
   * Address: 0x0069A5D0 (FUN_0069A5D0)
   *
   * What it does:
   * Returns this projectile's owning army pointer lane.
   */
  CArmyImpl* Projectile::GetArmyOwner() const
  {
    return ArmyRef;
  }

  /**
   * Address: 0x0069A5E0 (FUN_0069A5E0)
   *
   * What it does:
   * Returns the resolved launcher entity from this projectile weak-launcher
   * lane.
   */
  Entity* Projectile::GetLauncherEntity() const
  {
    const auto& view = *reinterpret_cast<const ProjectileDeserializeRuntimeView*>(this);
    return view.mLauncherWeak.GetObjectPtr();
  }

  /**
   * Address: 0x0069DE80 (FUN_0069DE80, Moho::Projectile::SetLifetime)
   *
   * What it does:
   * Sets the projectile expiration tick to `mCurTick + int(seconds * 10.0f)`.
   */
  void Projectile::SetLifetime(const float lifetimeSeconds)
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    const std::uint32_t lifetimeTicks = static_cast<std::uint32_t>(static_cast<std::int32_t>(lifetimeSeconds * 10.0f));
    view.mLifetimeEnd = SimulationRef->mCurTick + lifetimeTicks;
  }

  /**
   * Address: 0x0069BDD0 (FUN_0069BDD0, Moho::Projectile::MotionTick)
   * Mangled: ?MotionTick@Projectile@Moho@@UAE?AW4ETaskStatus@2@XZ
   *
   * IDA signature:
   * int __thiscall Moho::Projectile::MotionTick(Moho::Projectile *this);
   *
   * What it does:
   * Per-frame projectile update. If an impact is already pending
   * (mImpactInterpolation >= 0) it detonates immediately via Impact() and returns.
   * Otherwise it: applies any queued ground-bounce direction, advances mesh-scale
   * animation by mScaleVelocity, relinks the coord node to the Sim coord tail,
   * integrates velocity (ballistic gravity+forward accel, or homing steering via
   * UpdateTracking), caps to mMaxSpeed, applies stay-upright / local-spin, writes
   * the pending transform, runs CheckCollision(), handles lifetime expiry, draws
   * debug geometry when dbg_Projectile is set, and drives the terrain-bounce
   * impact interpolation. Always returns ETaskStatus 1 (continue).
   */
  int Projectile::MotionTick()
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);

    // Already impacting: detonate this tick and continue.
    if (view.mImpactInterpolation >= 0.0f) {
      this->Impact();
      return 1;
    }

    // A ground bounce queued last tick installs its reflected velocity now.
    if (view.mDirectAwayFromGround) {
      view.mVelocity = view.mGroundDirection;
      view.mDirectAwayFromGround = false;
    }

    // Snapshot the current world transform into a working VTransform. Orientation
    // is copied as the raw 4-float tuple (matches the binary's lane copy; the
    // ctor uses the same straight copy convention).
    VTransform tran;
    tran.orient_ = Wm3::Quatf{Orientation.x, Orientation.y, Orientation.z, Orientation.w};
    tran.pos_ = Position;

    // Advance mesh draw-scale by scale velocity (per-tick).
    const Wm3::Vector3f startVelocity = view.mVelocity;
    mDrawScaleX += view.mScaleVelocity.x * kProjectileTickSeconds;
    mDrawScaleY += view.mScaleVelocity.y * kProjectileTickSeconds;
    mDrawScaleZ += view.mScaleVelocity.z * kProjectileTickSeconds;

    // Relink the coord node at the FRONT of the Sim coord list: the binary
    // unlinks then inserts immediately after the sentinel (node.prev=sentinel,
    // node.next=sentinel.next, sentinel.next=node), asm 0x0069BF3B-0069BF5D.
    mCoordNode.ListLinkAfter(&SimulationRef->mCoordEntities);

    if (!view.mTrackTarget) {
      // --- Ballistic integration ---
      // Gravity acceleration (per-tick).
      view.mVelocity.x += view.mBallisticAcceleration.x * kProjectileTickSeconds;
      view.mVelocity.y += view.mBallisticAcceleration.y * kProjectileTickSeconds;
      view.mVelocity.z += view.mBallisticAcceleration.z * kProjectileTickSeconds;

      // Forward thrust: mAcceleration along the transform's forward axis
      // (derived from the orientation quaternion; asm 0x0069C032-0069C115).
      const float qx = tran.orient_.x;
      const float qy = tran.orient_.y;
      const float qz = tran.orient_.z;
      const float qw = tran.orient_.w;
      const float accel = view.mAcceleration * kProjectileTickSeconds;
      const float forwardX = 1.0f - (((qy * qy) + (qz * qz)) * 2.0f);
      const float forwardY = ((qw * qz) - (qy * qx)) * 2.0f;
      const float forwardZ = ((qz * qx) + (qw * qy)) * 2.0f;
      view.mVelocity.x += forwardZ * accel;
      view.mVelocity.y += forwardY * accel;
      view.mVelocity.z += forwardX * accel;

      if (view.mVelocityAlign) {
        moho::QuatFromVecRot(&tran.orient_, &view.mVelocity, view.mTurnRateDegrees * kProjectileDegToRad);
      }
    } else {
      // --- Homing steering ---
      this->UpdateTracking(tran);

      const float qx = tran.orient_.x;
      const float qy = tran.orient_.y;
      const float qz = tran.orient_.z;
      const float qw = tran.orient_.w;
      const float accel = view.mAcceleration * kProjectileTickSeconds;
      view.mVelocity.x += (((qz * qx) + (qw * qy)) * 2.0f) * accel;
      view.mVelocity.y += (((qw * qz) - (qy * qx)) * 2.0f) * accel;
      view.mVelocity.z += (1.0f - (((qy * qy) + (qz * qz)) * 2.0f)) * accel;
    }

    if (view.mMaxSpeed != 0.0f) {
      ClampVectorToMaxLength(view.mVelocity, view.mMaxSpeed);
    }

    if (view.mStayUpright) {
      // Rebuild orientation to face the transform's forward vector while keeping
      // the world up-axis (asm 0x0069C1AA-0069C263).
      const float qx = tran.orient_.x;
      const float qy = tran.orient_.y;
      const float qz = tran.orient_.z;
      const float qw = tran.orient_.w;
      const Wm3::Vector3f forward{
        ((qz * qx) + (qw * qy)) * 2.0f,
        ((qw * qz) - (qy * qx)) * 2.0f,
        1.0f - (((qy * qy) + (qz * qz)) * 2.0f),
      };
      tran.orient_ = moho::COORDS_Orient(forward);
    }

    // Advance position by the average of pre/post velocity over a half tick.
    tran.pos_.x += ((view.mVelocity.x + startVelocity.x) * kProjectileHalfTickBlend);
    tran.pos_.y += ((view.mVelocity.y + startVelocity.y) * kProjectileHalfTickBlend);
    tran.pos_.z += ((view.mVelocity.z + startVelocity.z) * kProjectileHalfTickBlend);

    // Local angular velocity spin (asm 0x0069C2C5-0069C4A1).
    const float angX = view.mLocalAngularVelocity.x;
    const float angY = view.mLocalAngularVelocity.y;
    const float angZ = view.mLocalAngularVelocity.z;
    if (((angX * angX) + (angY * angY) + (angZ * angZ)) > 0.0f) {
      // For velocity-aligned / tracking / upright ordnance the spin axis is
      // reprojected onto a fixed local axis (forward for align/track, up for
      // upright) while keeping the original spin magnitude, then written back
      // into mLocalAngularVelocity (asm 0x0069C304-0069C376, VecSetLengthTo
      // scales `spinAxis` to the length of the current mLocalAngularVelocity).
      const bool reproject = view.mVelocityAlign || view.mTrackTarget || view.mStayUpright;
      if (reproject) {
        Wm3::Vector3f spinAxis;
        if (view.mVelocityAlign || view.mTrackTarget) {
          spinAxis = Wm3::Vector3f{0.0f, 0.0f, 1.0f}; // local forward
        } else {
          spinAxis = Wm3::Vector3f{0.0f, 1.0f, 0.0f}; // local up (stay-upright)
        }
        Wm3::Vector3f rescaled{};
        (void)moho::VecSetLengthTo(&rescaled, &view.mLocalAngularVelocity, &spinAxis);
        view.mLocalAngularVelocity = rescaled;
      }

      // Build the per-tick spin quaternion from the (scaled) angular velocity
      // treated as an axis-angle vector (asm 0x0069C384 func_VecToQuatB).
      const Wm3::Vector3f spinAxisAngle{
        view.mLocalAngularVelocity.x * kProjectileTickSeconds,
        view.mLocalAngularVelocity.y * kProjectileTickSeconds,
        view.mLocalAngularVelocity.z * kProjectileTickSeconds,
      };
      Wm3::Quaternionf spin;
      moho::QuatFromAxisAngleVector(&spin, spinAxisAngle);

      // Compose the new orientation as spin * oldOrientation using the engine's
      // exact lane pattern (decompile lines: tran.orient.x/y/z/w assignments,
      // asm 0x0069C3AC-0x0069C4A1). spin=(sx,sy,sz,sw), old=(ox,oy,oz,ow).
      const float ox = tran.orient_.x;
      const float oy = tran.orient_.y;
      const float oz = tran.orient_.z;
      const float ow = tran.orient_.w;
      const float sx = spin.x;
      const float sy = spin.y;
      const float sz = spin.z;
      const float sw = spin.w;
      const float newX = ((sx * ox) - (sy * oy) - (sz * oz)) - (sw * ow);
      const float newY = ((sy * ox) + (sw * oz) + (oy * sx)) - (sz * ow);
      const float newZ = ((sz * ox) + (sy * ow) + (oz * sx)) - (sw * oy);
      const float newW = ((sw * ox) + (sz * oy) + (ow * sx)) - (sy * oz);
      tran.orient_ = Wm3::Quatf{newW, newX, newY, newZ};
    }

    // Underwater clamp: keep the projectile just below the surface.
    if (view.mStayUnderwater && view.mBelowWater) {
      STIMap* const mapData = SimulationRef->mMapData;
      const float waterElevation = mapData->mWaterEnabled ? mapData->mWaterElevation : -10000.0f;
      const float clampY = waterElevation - 0.0099999998f;
      if (clampY <= tran.pos_.y) {
        tran.pos_.y = clampY;
      }
    }

    this->SetPendingTransform(tran, 1.0f);
    this->CheckCollision();

    // Lifetime expiry: fuze in mid-air after the projectile outlives its timer.
    if (SimulationRef->mCurTick >= view.mLifetimeEnd && view.mImpactInterpolation < 0.0f) {
      view.mImpactInterpolation = 1.0f;
      view.mImpactPosition = PendingPosition;
      view.mImpactType = static_cast<EImpactType>((view.mBelowWater ? 1 : 0) + 3);
    }

    if (dbg_Projectile) {
      CDebugCanvas* const canvas = SimulationRef->GetDebugCanvas();
      const Wm3::Quaternionf drawOrient{tran.orient_.x, tran.orient_.y, tran.orient_.z, tran.orient_.w};
      canvas->AddWireCoords(tran.pos_, drawOrient, 1.0f);
      if (view.mImpactInterpolation >= 0.0f) {
        canvas->AddLine(view.mImpactPosition, Position, 0xFF00FF00u);
        canvas->AddLine(PendingPosition, view.mImpactPosition, 0xFFFF0000u);
        const Wm3::Quaternionf kIdentity{1.0f, 0.0f, 0.0f, 0.0f};
        canvas->AddWireCoords(view.mImpactPosition, kIdentity, 1.0f);
      } else {
        canvas->AddLine(PendingPosition, Position, 0xFF00FF00u);
      }
    }

    // Terrain-bounce impact interpolation.
    if (view.mImpactInterpolation >= 0.0f) {
      float interp = view.mImpactInterpolation;
      if (view.mImpactType == IMPACT_Terrain) {
        const int groundTick = view.mGroundTick;
        const bool canBounce = groundTick < view.mBounceLimit;
        view.mGroundTick = groundTick + 1;
        if (canBounce) {
          // Reflect the velocity about the terrain normal and store the bounce
          // direction for next tick's mDirectAwayFromGround install.
          const Wm3::Vec3f normal =
            SimulationRef->mMapData->GetTerrainNormal(view.mImpactPosition.x, view.mImpactPosition.z);
          const float damp = view.mBounceVelocityDamping;
          const Wm3::Vector3f damped{
            view.mVelocity.x * damp,
            view.mVelocity.y * damp,
            view.mVelocity.z * damp,
          };
          const float twoDot =
            ((normal.x * damped.x) + (normal.y * damped.y) + (normal.z * damped.z)) * 2.0f;
          view.mGroundDirection.x = damped.x - (normal.x * twoDot);
          view.mGroundDirection.y = damped.y - (normal.y * twoDot);
          view.mGroundDirection.z = damped.z - (normal.z * twoDot);

          // Nudge the impact position along the reflected (negated) velocity.
          const Wm3::Vector3f awayDir{-view.mVelocity.x, -view.mVelocity.y, -view.mVelocity.z};
          Wm3::Vector3f awayNorm{};
          Wm3::Vector3f::NormalizeInto(awayDir, &awayNorm);
          view.mImpactPosition.x += awayNorm.x * kProjectileHalfTickBlend;
          view.mImpactPosition.y += awayNorm.y * kProjectileHalfTickBlend;
          view.mImpactPosition.z += awayNorm.z * kProjectileHalfTickBlend;

          interp = interp * kProjectileBounceInterpDamp;
          view.mImpactInterpolation = -1.0f;
          view.mDirectAwayFromGround = true;
        }
      }

      const float pendingScale = (interp <= 0.001f) ? 1000.0f : (1.0f / interp);
      Wm3::Quaternionf lerped;
      const Wm3::Quaternionf currentOrient{Orientation.x, Orientation.y, Orientation.z, Orientation.w};
      const Wm3::Quaternionf pendingOrient{PendingOrientation.x, PendingOrientation.y, PendingOrientation.z,
                                           PendingOrientation.w};
      moho::QuatLERP(&pendingOrient, &currentOrient, &lerped, view.mImpactInterpolation);
      tran.orient_ = Wm3::Quatf{lerped.x, lerped.y, lerped.z, lerped.w};
      tran.pos_ = view.mImpactPosition;
      this->SetPendingTransform(tran, pendingScale);
    }

    return 1;
  }

  /**
   * Address: 0x0069DEC0 (FUN_0069DEC0, Moho::Projectile::Impact)
   * Mangled: ?Impact@Projectile@Moho@@QAEXXZ
   *
   * IDA signature:
   * void __thiscall Moho::Projectile::Impact(Moho::Projectile *this);
   *
   * What it does:
   * Impact/detonation handler. Fires the `OnImpact` script with the impact-type
   * label, updates the launcher army's shots-hit / shots-missed realtime stats,
   * dispatches the impact-event broadcaster with a hit/self/other category code,
   * clears the collided-entity weak link, resets the impact position, and marks
   * the impact state invalid.
   */
  void Projectile::Impact()
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);

    // Resolve the launcher entity (asm 0x0069DEE0-0069DEF8).
    Entity* const launcherEntity = view.mLauncherWeak.GetObjectPtr();

    // The collided-entity weak link (asm `v4 = &this->v182`).
    Entity* const collidedEntity = view.mCollidedEntityWeak.GetObjectPtr();

    // Fire the `OnImpact(self, impactTypeString)` script. The binary guards the
    // Lua state with a temporary LuaObject when no collided entity is present;
    // LuaPCall performs the equivalent marshalling.
    const char* impactTypeString = ENT_GetImpactTypeString(view.mImpactType);
    LuaPlus::LuaObject impactResult;
    const char* impactArgs[] = {impactTypeString};
    this->LuaPCall("OnImpact", impactArgs, &impactResult);

    // Target/army accounting: only when the projectile had a real target entity.
    Entity* const targetEntity = view.mTargetPosData.GetEntity();
    if (targetEntity != nullptr) {
      // Launcher shots-hit / shots-missed realtime-stat accounting.
      if (launcherEntity != nullptr && launcherEntity->RealtimeStatsEnabled) {
        CArmyImpl* const launcherArmy = launcherEntity->ArmyRef;
        if (launcherArmy != nullptr) {
          CArmyStats* const stats = launcherArmy->GetArmyStats();
          msvc8::string statPath = msvc8::string("RealTimeStats_") + launcherEntity->GetUniqueName();
          const bool didHit = view.mTargetPosData.ImpactDidHitEntity(collidedEntity, view.mImpactType);
          statPath = statPath + (didHit ? "_Shots_Hit" : "_Shots_Missed");
          const std::int32_t delta = 1;
          (void)stats->UpdateUnitStat(statPath.c_str(), &delta);
        }
      }

      // Impact-event broadcaster dispatch by category (asm 0x0069E077-0069E112).
      const bool didHit = view.mTargetPosData.ImpactDidHitEntity(collidedEntity, view.mImpactType);
      int eventCode;
      if (didHit) {
        eventCode = 0;
      } else if (view.mImpactType == IMPACT_Projectile || view.mImpactType == IMPACT_ProjectileUnderwater ||
                 (collidedEntity != nullptr &&
                  (static_cast<std::uint32_t>(collidedEntity->id_) & 0xF0000000u) == 0x40000000u)) {
        eventCode = 2;
      } else {
        eventCode = 1;
      }
      // Impact-event broadcaster fire (asm 0x0069E0E6-0x0069E112): notify the
      // single chained listener via its slot-0 OnEvent with the selected code.
      // The intrusive link->owner downcast lives in GetListener(); the empty
      // check there mirrors the `[this+0x270] == 0` skip in the binary.
      if (auto* const listener = view.mImpactEventBroadcaster.GetListener()) {
        listener->OnEvent(static_cast<EProjectileImpactEvent>(eventCode));
      }
    }

    // Reset impact state (asm 0x0069E114-0069E177).
    view.mImpactPosition = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    // Unlink the collided-entity weak link from its owner chain.
    view.mCollidedEntityWeak.UnlinkFromOwnerChain();
    view.mImpactType = IMPACT_Invalid;
    view.mImpactInterpolation = kProjectileUnsetValue;
  }

  /**
   * Address: 0x0069C8F0 (FUN_0069C8F0, Moho::Projectile::UpdateTracking)
   * Mangled: ?UpdateTracking@Projectile@Moho@@AAEXAAVVTransform@2@@Z
   *
   * IDA signature:
   * void __thiscall Moho::Projectile::UpdateTracking(Moho::Projectile *this, Moho::VTransform *trn);
   *
   * What it does:
   * Homing/tracking steering update. Resolves the aim point (live gun position,
   * optionally lead-predicted; fires `OnLostTarget` and disables tracking when the
   * target is gone), applies underwater clamps and zig-zag jitter from the
   * projectile attributes, and steers `trn`'s orientation toward the aim direction
   * by at most the projectile turn rate.
   */
  void Projectile::UpdateTracking(VTransform& trn)
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);

    if (view.mTargetPosData.HasTarget()) {
      // Live target: cache the current gun-aim world position (asm 0x0069C90A-0x0069C931).
      view.mCachedAimPoint = view.mTargetPosData.GetTargetPosGun(false);
    } else {
      // Target lost: fire OnLostTarget once, then continue steering toward the last
      // cached aim only if the "keep last aim" latch is set (asm 0x0069C933-0x0069C956);
      // otherwise abort this tick.
      if (view.mTrackTarget) {
        this->CallbackStr("OnLostTarget");
        view.mTrackTarget = false;
      }
      if (!view.mKeepLastAimLatch) {
        return;
      }
    }

    STIMap* const mapData = SimulationRef->mMapData;
    Wm3::Vector3f aim = view.mCachedAimPoint;

    // Lead-target prediction (asm 0x0069C9A0-0x0069CB39). Only when lead-target is
    // enabled and the projectile has positive top speed. One Newton refinement of
    // the intercept lead-time: both lead terms project from the ORIGINAL aim; only
    // the time-of-flight estimate is refined (t1 -> t2).
    if (view.mLeadTarget && view.mMaxSpeed > 0.0f && view.mTargetPosData.HasTarget()) {
      Entity* const targetEntity = view.mTargetPosData.GetEntity();
      if (targetEntity != nullptr) {
        const float perTickSpeed = view.mMaxSpeed * kProjectileTickSeconds; // mMaxSpeed * 0.1
        if (perTickSpeed > 0.0f) {
          const Wm3::Vec3f targetVelocity = targetEntity->GetVelocity(); // vtable slot 15 (+0x3C)
          const Wm3::Vector3f aim0 = aim;
          const Wm3::Vector3f& projectilePos = trn.pos_;

          const auto leadAt = [&](const Wm3::Vector3f& fromPoint) {
            const float dist = std::sqrt(
              ((projectilePos.x - fromPoint.x) * (projectilePos.x - fromPoint.x)) +
              ((projectilePos.y - fromPoint.y) * (projectilePos.y - fromPoint.y)) +
              ((projectilePos.z - fromPoint.z) * (projectilePos.z - fromPoint.z)));
            const float t = dist / perTickSpeed;
            return Wm3::Vector3f{
              aim0.x + targetVelocity.x * t,
              aim0.y + targetVelocity.y * t,
              aim0.z + targetVelocity.z * t,
            };
          };

          const Wm3::Vector3f predicted = leadAt(aim0); // t1 = |P - aim0| / speed
          aim = leadAt(predicted);                      // t2 = |P - predicted| / speed
        }
      }
    }

    // Underwater aim clamp: keep the aim point just below the surface.
    if (view.mStayUnderwater) {
      const float waterElevation = mapData->mWaterEnabled ? mapData->mWaterElevation : -10000.0f;
      const float clampY = waterElevation - 0.25f;
      if (clampY <= aim.y) {
        aim.y = clampY;
      }
    }

    // Steering direction from current position (trn.pos_) to the aim point.
    Wm3::Vector3f steer{
      aim.x - trn.pos_.x,
      aim.y - trn.pos_.y,
      aim.z - trn.pos_.z,
    };

    // Zig-zag jitter (asm 0x0069CC56-0x0069CF65): only when attributes enable it.
    // A negative attribute value means "inherit from the blueprint".
    float maxZigZag = view.mAttributes.mMaxZigZag;
    if (maxZigZag < 0.0f) {
      maxZigZag = view.mAttributes.mBlueprint->Physics.MaxZigZag;
    }
    if (maxZigZag > 0.0f) {
      float zigZagFrequency = view.mAttributes.mZigZagFrequency;
      if (zigZagFrequency < 0.0f) {
        zigZagFrequency = view.mAttributes.mBlueprint->Physics.ZigZagFrequency;
      }
      if (zigZagFrequency > 0.0f) {
        // Re-roll the random offset every FloorSecondsToTicks(frequency) ticks
        // (asm 0x0069CCAA-0x0069CD71).
        const std::uint32_t curTick = SimulationRef->mCurTick;
        if (static_cast<std::uint32_t>(view.mZigZagNextTick) <= curTick) {
          CRandomStream* const rng = SimulationRef->mRngState;
          view.mZigZagRandomOffset.x = rng->FRand(-maxZigZag, maxZigZag);
          view.mZigZagRandomOffset.y = rng->FRand(-maxZigZag, maxZigZag);
          view.mZigZagRandomOffset.z = rng->FRand(-maxZigZag, maxZigZag);
          view.mZigZagNextTick =
            static_cast<std::int32_t>(curTick) + FloorSecondsToTicks(zigZagFrequency);
        }

        // Blend factor from the distance still to travel (asm 0x0069CD77-0x0069CDFE).
        const float distToAim = std::sqrt((steer.x * steer.x) + (steer.y * steer.y) + (steer.z * steer.z));
        float blend = distToAim / maxZigZag;
        if (blend >= 1.0f) {
          blend = 1.0f;
        }

        // Jittered aim point = pos + normalize(steer)*mMaxSpeed + rndOffset*blend,
        // with the vertical clamped above terrain (+0.5) and, unless underwater,
        // above the water surface (+0.5) (asm 0x0069CDFE-0x0069CF65).
        Wm3::Vector3f steerDir{};
        Wm3::Vector3f::NormalizeInto(steer, &steerDir);

        const float jitteredX = (trn.pos_.x + steerDir.x * view.mMaxSpeed) + view.mZigZagRandomOffset.x * blend;
        const float jitteredZ = (trn.pos_.z + steerDir.z * view.mMaxSpeed) + view.mZigZagRandomOffset.z * blend;
        const float baseY = trn.pos_.y + steerDir.y * view.mMaxSpeed;
        float jitteredY = baseY + view.mZigZagRandomOffset.y * blend;

        CHeightField* const heightField = mapData->mHeightField.get();
        const float groundLimit = heightField->GetElevation(jitteredX, jitteredZ) + 0.5f;
        const float groundClampedBase = (baseY <= groundLimit) ? groundLimit : baseY;
        if (jitteredY < groundClampedBase) {
          jitteredY = groundClampedBase;
        }
        if (!view.mStayUnderwater) {
          const float waterLine = mapData->mWaterEnabled ? mapData->mWaterElevation : -10000.0f;
          const float waterLimit = waterLine + 0.5f;
          const float waterClampedBase = (baseY > waterLimit) ? waterLimit : baseY;
          if (jitteredY < waterClampedBase) {
            jitteredY = waterClampedBase;
          }
        }

        steer.x = jitteredX - trn.pos_.x;
        steer.y = jitteredY - trn.pos_.y;
        steer.z = jitteredZ - trn.pos_.z;
      }
    }

    // Turn the transform orientation toward the steering direction, at most
    // mTurnRateDegrees per tick.
    moho::QuatFromVecRot(&trn.orient_, &steer, view.mTurnRateDegrees * 0.0017453292f);

    // Underwater orientation flatten (asm 0x0069CF8A-0x0069D10F): when ascending
    // toward the surface, clip the forward vector so it only rises up to the water
    // plane, then rebuild the orientation from the clipped forward. Only runs while
    // underwater; the base QuatFromVecRot steering above is applied unconditionally.
    if (view.mStayUnderwater && view.mBelowWater) {
      // Forward vector = R(orient) * (0,0,1) (asm 0x0069CFA4-0x0069D017).
      const float qw = trn.orient_.w;
      const float qx = trn.orient_.x;
      const float qy = trn.orient_.y;
      const float qz = trn.orient_.z;
      const float forwardX = ((qw * qy) + (qz * qx)) * 2.0f;
      const float forwardY = ((qz * qy) - (qw * qx)) * 2.0f;
      const float forwardZ = 1.0f - (((qy * qy) + (qx * qx)) * 2.0f);

      // Only flatten while pointing upward (asm 0x0069CFFB-0x0069D01D: forward.y > 0).
      if (forwardY > 0.0f) {
        const float waterLine = mapData->mWaterEnabled ? mapData->mWaterElevation : -10000.0f;
        const float t = (waterLine - trn.pos_.y) / forwardY;
        // Only when the surface is reached within one forward unit (asm 0x0069D047: t < 1.0).
        if (t < 1.0f) {
          Wm3::Vector3f clippedForward{forwardX, forwardY * t, forwardZ};
          const float lenSq =
            (clippedForward.x * clippedForward.x) + (clippedForward.y * clippedForward.y) +
            (clippedForward.z * clippedForward.z);
          // Degenerate clipped forward is normalized before re-orienting
          // (asm 0x0069D077-0x0069D0F3: threshold flt_DFFBE8 == 1e-6).
          if (lenSq < 1.0e-6f) {
            Wm3::Vector3f::NormalizeInto(clippedForward, &clippedForward);
          }
          trn.orient_ = moho::COORDS_Orient(clippedForward);
        }
      }
    }

    // Velocity-align: reproject the velocity onto the new forward axis
    // (asm 0x0069D190-0069D1BA: mVelocity = ProjectVectorOntoAxis(forward, mVelocity)).
    if (view.mVelocityAlign) {
      const float qx = trn.orient_.x;
      const float qy = trn.orient_.y;
      const float qz = trn.orient_.z;
      const float qw = trn.orient_.w;
      const Wm3::Vector3f forward{
        ((qz * qx) + (qw * qy)) * 2.0f,
        ((qz * qw) - (qx * qy)) * 2.0f,
        1.0f - (((qz * qz) + (qy * qy)) * 2.0f),
      };
      view.mVelocity = ProjectVectorOntoAxisLocal(forward, view.mVelocity);
    }
  }

  /**
   * Address: 0x0069D1D0 (FUN_0069D1D0, Moho::Projectile::CheckCollision)
   * Mangled: ?CheckCollision@Projectile@Moho@@AAEXXZ
   *
   * IDA signature:
   * void __thiscall Moho::Projectile::CheckCollision(Moho::Projectile *this);
   *
   * What it does:
   * Per-tick collision pass over the segment swept from the current world position
   * (Position) to the pending position (PendingPosition). Handles water-surface
   * crossing / layer change, tests the water plane for surface-colliding ordnance,
   * samples the terrain surface, then (mDoCollision) the explicit homing target
   * and the entity sweep, and finally the terrain height field. The earliest hit
   * stamps mImpactInterpolation, mImpactPosition, the collided-entity weak link,
   * and mImpactType.
   */
  void Projectile::CheckCollision()
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);

    // Swept segment this tick: current world position -> pending position.
    const Wm3::Vector3f& curPos = Position;
    const Wm3::Vector3f& nextPos = PendingPosition;

    // Two-endpoint segment (Origin=midpoint, Direction=normalized, Extent=half
    // length) via the recovered FA ctor (FUN_004FE130). asm 0x0069D247.
    const Wm3::Segment3f segment = Wm3::MakeSegment3fFromEndpoints(curPos, nextPos);
    // Distance travelled this tick = segment half-extent * 2.0 (ds:flt_DFEB0C == 2.0).
    const float distMoved = segment.Extent * 2.0f;

    STIMap* const mapData = SimulationRef->mMapData;
    const float waterElevation = mapData->mWaterEnabled ? mapData->mWaterElevation : -10000.0f;
    bool wentUnderwater = false;

    // --- Branch A: water-surface crossing / layer change ---
    if (view.mCollideSurface) {
      const float nextY = nextPos.y;
      if (view.mBelowWater) {
        // Currently underwater: rising above the surface exits the water.
        if (nextY > waterElevation) {
          this->SetCurrentLayer(LAYER_Air);
          this->CallbackStr("OnExitWater");
          view.mBelowWater = false;
        }
      } else {
        // Currently in air: dropping below the surface enters the water.
        if (waterElevation > nextY) {
          this->SetCurrentLayer(LAYER_Water);
          this->CallbackStr("OnEnterWater");
          if (!view.mBelowWater) {
            wentUnderwater = true;
          }
          view.mBelowWater = true;
        }
      }
    }

    // --- Branch A2: water-plane detonation for surface-destroy ordnance ---
    if (view.mDestroyOnWater && wentUnderwater) {
      Wm3::Vector3f planeHit{};
      if (WaterPlaneIntersection(planeHit, curPos, nextPos, waterElevation) &&
          IsValidVector3f(planeHit)) {
        // Fraction of the segment consumed before the water hit.
        const float hitDist = std::sqrt(
          ((planeHit.x - curPos.x) * (planeHit.x - curPos.x)) +
          ((planeHit.y - curPos.y) * (planeHit.y - curPos.y)) +
          ((planeHit.z - curPos.z) * (planeHit.z - curPos.z)));
        view.mImpactPosition = planeHit;
        view.mImpactInterpolation = (distMoved != 0.0f) ? (hitDist / distMoved) : 0.0f;
        view.mImpactType = IMPACT_Water;
      } else {
        view.mImpactPosition = curPos;
        view.mImpactInterpolation = 0.0f;
      }
      // asm 0x0069D336-0x0069D4D7: the binary parametrizes the swept segment and
      // solves the y == waterElevation crossing via the file-static
      // CColHitResult::PlaneIntersection (FUN_00577540). Because the crossing point
      // lies on the segment, the along-segment hit distance equals the euclidean
      // distance from curPos to the crossing, so the fraction is that distance
      // divided by distMoved (asm 0x0069D48A-0x0069D496). mImpactType stamped
      // IMPACT_Water (2) per asm 0x0069D4CD.
    }

    // --- Branch B: terrain-surface intersection ---
    {
      const GeomLine3 terrainLine{
        Wm3::Vec3f(curPos.x, curPos.y, curPos.z),
        Wm3::Vec3f(segment.Direction.x, segment.Direction.y, segment.Direction.z),
        0.0f,
        distMoved,
      };
      CGeomHitResult terrainHit{};
      CHeightField* const heightField = mapData->mHeightField.get();
      const Wm3::Vec3f hitPoint = heightField->Intersection(terrainLine, &terrainHit);
      if (IsValidVector3f(Wm3::Vector3f{hitPoint.x, hitPoint.y, hitPoint.z})) {
        // Earliest-hit predicate (asm 0x0069D5C4-0x0069D5E3): record when there is
        // no hit yet (mImpactInterpolation < 0) OR when this terrain hit is closer
        // than the stored one — i.e. mImpactInterpolation*distMoved > terrainHit.distance.
        if (view.mImpactInterpolation < 0.0f ||
            (view.mImpactInterpolation * distMoved) > terrainHit.distance) {
          const float hitFraction = (distMoved != 0.0f) ? (terrainHit.distance / distMoved) : 0.0f;
          view.mImpactInterpolation = hitFraction;
          view.mImpactPosition = Wm3::Vector3f{hitPoint.x, hitPoint.y, hitPoint.z};
          view.mImpactType = IMPACT_Terrain;
        }
      }
    }

    // --- Branch C: explicit homing-target collision ---
    // Only for a target entity that is itself a projectile (vtable slot 6 /
    // +0x18 == IsProjectile, asm 0x0069D651) and carries no collision extents
    // (CollisionExtents == null, [esi+0x178] guard at asm 0x0069D660).
    if (view.mDoCollision) {
      Entity* const target = view.mTargetPosData.GetEntity();
      if (target != nullptr && target->IsProjectile() != nullptr &&
          target->CollisionExtents == nullptr) {
        // Closest point on the swept segment to the target's world position, and
        // its squared distance (asm 0x0069D66C: DistVector3Segment3(target->Position,
        // segment); 0x0069D692: GetSquared; 0x0069D706: GetEndPoint).
        Wm3::Vector3f closestOnSegment{};
        const float distSq = DistPointToSegmentSquared(target->Position, segment, &closestOnSegment);

        // Hit radius squared = |target velocity|^2 + 0.5 (asm 0x0069D69B: target
        // GetVelocity() via vtable slot 15 (+0x3C); 0x0069D6D4: + flt_E4F724 == 0.5).
        const Wm3::Vec3f targetVelocity = target->GetVelocity();
        const float hitRadiusSq =
          (targetVelocity.x * targetVelocity.x) + (targetVelocity.y * targetVelocity.y) +
          (targetVelocity.z * targetVelocity.z) + 0.5f;

        // asm 0x0069D6DC: proceed only when distSq <= hitRadiusSq (jb skips otherwise).
        if (distSq <= hitRadiusSq && RunProjectileOnCollisionCheckScript(target, this)) {
          // Fraction of the segment consumed at the closest point
          // (asm 0x0069D719-0x0069D7F1): |closest - curPos| / |nextPos - curPos|,
          // clamped to [0, 1].
          const float toClosestSq =
            ((closestOnSegment.x - curPos.x) * (closestOnSegment.x - curPos.x)) +
            ((closestOnSegment.y - curPos.y) * (closestOnSegment.y - curPos.y)) +
            ((closestOnSegment.z - curPos.z) * (closestOnSegment.z - curPos.z));
          const float spanSq =
            ((nextPos.x - curPos.x) * (nextPos.x - curPos.x)) +
            ((nextPos.y - curPos.y) * (nextPos.y - curPos.y)) +
            ((nextPos.z - curPos.z) * (nextPos.z - curPos.z));
          float fraction = std::sqrt(toClosestSq / spanSq);
          if (fraction >= 1.0f) {
            fraction = 1.0f;
          }
          if (fraction < 0.0f) {
            fraction = 0.0f;
          }

          view.mImpactPosition = closestOnSegment;
          view.mCollidedEntityWeak.Set(target);
          view.mImpactInterpolation = fraction;
          view.mImpactType = IMPACT_Projectile;
        }
      }
    }

    // --- Branch D: swept-entity collision ---
    // The entity gather goes through the sim's occupation grid (Sim::mOGrid,
    // asm [sim+0x908]). Query flags 0x0D00 = Unit | Entity | Projectile.
    if (view.mDoCollision) {
      COGrid* const oGrid = SimulationRef->mOGrid;
      constexpr auto kProjectileCollisionMask =
        static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Entity | ENTITYTYPE_Projectile);
      Entity* const launcherEntity = view.mLauncherWeak.GetObjectPtr();

      if (distMoved < 0.01f /* ds:dword_DFEB80 short-move threshold */) {
        // Short move: sphere gather at the current position, radius 1.0
        // (asm 0x0069D844-0x0069D9F2; ds:a7 == 1.0). First confirmed hit wins and
        // the pass ends immediately (the binary returns after recording).
        Wm3::Sphere3f querySphere{};
        querySphere.Center = Wm3::Vec3f(curPos.x, curPos.y, curPos.z);
        querySphere.Radius = 1.0f;

        CollisionResultFastVectorN10 results{};
        oGrid->ForAllEntitiesIterator(results, kProjectileCollisionMask, querySphere);

        for (const CollisionResult& result : results) {
          Entity* const candidate = result.sourceEntity;

          // Skip the launcher unit itself (asm 0x0069D909-0x0069D930): the binary
          // compares candidate-as-Unit against the launcher entity, treating a
          // non-Unit candidate as null — so a null launcher skips every non-Unit.
          Entity* const candidateIfUnit = (candidate->IsUnit() != nullptr) ? candidate : nullptr;
          if (candidateIfUnit == launcherEntity) {
            continue;
          }
          // Skip self (asm 0x0069D932).
          if (candidate == this) {
            continue;
          }
          // Skip once an earlier hit has already been recorded this pass
          // (asm 0x0069D936-0x0069D940: 0.0 <= mImpactInterpolation).
          if (view.mImpactInterpolation >= 0.0f) {
            continue;
          }
          if (RunProjectileOnCollisionCheckScript(candidate, this)) {
            // asm 0x0069D984-0x0069D9D0: record and return.
            view.mImpactInterpolation = 0.0f;
            view.mImpactPosition = curPos;
            view.mCollidedEntityWeak.Set(candidate);
            view.mImpactType = ENT_GetImpactType(SimulationRef, candidate, curPos);
            break;
          }
        }
      } else {
        // Long move: line sweep over the segment extended 10% at each end
        // (asm 0x0069DA4F-0x0069DAE7; dbl_E4F710+4 == 0.1). Records the earliest
        // confirmed hit across all results (no early-out).
        const Wm3::Vector3f delta{nextPos.x - curPos.x, nextPos.y - curPos.y, nextPos.z - curPos.z};
        const Wm3::Vec3f lineStart(
          curPos.x - delta.x * kProjectileTickSeconds,
          curPos.y - delta.y * kProjectileTickSeconds,
          curPos.z - delta.z * kProjectileTickSeconds);
        const Wm3::Vec3f lineEnd(
          nextPos.x + delta.x * kProjectileTickSeconds,
          nextPos.y + delta.y * kProjectileTickSeconds,
          nextPos.z + delta.z * kProjectileTickSeconds);

        Entity* const homingTarget = view.mTargetPosData.GetEntity();
        Entity* const collidedEntity = view.mCollidedEntityWeak.GetObjectPtr();
        CArmyImpl* const projectileArmy = ArmyRef;

        EntityLineCollisionVector results{};
        oGrid->GetEntityCollisionsInLine(results, lineStart, lineEnd);

        for (const EntityLineCollision& result : results) {
          Entity* const candidate = result.entity;

          // Filter B decides whether the friendly-air weapon gate (Filter E) is
          // applied; the homing target is always allowed to be hit.
          const bool isHomingTarget = (candidate == homingTarget);
          if (!isHomingTarget) {
            // Filter A (asm 0x0069DB3E-0x0069DBA5): once we have collided with a
            // Unit, skip that unit's own shield bubble.
            if (collidedEntity != nullptr && collidedEntity->IsUnit() != nullptr &&
                candidate->IsShield() != nullptr &&
                candidate->mAttachInfo.GetAttachTargetEntity() == collidedEntity) {
              continue;
            }
            // Filter C (asm 0x0069DBB7-0x0069DBED): skip the launcher unit. The
            // binary only runs this test when the launcher weak resolves to a live
            // entity (asm 0x0069DBBD-0x0069DBC4 short-circuits past it otherwise).
            if (launcherEntity != nullptr && candidate->IsUnit() != nullptr &&
                candidate == launcherEntity) {
              continue;
            }
            // Filter D (asm 0x0069DBF3): skip self.
            if (candidate == this) {
              continue;
            }
            // Filter E (asm 0x0069DBFD-0x0069DC2D): a child projectile only
            // collides with ENEMY air-layer candidates (skips friendly air units).
            if (view.mIsChildProjectile && projectileArmy != nullptr &&
                candidate->mCurrentLayer == LAYER_Air) {
              if (!projectileArmy->IsEnemy(static_cast<std::uint32_t>(candidate->GetArmyIndex()))) {
                continue;
              }
            }
          } else {
            // Filter D still applies to the homing target path.
            if (candidate == this) {
              continue;
            }
          }

          // Earliest-hit guard (asm 0x0069DC33-0x0069DC4D): proceed when there is
          // no hit yet, or this candidate is closer along the swept line.
          if (view.mImpactInterpolation >= 0.0f &&
              (view.mImpactInterpolation * distMoved) <= result.distanceFromLineStart) {
            continue;
          }

          if (RunProjectileOnCollisionCheckScript(candidate, this)) {
            view.mImpactInterpolation =
              (distMoved != 0.0f) ? (result.distanceFromLineStart / distMoved) : 0.0f;
            view.mImpactPosition =
              Wm3::Vector3f{result.position.x, result.position.y, result.position.z};
            view.mCollidedEntityWeak.Set(candidate);
            view.mImpactType = ENT_GetImpactType(SimulationRef, candidate, curPos);
          }
        }
      }
    }

    // --- Branch E: terrain height-field elevation / detonate-height ---
    // asm 0x0069DCDE-0x0069DE53. Detonates the projectile when the swept segment
    // crosses a proximity band above/below the effective surface (the higher of
    // terrain elevation and water level). Above-band fires while ascending, the
    // below-band while descending. The detonate distances come from the projectile
    // attributes, falling back to the blueprint when the attribute is the -1
    // sentinel. blueprint+0x1E4 == Physics.DetonateAboveHeight (Physics @ +0x1DC,
    // +0x08); blueprint+0x1E8 == Physics.DetonateBelowHeight (+0x0C).
    {
      CHeightField* const heightField = mapData->mHeightField.get();
      const float groundElevation = heightField->GetElevation(nextPos.x, nextPos.z);

      // Effective surface = max(terrain, water) (asm 0x0069DD0E-0x0069DD20).
      const float surfaceY = (waterElevation > groundElevation) ? waterElevation : groundElevation;
      const float heightAboveSurface = nextPos.y - surfaceY;

      // Resolve detonate distances with the -1 sentinel -> blueprint fallback
      // (asm 0x0069DD2D-0x0069DD66).
      float detonateAbove = view.mAttributes.mDetonateAboveHeight;
      if (detonateAbove < 0.0f) {
        detonateAbove = view.mAttributes.mBlueprint->Physics.DetonateAboveHeight;
      }
      float detonateBelow = view.mAttributes.mDetonateBelowHeight;
      if (detonateBelow < 0.0f) {
        detonateBelow = view.mAttributes.mBlueprint->Physics.DetonateBelowHeight;
      }

      const float dy = nextPos.y - curPos.y;
      bool detonated = false;
      float fraction = 0.0f;

      // Below band (asm 0x0069DD66-0x0069DDA3): active while descending and within
      // detonateBelow of the surface. Crossing fraction solved against ground.
      if (detonateBelow > 0.0f && detonateBelow > heightAboveSurface && dy < 0.0f) {
        fraction = (detonateBelow + groundElevation - curPos.y) / dy;
        detonated = true;
      } else if (detonateAbove > 0.0f && heightAboveSurface > detonateAbove && dy > 0.0f) {
        // Above band (asm 0x0069DDAB-0x0069DDEC): active while ascending once the
        // projectile has risen past detonateAbove of the surface.
        fraction = (detonateAbove + groundElevation - curPos.y) / dy;
        detonated = true;
      }

      if (detonated) {
        // Clamp the crossing fraction into [0.1, 1.0]: the band-crossing solve
        // saturates at 1.0 (asm 0x0069DDE9/0x0069DD9E vs ds:a7 == 1.0) and is then
        // floored at one tick (asm 0x0069DDF1: max(fraction, dbl_E4F710+4 == 0.1)).
        if (fraction >= 1.0f) {
          fraction = 1.0f;
        }
        if (fraction < kProjectileTickSeconds) {
          fraction = kProjectileTickSeconds;
        }
        view.mImpactInterpolation = fraction;
        view.mImpactPosition = Wm3::Vector3f{
          curPos.x + (nextPos.x - curPos.x) * fraction,
          curPos.y + dy * fraction,
          curPos.z + (nextPos.z - curPos.z) * fraction,
        };
        view.mImpactType = IMPACT_Air;
      }
    }
  }

  /**
   * Address: 0x0069E520 (FUN_0069E520, Moho::Projectile::MemberConstruct)
   *
   * What it does:
   * Reads owner `Sim` pointer from archive payload, allocates one projectile
   * object through the archive ctor lane, and publishes it as unowned
   * construct output.
   */
  void Projectile::MemberConstruct(gpg::ReadArchive* const archive, gpg::SerConstructResult* const result)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(result != nullptr);
    if (!archive || !result) {
      return;
    }

    Sim* ownerSim = nullptr;
    gpg::RRef ownerRef{};
    (void)archive->ReadPointer_Sim(&ownerSim, &ownerRef);

    Projectile* const object = new (std::nothrow) Projectile(ownerSim);
    result->SetUnowned(MakeProjectileRef(object), 0u);
  }

  /**
   * Address: 0x0069EDF0 (FUN_0069EDF0, Moho::InstanceCounter<Moho::Projectile>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for Projectile
   * instance counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::Projectile>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::Projectile).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x0069F8E0 (FUN_0069F8E0, member-deserialize thunk lane)
   * Address: 0x00680790 (FUN_00680790)
   * Address: 0x006A0370 (FUN_006A0370, Moho::Projectile::MemberDeserialize)
   *
   * What it does:
   * Restores projectile runtime state from archive payload, including base
   * entity lanes, physics vectors, impact state, weak links, and attributes.
   */
  void Projectile::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    const gpg::RRef ownerRef{};

    archive->Read(CachedEntityType(), this, ownerRef);
    archive->Read(CachedImpactBroadcasterType(), &view.mImpactEventBroadcaster, ownerRef);
    archive->Read(CachedWeakEntityType(), &view.mLauncherWeak, ownerRef);
    archive->Read(CachedVector3fType(), &view.mVelocity, ownerRef);
    archive->Read(CachedVector3fType(), &view.mLocalAngularVelocity, ownerRef);
    archive->Read(CachedVector3fType(), &view.mScaleVelocity, ownerRef);

    archive->ReadFloat(&view.mImpactInterpolation);
    archive->ReadBool(&view.mCollideSurface);
    archive->ReadBool(&view.mDoCollision);
    archive->ReadBool(&view.mTrackTarget);
    archive->ReadBool(&view.mVelocityAlign);
    archive->ReadBool(&view.mStayUpright);
    archive->ReadBool(&view.mLeadTarget);
    archive->ReadBool(&view.mStayUnderwater);
    archive->ReadBool(&view.mDestroyOnWater);

    archive->ReadFloat(&view.mTurnRateDegrees);
    archive->ReadFloat(&view.mMaxSpeed);
    archive->ReadFloat(&view.mAcceleration);
    archive->Read(CachedVector3fType(), &view.mBallisticAcceleration, ownerRef);
    archive->Read(CachedVector3fType(), &view.mCachedAimPoint, ownerRef);
    archive->ReadBool(&view.mKeepLastAimLatch);

    archive->ReadFloat(&view.mDamage);
    archive->ReadFloat(&view.mDamageRadius);
    archive->ReadString(&view.mDamageTypeName);

    archive->Read(CachedAiTargetType(), &view.mTargetPosData, ownerRef);
    archive->Read(CachedVector3fType(), &view.mImpactPosition, ownerRef);
    archive->Read(CachedWeakEntityType(), &view.mCollidedEntityWeak, ownerRef);

    archive->ReadUInt(&view.mLifetimeEnd);
    archive->ReadBool(&view.mBelowWater);
    archive->ReadInt(&view.mBounceLimit);
    archive->ReadInt(&view.mGroundTick);
    archive->ReadBool(&view.mDirectAwayFromGround);
    archive->Read(CachedVector3fType(), &view.mGroundDirection, ownerRef);
    archive->ReadFloat(&view.mBounceVelocityDamping);
    archive->ReadInt(&view.mZigZagNextTick);
    archive->Read(CachedVector3fType(), &view.mZigZagRandomOffset, ownerRef);
    archive->Read(CachedProjectileAttributesType(), &view.mAttributes, ownerRef);
    archive->ReadBool(&view.mIsChildProjectile);
  }

  /**
   * Address: 0x006A0820 (FUN_006A0820, Moho::Projectile::MemberSerialize)
   *
   * What it does:
   * Serializes projectile runtime state to archive payload, including base
   * entity lanes, physics vectors, impact state, weak links, and attributes.
   */
  void Projectile::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const auto& view = *reinterpret_cast<const ProjectileDeserializeRuntimeView*>(this);
    const gpg::RRef ownerRef{};

    archive->Write(CachedEntityType(), this, ownerRef);
    archive->Write(CachedImpactBroadcasterType(), &view.mImpactEventBroadcaster, ownerRef);
    archive->Write(CachedWeakEntityType(), &view.mLauncherWeak, ownerRef);
    archive->Write(CachedVector3fType(), &view.mVelocity, ownerRef);
    archive->Write(CachedVector3fType(), &view.mLocalAngularVelocity, ownerRef);
    archive->Write(CachedVector3fType(), &view.mScaleVelocity, ownerRef);

    archive->WriteFloat(view.mImpactInterpolation);
    archive->WriteBool(view.mCollideSurface);
    archive->WriteBool(view.mDoCollision);
    archive->WriteBool(view.mTrackTarget);
    archive->WriteBool(view.mVelocityAlign);
    archive->WriteBool(view.mStayUpright);
    archive->WriteBool(view.mLeadTarget);
    archive->WriteBool(view.mStayUnderwater);
    archive->WriteBool(view.mDestroyOnWater);

    archive->WriteFloat(view.mTurnRateDegrees);
    archive->WriteFloat(view.mMaxSpeed);
    archive->WriteFloat(view.mAcceleration);
    archive->Write(CachedVector3fType(), &view.mBallisticAcceleration, ownerRef);
    archive->Write(CachedVector3fType(), &view.mCachedAimPoint, ownerRef);
    archive->WriteBool(view.mKeepLastAimLatch);

    archive->WriteFloat(view.mDamage);
    archive->WriteFloat(view.mDamageRadius);
    archive->WriteString(const_cast<msvc8::string*>(&view.mDamageTypeName));

    archive->Write(CachedAiTargetType(), &view.mTargetPosData, ownerRef);
    archive->Write(CachedVector3fType(), &view.mImpactPosition, ownerRef);
    archive->Write(CachedWeakEntityType(), &view.mCollidedEntityWeak, ownerRef);

    archive->WriteUInt(view.mLifetimeEnd);
    archive->WriteBool(view.mBelowWater);
    archive->WriteInt(view.mBounceLimit);
    archive->WriteInt(view.mGroundTick);
    archive->WriteBool(view.mDirectAwayFromGround);
    archive->Write(CachedVector3fType(), &view.mGroundDirection, ownerRef);
    archive->WriteFloat(view.mBounceVelocityDamping);
    archive->WriteInt(view.mZigZagNextTick);
    archive->Write(CachedVector3fType(), &view.mZigZagRandomOffset, ownerRef);
    archive->Write(CachedProjectileAttributesType(), &view.mAttributes, ownerRef);
    archive->WriteBool(view.mIsChildProjectile);
  }

  /**
   * Address: 0x0069F8F0 (FUN_0069F8F0)
   *
   * What it does:
   * Thin serialization thunk that forwards to `Projectile::MemberSerialize`.
   */
  [[maybe_unused]] void ProjectileMemberSerializeThunkA(Projectile* const projectile, gpg::WriteArchive* const archive)
  {
    projectile->MemberSerialize(archive);
  }

  /**
   * Address: 0x006A0050 (FUN_006A0050)
   *
   * What it does:
   * Thin deserialization thunk that forwards to
   * `Projectile::MemberDeserialize`.
   */
  [[maybe_unused]] void ProjectileMemberDeserializeThunk(Projectile* const projectile, gpg::ReadArchive* const archive)
  {
    projectile->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006A0060 (FUN_006A0060)
   *
   * What it does:
   * Thin serialization thunk alias that forwards to
   * `Projectile::MemberSerialize`.
   */
  [[maybe_unused]] void ProjectileMemberSerializeThunkB(Projectile* const projectile, gpg::WriteArchive* const archive)
  {
    projectile->MemberSerialize(archive);
  }
} // namespace moho
