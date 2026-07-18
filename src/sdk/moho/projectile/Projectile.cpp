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
#include "moho/math/Vector3f.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/projectile/CProjectileAttributes.h"
#include "moho/projectile/ProjectileStartupRegistrations.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/EImpactTypeTypeInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"

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

  struct ProjectileImpactBroadcasterStorage
  {
    std::uint8_t bytes[0x08];
  };
  static_assert(sizeof(ProjectileImpactBroadcasterStorage) == 0x08, "Impact broadcaster storage size must be 0x08");

  struct ProjectileDeserializeRuntimeView
  {
    std::uint8_t mEntityStateStorage[0x270];
    ProjectileImpactBroadcasterStorage mImpactEventBroadcaster;
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
    Wm3::Vector3f mUnknownVelocityVector;
    bool mUnknownTrajectoryFlag;
    std::uint8_t mUnknownTrajectoryPadding[3];
    float mDamage;
    float mDamageRadius;
    msvc8::string mDamageTypeName;
    moho::CAiTarget mTargetPosData;
    Wm3::Vector3f mImpactPosition;
    moho::WeakPtr<moho::Entity> mUnknownEntityWeak;
    std::uint32_t mLifetimeEnd;
    bool mBelowWater;
    std::uint8_t mBelowWaterPadding[3];
    std::int32_t mBounceLimit;
    std::int32_t mGroundTick;
    bool mDirectAwayFromGround;
    std::uint8_t mGroundDirectionPadding[3];
    Wm3::Vector3f mGroundDirection;
    float mBounceVelocityDamping;
    std::int32_t mUnknownBounceCount;
    Wm3::Vector3f mUnknownGroundVector;
    moho::EImpactType mImpactType;
    moho::CProjectileAttributes mAttributes;
    bool mUnknownTailFlag;
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
    offsetof(ProjectileDeserializeRuntimeView, mUnknownEntityWeak) == 0x328,
    "ProjectileDeserializeRuntimeView::mUnknownEntityWeak offset must be 0x328"
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
    offsetof(ProjectileDeserializeRuntimeView, mUnknownBounceCount) == 0x354,
    "ProjectileDeserializeRuntimeView::mUnknownBounceCount offset must be 0x354"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mUnknownGroundVector) == 0x358,
    "ProjectileDeserializeRuntimeView::mUnknownGroundVector offset must be 0x358"
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
    offsetof(ProjectileDeserializeRuntimeView, mUnknownTailFlag) == 0x37C,
    "ProjectileDeserializeRuntimeView::mUnknownTailFlag offset must be 0x37C"
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

  void UnlinkImpactBroadcaster(ProjectileImpactBroadcasterStorage& broadcaster) noexcept
  {
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

    view.mUnknownVelocityVector = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mUnknownTrajectoryFlag = false;
    view.mImpactPosition = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mUnknownEntityWeak.ClearLinkState();
    view.mLifetimeEnd = 0u;
    view.mBelowWater = false;
    view.mBounceLimit = 0;
    view.mGroundTick = 0;
    view.mDirectAwayFromGround = false;
    view.mGroundDirection = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mBounceVelocityDamping = kProjectileBounceVelocityDampingDefault;
    view.mUnknownBounceCount = 0;
    view.mUnknownGroundVector = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactType = IMPACT_Air;
    view.mAttributes = CProjectileAttributes();
    view.mUnknownTailFlag = false;
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
    view.mUnknownVelocityVector = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mUnknownTrajectoryFlag = false;
    view.mImpactPosition = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mUnknownEntityWeak.ClearLinkState();
    view.mBounceLimit = 0;
    view.mGroundTick = 0;
    view.mBelowWater = false;
    view.mDirectAwayFromGround = false;
    view.mGroundDirection = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mBounceVelocityDamping = blueprint->Physics.BounceVelDamp;
    view.mUnknownBounceCount = 0;
    view.mUnknownGroundVector = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactType = IMPACT_Air;

    view.mAttributes.mBlueprint = const_cast<RProjectileBlueprint*>(blueprint);
    view.mAttributes.mMaxZigZag = kProjectileUnsetValue;
    view.mAttributes.mZigZagFrequency = kProjectileUnsetValue;
    view.mAttributes.mDetonateAboveHeight = kProjectileUnsetValue;
    view.mAttributes.mDetonateBelowHeight = kProjectileUnsetValue;

    view.mUnknownTailFlag = isChildProjectile;

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
      // a random initial speed (asm 0x0069B85F-0069B918). The ARITHMETIC below is
      // transcribed 1:1 from the .asm (movaps/mulss/addss/subss chain, *flt_DFEB0C
      // == *2.0), and the result-lane store order (mVelocity.x/y/z <- result.y /
      // result.z / var_10 each * GetRandomInitialSpeed) is confirmed.
      //
      /* UNRESOLVED: exact launchTransform lane -> (qx,qy,qz,qw) mapping for the
       * ballistic branch, asm 0x0069B55C-0x0069B56E. IDA names the four input
       * stack slots (x, y, z, qx) but they do NOT line up cleanly with the
       * VTransform value-arg's 7 floats (posori occupies frame slots +0x00..+0x1B;
       * the `z`/`qx` slots read here fall at +0x1C/+0x20, past posori's end), so the
       * decompiler's `posori.orient.x` / `posori.pos.*` labels are unreliable here.
       * The quaternion->forward algebra below assumes the standard
       * (x,y,z,w) = orient_.(x,y,z,w) mapping; VERIFY the precise slot->field
       * binding against a live frame trace before trusting the launch DIRECTION for
       * non-realistic-ordinance projectiles. The realistic-ordinance path (the
       * common weapon case) is unaffected. */
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

    // Splice the coord node into Sim::mCoordEntities (ListLinkBefore == tail insert;
    // it self-unlinks first, matching the binary's self-init + list-tail insert).
    mCoordNode.ListLinkBefore(&sim->mCoordEntities);

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
        // v207 (mUnknownTrajectoryFlag) := 1 unless the target's current layer is
        // Air (0x10) or Sub (0x04).
        Entity* const trackedEntity = view.mTargetPosData.targetEntity.GetObjectPtr();
        if (trackedEntity != nullptr) {
          const ELayer trackedLayer = trackedEntity->mCurrentLayer;
          if (trackedLayer != LAYER_Air && trackedLayer != LAYER_Sub) {
            view.mUnknownTrajectoryFlag = true;
          }
        }
        const Wm3::Vec3f gunPos = view.mTargetPosData.GetTargetPosGun(false);
        view.mUnknownVelocityVector = Wm3::Vector3f{gunPos.x, gunPos.y, gunPos.z};
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

      /* UNRESOLVED: camera-follow sync-vector push, asm 0x0069BD56-0x0069BD8E.
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
    archive->Read(CachedVector3fType(), &view.mUnknownVelocityVector, ownerRef);
    archive->ReadBool(&view.mUnknownTrajectoryFlag);

    archive->ReadFloat(&view.mDamage);
    archive->ReadFloat(&view.mDamageRadius);
    archive->ReadString(&view.mDamageTypeName);

    archive->Read(CachedAiTargetType(), &view.mTargetPosData, ownerRef);
    archive->Read(CachedVector3fType(), &view.mImpactPosition, ownerRef);
    archive->Read(CachedWeakEntityType(), &view.mUnknownEntityWeak, ownerRef);

    archive->ReadUInt(&view.mLifetimeEnd);
    archive->ReadBool(&view.mBelowWater);
    archive->ReadInt(&view.mBounceLimit);
    archive->ReadInt(&view.mGroundTick);
    archive->ReadBool(&view.mDirectAwayFromGround);
    archive->Read(CachedVector3fType(), &view.mGroundDirection, ownerRef);
    archive->ReadFloat(&view.mBounceVelocityDamping);
    archive->ReadInt(&view.mUnknownBounceCount);
    archive->Read(CachedVector3fType(), &view.mUnknownGroundVector, ownerRef);
    archive->Read(CachedProjectileAttributesType(), &view.mAttributes, ownerRef);
    archive->ReadBool(&view.mUnknownTailFlag);
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
    archive->Write(CachedVector3fType(), &view.mUnknownVelocityVector, ownerRef);
    archive->WriteBool(view.mUnknownTrajectoryFlag);

    archive->WriteFloat(view.mDamage);
    archive->WriteFloat(view.mDamageRadius);
    archive->WriteString(const_cast<msvc8::string*>(&view.mDamageTypeName));

    archive->Write(CachedAiTargetType(), &view.mTargetPosData, ownerRef);
    archive->Write(CachedVector3fType(), &view.mImpactPosition, ownerRef);
    archive->Write(CachedWeakEntityType(), &view.mUnknownEntityWeak, ownerRef);

    archive->WriteUInt(view.mLifetimeEnd);
    archive->WriteBool(view.mBelowWater);
    archive->WriteInt(view.mBounceLimit);
    archive->WriteInt(view.mGroundTick);
    archive->WriteBool(view.mDirectAwayFromGround);
    archive->Write(CachedVector3fType(), &view.mGroundDirection, ownerRef);
    archive->WriteFloat(view.mBounceVelocityDamping);
    archive->WriteInt(view.mUnknownBounceCount);
    archive->Write(CachedVector3fType(), &view.mUnknownGroundVector, ownerRef);
    archive->Write(CachedProjectileAttributesType(), &view.mAttributes, ownerRef);
    archive->WriteBool(view.mUnknownTailFlag);
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
