#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/WeakPtr.h"
#include "moho/projectile/CProjectileAttributes.h"
#include "moho/projectile/ProjectileStartupRegistrations.h"
#include "moho/sim/EImpactTypeTypeInfo.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  class CArmyImpl;
  struct RProjectileBlueprint;
  class Sim;
  class VTransform;

  /**
   * Address: 0x0069AC30 (FUN_0069AC30, Moho::Projectile::Projectile)
   *
   * What it does:
   * Primary projectile runtime entity. Current recovered layout keeps RTTI and
   * serializer-visible lanes while preserving full binary size.
   */
  class Projectile : public Entity
  {
  private:
    /**
     * Address: 0x0069AC30 (FUN_0069AC30, Moho::Projectile::Projectile)
     *
     * What it does:
     * Constructs one archive-owned projectile shell from simulation owner
     * context and writes default runtime lanes.
     */
    explicit Projectile(Sim* sim);

    /**
     * Address: 0x0069D1D0 (FUN_0069D1D0, Moho::Projectile::CheckCollision)
     * Mangled: ?CheckCollision@Projectile@Moho@@AAEXXZ
     *
     * IDA signature:
     * void __thiscall Moho::Projectile::CheckCollision(Moho::Projectile *this);
     *
     * Per-tick collision pass over the segment swept from the previous to the
     * pending position: handles water-surface crossing / layer change, tests the
     * water plane, samples terrain surface intersection, tests the explicit
     * homing target, sweeps entities crossing the segment, and finally tests the
     * terrain height field. The earliest hit stamps mImpactInterpolation,
     * mImpactPosition, the collided-entity weak link, and mImpactType.
     */
    void CheckCollision();

    /**
     * Address: 0x0069C8F0 (FUN_0069C8F0, Moho::Projectile::UpdateTracking)
     * Mangled: ?UpdateTracking@Projectile@Moho@@AAEXAAVVTransform@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::Projectile::UpdateTracking(Moho::Projectile *this, Moho::VTransform *trn);
     *
     * Homing/tracking steering update: resolves the aim point (optionally lead-
     * predicted), applies underwater clamps and zig-zag jitter, and steers `trn`
     * toward the aim direction by up to the projectile turn rate.
     */
    void UpdateTracking(VTransform& trn);

  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x0069AFE0 (FUN_0069AFE0, Moho::Projectile::Projectile)
     * Mangled: ??0Projectile@Moho@@QAE@PBVRProjectileBlueprint@1@PAVSim@1@PAVSimArmy@1@PAVEntity@1@VVTransform@1@MMV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVCAiTarget@1@_N@Z
     *
     * What it does:
     * Constructs one live projectile from runtime launch parameters: reserves a
     * projectile-family entity id, seeds randomized physics lanes from blueprint
     * spread ranges, splices launcher/target weak links, computes launch velocity,
     * writes the transforms, links into the Sim coord list, selects the initial
     * layer, and fires the OnPreCreate / OnLayerChange / OnCreate scripts.
     */
    Projectile(
      const RProjectileBlueprint* blueprint,
      Sim* sim,
      CArmyImpl* army,
      Entity* sourceEntity,
      const VTransform& launchTransform,
      float damage,
      float damageRadius,
      const msvc8::string& damageTypeName,
      const CAiTarget& target,
      bool isChildProjectile
    );

    /**
     * Address: 0x0069AED0 (FUN_0069AED0, Moho::Projectile::~Projectile)
     *
     * What it does:
     * Unlinks intrusive weak/broadcaster lanes owned by this projectile and
     * decrements the projectile instance-counter stat before base teardown.
     */
    ~Projectile() override;

    /**
     * Address: 0x0069A610 (FUN_0069A610, Moho::Projectile::IsProjectile)
     *
     * What it does:
     * Returns this projectile pointer through the RTTI/downcast lane.
     */
    Projectile* IsProjectile() override;

    /**
     * Address: 0x0069A5D0 (FUN_0069A5D0)
     *
     * What it does:
     * Returns this projectile's owning army pointer lane.
     */
    [[nodiscard]] CArmyImpl* GetArmyOwner() const;

    /**
     * Address: 0x0069A5E0 (FUN_0069A5E0)
     *
     * What it does:
     * Returns the resolved launcher entity from this projectile weak-launcher lane.
     */
    [[nodiscard]] Entity* GetLauncherEntity() const;

    /**
     * Address: 0x0069DE80 (FUN_0069DE80, Moho::Projectile::SetLifetime)
     *
     * What it does:
     * Sets the projectile expiration tick to `mCurTick + int(seconds * 10.0f)`.
     */
    void SetLifetime(float lifetimeSeconds);

    /**
     * Address: 0x0069BDD0 (FUN_0069BDD0, Moho::Projectile::MotionTick)
     * Mangled: ?MotionTick@Projectile@Moho@@UAE?AW4ETaskStatus@2@XZ
     *
     * IDA signature:
     * int __thiscall Moho::Projectile::MotionTick(Moho::Projectile *this);
     *
     * Overrides Entity::MotionTick (primary vtable slot 20). Per-frame projectile
     * update: advances mesh-scale animation, relinks into the Sim coord tail,
     * integrates velocity (ballistic or homing via UpdateTracking), applies speed
     * cap / upright / spin, writes the pending transform, runs CheckCollision,
     * handles lifetime expiry, and drives the terrain-bounce impact interpolation.
     */
    int MotionTick() override;

    /**
     * Address: 0x0069DEC0 (FUN_0069DEC0, Moho::Projectile::Impact)
     * Mangled: ?Impact@Projectile@Moho@@QAEXXZ
     *
     * IDA signature:
     * void __thiscall Moho::Projectile::Impact(Moho::Projectile *this);
     *
     * Impact/detonation handler: fires the `OnImpact` script, updates launcher
     * army shots-hit/missed realtime stats, dispatches the target/self collision
     * detonation callback by impact category, clears the collided-entity weak
     * link, and resets impact state.
     */
    void Impact();

    /**
     * Address: 0x0069E520 (FUN_0069E520, Moho::Projectile::MemberConstruct)
     */
    static void MemberConstruct(gpg::ReadArchive* archive, gpg::SerConstructResult* result);

    /**
     * Address: 0x006A0370 (FUN_006A0370, Moho::Projectile::MemberDeserialize)
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x006A0820 (FUN_006A0820, Moho::Projectile::MemberSerialize)
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    // Single-listener impact-event notifier: one intrusive weak node aimed at
    // the `CAcquireTargetTask` that fired this projectile, bound by
    // `CAiAttackerImpl::TransmitProjectileImpactEvent` and read back by
    // `Impact()`, which virtual-dispatches the chained listener's slot-0 OnEvent
    // with the per-category event code (asm 0x0069E0E6-0x0069E112).
    //
    // RTTI declares this a *base* rather than a member -
    // `.?AV?$ManyToOneBroadcaster@W4EProjectileImpactEvent@Moho@@@Moho@@` at
    // mdisp=624 (dumps/rtti_dump_all.hpp:63981), with
    // `InstanceCounter<Projectile>` at mdisp=632 right after it. Modelling it as
    // the first member is layout-identical, because `sizeof(Entity)` is 0x270,
    // so the base would land exactly here; the distinction is recorded rather
    // than acted on because flipping it also moves `InstanceCounter<Projectile>`
    // into the base list, and that one is empty-base-optimised.
    ManyToOneBroadcaster<EProjectileImpactEvent> mImpactEventBroadcaster; // +0x270

    /** The entity that fired this projectile, or the parent projectile's launcher for a child. */
    WeakPtr<Entity> mLauncherWeak; // +0x278

    /** World-space velocity in units per tick; integrated every `MotionTick`. */
    Wm3::Vector3f mVelocity;             // +0x280
    Wm3::Vector3f mLocalAngularVelocity; // +0x28C
    Wm3::Vector3f mScaleVelocity;        // +0x298

    /**
     * Fraction of the current tick's swept segment at which the earliest hit
     * found by `CheckCollision` occurred; 1.0 means "no hit this tick".
     */
    float mImpactInterpolation; // +0x2A4

    // The eight blueprint physics flags, one byte each, in blueprint order.
    bool mCollideSurface;   // +0x2A8
    bool mDoCollision;      // +0x2A9
    bool mTrackTarget;      // +0x2AA
    bool mVelocityAlign;    // +0x2AB
    bool mStayUpright;      // +0x2AC
    bool mLeadTarget;       // +0x2AD
    bool mStayUnderwater;   // +0x2AE
    bool mDestroyOnWater;   // +0x2AF

    float mTurnRateDegrees;                 // +0x2B0
    float mMaxSpeed;                        // +0x2B4
    float mAcceleration;                    // +0x2B8
    Wm3::Vector3f mBallisticAcceleration;   // +0x2BC

    float mDamage;                 // +0x2C8
    float mDamageRadius;           // +0x2CC
    msvc8::string mDamageTypeName; // +0x2D0
    CAiTarget mTargetPosData;      // +0x2EC

    /**
     * Cached homing aim point, written by `GetTargetPosGun` while a live target
     * exists. `mKeepLastAimLatch` is set in the launch constructor for ground
     * targets (non-Air/Sub layer); while it is set, `UpdateTracking` keeps
     * steering toward this point after the live target is lost rather than
     * giving up.
     */
    Wm3::Vector3f mCachedAimPoint;          // +0x30C
    bool mKeepLastAimLatch;                 // +0x318
    std::uint8_t pad_0319_031B[0x03];       // +0x319

    /** Earliest hit found this tick, and what it hit; both reset by `Impact()`. */
    Wm3::Vector3f mImpactPosition;          // +0x31C
    WeakPtr<Entity> mCollidedEntityWeak;    // +0x328

    std::uint32_t mLifetimeEnd;             // +0x330
    bool mBelowWater;                       // +0x334
    std::uint8_t pad_0335_0337[0x03];       // +0x335
    std::int32_t mBounceLimit;              // +0x338

    /** Terrain-bounce state: the tick the projectile met the ground, and the bounce normal. */
    std::int32_t mGroundTick;               // +0x33C
    bool mDirectAwayFromGround;             // +0x340
    std::uint8_t pad_0341_0343[0x03];       // +0x341
    Wm3::Vector3f mGroundDirection;         // +0x344
    float mBounceVelocityDamping;           // +0x350

    /** Zig-zag jitter applied by `UpdateTracking`, re-rolled when the tick is reached. */
    std::int32_t mZigZagNextTick;           // +0x354
    Wm3::Vector3f mZigZagRandomOffset;      // +0x358

    EImpactType mImpactType;                // +0x364
    CProjectileAttributes mAttributes;      // +0x368
    bool mIsChildProjectile;                // +0x37C
    std::uint8_t pad_037D_037F[0x03];       // +0x37D
  };

  // Offsets read directly by `Projectile::Impact` (0x0069DEC0): [edi+270h],
  // [edi+278h], [edi+2A4h], [edi+2ECh], [edi+2F0h], [edi+31Ch], [edi+320h],
  // [edi+324h], [edi+328h] and [edi+364h].
  static_assert(offsetof(Projectile, mImpactEventBroadcaster) == 0x270, "Projectile::mImpactEventBroadcaster offset must be 0x270");
  static_assert(offsetof(Projectile, mLauncherWeak) == 0x278, "Projectile::mLauncherWeak offset must be 0x278");
  static_assert(offsetof(Projectile, mVelocity) == 0x280, "Projectile::mVelocity offset must be 0x280");
  static_assert(offsetof(Projectile, mLocalAngularVelocity) == 0x28C, "Projectile::mLocalAngularVelocity offset must be 0x28C");
  static_assert(offsetof(Projectile, mScaleVelocity) == 0x298, "Projectile::mScaleVelocity offset must be 0x298");
  static_assert(offsetof(Projectile, mImpactInterpolation) == 0x2A4, "Projectile::mImpactInterpolation offset must be 0x2A4");
  static_assert(offsetof(Projectile, mDestroyOnWater) == 0x2AF, "Projectile::mDestroyOnWater offset must be 0x2AF");
  static_assert(offsetof(Projectile, mTurnRateDegrees) == 0x2B0, "Projectile::mTurnRateDegrees offset must be 0x2B0");
  static_assert(offsetof(Projectile, mAcceleration) == 0x2B8, "Projectile::mAcceleration offset must be 0x2B8");
  static_assert(offsetof(Projectile, mBallisticAcceleration) == 0x2BC, "Projectile::mBallisticAcceleration offset must be 0x2BC");
  static_assert(offsetof(Projectile, mDamage) == 0x2C8, "Projectile::mDamage offset must be 0x2C8");
  static_assert(offsetof(Projectile, mDamageRadius) == 0x2CC, "Projectile::mDamageRadius offset must be 0x2CC");
  static_assert(offsetof(Projectile, mDamageTypeName) == 0x2D0, "Projectile::mDamageTypeName offset must be 0x2D0");
  static_assert(offsetof(Projectile, mTargetPosData) == 0x2EC, "Projectile::mTargetPosData offset must be 0x2EC");
  static_assert(offsetof(Projectile, mCachedAimPoint) == 0x30C, "Projectile::mCachedAimPoint offset must be 0x30C");
  static_assert(offsetof(Projectile, mKeepLastAimLatch) == 0x318, "Projectile::mKeepLastAimLatch offset must be 0x318");
  static_assert(offsetof(Projectile, mImpactPosition) == 0x31C, "Projectile::mImpactPosition offset must be 0x31C");
  static_assert(offsetof(Projectile, mCollidedEntityWeak) == 0x328, "Projectile::mCollidedEntityWeak offset must be 0x328");
  static_assert(offsetof(Projectile, mLifetimeEnd) == 0x330, "Projectile::mLifetimeEnd offset must be 0x330");
  static_assert(offsetof(Projectile, mBelowWater) == 0x334, "Projectile::mBelowWater offset must be 0x334");
  static_assert(offsetof(Projectile, mBounceLimit) == 0x338, "Projectile::mBounceLimit offset must be 0x338");
  static_assert(offsetof(Projectile, mGroundTick) == 0x33C, "Projectile::mGroundTick offset must be 0x33C");
  static_assert(offsetof(Projectile, mDirectAwayFromGround) == 0x340, "Projectile::mDirectAwayFromGround offset must be 0x340");
  static_assert(offsetof(Projectile, mGroundDirection) == 0x344, "Projectile::mGroundDirection offset must be 0x344");
  static_assert(offsetof(Projectile, mBounceVelocityDamping) == 0x350, "Projectile::mBounceVelocityDamping offset must be 0x350");
  static_assert(offsetof(Projectile, mZigZagNextTick) == 0x354, "Projectile::mZigZagNextTick offset must be 0x354");
  static_assert(offsetof(Projectile, mZigZagRandomOffset) == 0x358, "Projectile::mZigZagRandomOffset offset must be 0x358");
  static_assert(offsetof(Projectile, mImpactType) == 0x364, "Projectile::mImpactType offset must be 0x364");
  static_assert(offsetof(Projectile, mAttributes) == 0x368, "Projectile::mAttributes offset must be 0x368");
  static_assert(offsetof(Projectile, mIsChildProjectile) == 0x37C, "Projectile::mIsChildProjectile offset must be 0x37C");
  static_assert(sizeof(Projectile) == 0x380, "Projectile size must be 0x380");

  /**
   * Address: 0x006A0FB0 (FUN_006A0FB0, Moho::PROJ_Create)
   *
   * What it does:
   * Allocates one projectile and forwards launch parameters into the
   * projectile constructor path.
   */
  Projectile* PROJ_Create(
    Sim* sim,
    const RProjectileBlueprint* blueprint,
    CArmyImpl* army,
    Entity* sourceEntity,
    const VTransform& launchTransform,
    float damage,
    float damageRadius,
    const msvc8::string& damageTypeName,
    const CAiTarget& target,
    bool isChildProjectile
  );

  template <>
  class CScrLuaMetatableFactory<Projectile> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x0067FFE0 (FUN_0067FFE0, Moho::CScrLuaMetatableFactory<Moho::Projectile>::Create)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<Projectile>) == 0x08,
    "CScrLuaMetatableFactory<Projectile> size must be 0x08"
  );

  /**
   * Address: 0x0067F0E0 (FUN_0067F0E0, func_GetProjectileFactory)
   *
   * What it does:
   * Returns cached `Projectile` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_GetProjectileFactory(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x00BD50D0 (FUN_00BD50D0, register_CScrLuaMetatableFactory_Projectile_Index)
   *
   * What it does:
   * Assigns startup factory-object index for `CScrLuaMetatableFactory<Projectile>::sInstance`.
   */
  int register_CScrLuaMetatableFactory_Projectile_Index();
} // namespace moho
