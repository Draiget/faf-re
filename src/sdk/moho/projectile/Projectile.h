#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaObjectFactory.h"
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
    std::uint8_t mUnknown0270[0x1C];   // +0x270
    Wm3::Vector3f mLocalAngularVelocity; // +0x28C
    Wm3::Vector3f mScaleVelocity;      // +0x298
    std::uint8_t mUnknown02A4[0x24];   // +0x2A4
    float mDamage;                   // +0x2C8
    float mDamageRadius;             // +0x2CC
    msvc8::string mDamageTypeName;   // +0x2D0
    CAiTarget mTargetPosData;        // +0x2EC
    std::uint8_t mUnknown030C[0x74]; // +0x30C
  };

  static_assert(offsetof(Projectile, mLocalAngularVelocity) == 0x28C, "Projectile::mLocalAngularVelocity offset must be 0x28C");
  static_assert(offsetof(Projectile, mScaleVelocity) == 0x298, "Projectile::mScaleVelocity offset must be 0x298");
  static_assert(offsetof(Projectile, mDamage) == 0x2C8, "Projectile::mDamage offset must be 0x2C8");
  static_assert(offsetof(Projectile, mDamageRadius) == 0x2CC, "Projectile::mDamageRadius offset must be 0x2CC");
  static_assert(offsetof(Projectile, mDamageTypeName) == 0x2D0, "Projectile::mDamageTypeName offset must be 0x2D0");
  static_assert(offsetof(Projectile, mTargetPosData) == 0x2EC, "Projectile::mTargetPosData offset must be 0x2EC");
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
