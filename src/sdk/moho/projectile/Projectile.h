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

  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x0069AFE0 (FUN_0069AFE0, Moho::Projectile::Projectile)
     *
     * What it does:
     * Constructs one projectile from runtime launch parameters.
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
   * Address: 0x00BD50D0 (FUN_00BD50D0, register_CScrLuaMetatableFactory_Projectile_Index)
   *
   * What it does:
   * Assigns startup factory-object index for `CScrLuaMetatableFactory<Projectile>::sInstance`.
   */
  int register_CScrLuaMetatableFactory_Projectile_Index();
} // namespace moho
