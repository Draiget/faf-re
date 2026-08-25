#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  class Entity;
  class Sim;

  /**
   * Owns the reflected enum descriptor for `EImpactType`.
   */
  enum EImpactType : std::int32_t
  {
    IMPACT_Invalid = 0,
    IMPACT_Terrain = 1,
    IMPACT_Water = 2,
    IMPACT_Air = 3,
    IMPACT_Underwater = 4,
    IMPACT_Projectile = 5,
    IMPACT_ProjectileUnderwater = 6,
    IMPACT_Prop = 7,
    IMPACT_Shield = 8,
    IMPACT_Unit = 9,
    IMPACT_UnitAir = 10,
    IMPACT_UnitUnderwater = 11,
  };

  static_assert(sizeof(EImpactType) == 0x04, "EImpactType size must be 0x04");

  /**
   * Address: 0x0067B240 (FUN_0067B240, Moho::ENT_GetImpactType)
   *
   * What it does:
   * Resolves impact classification from hit position vs waterline and optional
   * collided-entity runtime type/layer lanes.
   */
  [[nodiscard]] EImpactType ENT_GetImpactType(Sim* sim, Entity* entity, const Wm3::Vector3f& hitPosition);

  /**
   * Address: 0x0067B320 (FUN_0067B320, Moho::ENT_GetImpactTypeString)
   *
   * What it does:
   * Converts an impact type enum into its canonical debug/script label.
   */
  [[nodiscard]] const char* ENT_GetImpactTypeString(EImpactType impactType);

  /**
   * Owns reflected metadata for the `EImpactType` enum.
   */
  class EImpactTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00509F60 (FUN_00509F60, Moho::EImpactTypeTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for the `EImpactType` enum descriptor.
     */
    ~EImpactTypeTypeInfo() override;

    /**
     * Address: 0x00509F50 (FUN_00509F50, Moho::EImpactTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `EImpactType`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00509F30 (FUN_00509F30, Moho::EImpactTypeTypeInfo::Init)
     *
     * What it does:
     * Writes the enum width, installs values, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00509F90 (FUN_00509F90, Moho::EImpactTypeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `IMPACT_` enum names and values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EImpactTypeTypeInfo) == 0x78, "EImpactTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EImpactType,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EImpactType@Moho@@H@gpg'`):
   * `FUN_00BC7A90` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at 0x0050A6A0 (compiler/linker artifact, no source line -- see the
   * class-level Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h).
   *
   * The previous raw-struct recovery of this instantiation also modeled a
   * "secondary" startup thunk at 0x0050A9D0 as if it were a duplicate
   * emission of this same ctor. It is not: per `vtable_writers`, 0x0050A9D0
   * is the (itself dead, zero-xref) ctor of the unrelated template
   * instantiation `gpg::SerSaveLoadHelper<Moho::EImpactType>`
   * (`class_name='?$SerSaveLoadHelper@W4EImpactType@Moho@@@gpg'`), the same
   * distinct ~50-instantiation template family flagged on `EAlliance`'s
   * conversion, out of scope here.
   */
  using EImpactTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EImpactType, int>;

  /**
   * Address: 0x00BC7A70 (FUN_00BC7A70, register_EImpactTypeTypeInfo)
   *
   * What it does:
   * Runs `EImpactType` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EImpactTypeTypeInfo();
} // namespace moho
