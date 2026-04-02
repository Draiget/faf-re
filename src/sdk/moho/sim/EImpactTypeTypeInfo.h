#pragma once

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
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
} // namespace moho
