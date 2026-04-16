#pragma once

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Strategic-icon lane classification used by world-session icon rendering.
   */
  enum EGenericIconType : std::int32_t
  {
    GIT_Land = 0,
    GIT_LandHL = 1,
    GIT_Naval = 2,
    GIT_NavalHL = 3,
    GIT_Air = 4,
    GIT_AirHL = 5,
    GIT_Structure = 6,
    GIT_StructureHL = 7,
  };

  static_assert(sizeof(EGenericIconType) == 0x04, "EGenericIconType size must be 0x04");

  /**
   * Owns reflected metadata for the `EGenericIconType` enum.
   */
  class EGenericIconTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0085B120 (FUN_0085B120, Moho::EGenericIconTypeTypeInfo::EGenericIconTypeTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EGenericIconType` with the reflection registry.
     */
    EGenericIconTypeTypeInfo();

    /**
     * Address: 0x0085B1B0 (FUN_0085B1B0, Moho::EGenericIconTypeTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for the enum type descriptor.
     */
    ~EGenericIconTypeTypeInfo() override;

    /**
     * Address: 0x0085B1A0 (FUN_0085B1A0, Moho::EGenericIconTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected enum type label.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0085B180 (FUN_0085B180, Moho::EGenericIconTypeTypeInfo::Init)
     *
     * What it does:
     * Writes enum width, installs enum labels, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0085B1E0 (FUN_0085B1E0, Moho::EGenericIconTypeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `GIT_` icon-type enum names and integer values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EGenericIconTypeTypeInfo) == 0x78, "EGenericIconTypeTypeInfo size must be 0x78");
} // namespace moho
