#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E2D7BC
   * COL: 0x00E870C0
   */
  class SInfoCacheTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x006A4E60 (FUN_006A4E60)
     *
     * What it does:
     * Constructs and preregisters RTTI metadata for `SInfoCache`.
     */
    SInfoCacheTypeInfo();

    /**
     * Address: 0x006A4EF0 (FUN_006A4EF0, sub_6A4EF0)
     *
     * What it does:
     * Releases reflected `SInfoCacheTypeInfo` field/base vectors and restores the
     * base `RObject` vtable lane during teardown.
     */
    ~SInfoCacheTypeInfo() override;

    /**
     * Address: 0x006A4EC0 (FUN_006A4EC0, Moho::SInfoCacheTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size metadata for `SInfoCache` and finalizes the type.
     */
    void Init() override;

    /**
     * Address: 0x006A4EE0 (FUN_006A4EE0, Moho::SInfoCacheTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type-name literal for `SInfoCache`.
     */
    [[nodiscard]] const char* GetName() const override;
  };

  static_assert(sizeof(SInfoCacheTypeInfo) == 0x64, "SInfoCacheTypeInfo size must be 0x64");

} // namespace moho
