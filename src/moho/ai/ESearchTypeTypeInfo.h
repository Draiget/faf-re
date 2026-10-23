#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class ESearchTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A9D90 (FUN_005A9D90, Moho::ESearchTypeTypeInfo::ESearchTypeTypeInfo)
     *
     * What it does:
     * Preregisters `ESearchType` enum metadata with the reflection runtime.
     */
    ESearchTypeTypeInfo();

    /**
     * Address: 0x005A9E20 (FUN_005A9E20, scalar deleting thunk)
     */
    ~ESearchTypeTypeInfo() override;

    /**
     * Address: 0x005A9E10 (FUN_005A9E10, Moho::ESearchTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type name literal for `ESearchType`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A9DF0 (FUN_005A9DF0, Moho::ESearchTypeTypeInfo::Init)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(ESearchTypeTypeInfo) == 0x78, "ESearchTypeTypeInfo size must be 0x78");


  /**
   * Address: 0x00BCCCF0 (FUN_00BCCCF0, register_ESearchTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `ESearchType`.
   */
  void register_ESearchTypeTypeInfo();
} // namespace moho
