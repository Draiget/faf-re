#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E17584
   * COL:  0x00E6C5A8
   */
  class IArmyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00550B50 (FUN_00550B50, Moho::IArmyTypeInfo::dtr)
     */
    ~IArmyTypeInfo() override;

    /**
     * Address: 0x00550B40 (FUN_00550B40, Moho::IArmyTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00550B20 (FUN_00550B20, Moho::IArmyTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(IArmyTypeInfo) == 0x64, "IArmyTypeInfo size must be 0x64");

  /**
   * Address: 0x00550AC0 (FUN_00550AC0, preregister_IArmyTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for `IArmy`.
   */
  [[nodiscard]] gpg::RType* preregister_IArmyTypeInfo();

  /**
   * Address: 0x00BC9B50 (FUN_00BC9B50, register_IArmyTypeInfo)
   *
   * What it does:
   * Runs `IArmy` typeinfo preregistration and installs process-exit cleanup.
   */
  int register_IArmyTypeInfo();
} // namespace moho

