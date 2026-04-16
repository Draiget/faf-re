#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EBeamParamTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00770AC0 (FUN_00770AC0)
     *
     * What it does:
     * Preregisters the reflected `EBeamParam` enum metadata.
     */
    EBeamParamTypeInfo();

    /**
     * Address: 0x00770B50 (FUN_00770B50, scalar deleting thunk)
     */
    ~EBeamParamTypeInfo() override;

    /**
     * Address: 0x00770B40 (FUN_00770B40)
     *
     * What it does:
     * Returns the reflection type name literal for EBeamParam.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00770B20 (FUN_00770B20)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00770B80 (FUN_00770B80)
     *
     * What it does:
     * Registers EBeamParam enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EBeamParamTypeInfo) == 0x78, "EBeamParamTypeInfo size must be 0x78");
} // namespace moho
