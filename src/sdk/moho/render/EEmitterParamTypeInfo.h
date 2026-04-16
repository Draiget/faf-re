#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EEmitterParamTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00770790 (FUN_00770790)
     *
     * What it does:
     * Preregisters the reflected `EEmitterParam` enum metadata.
     */
    EEmitterParamTypeInfo();

    /**
     * Address: 0x00770820 (FUN_00770820, scalar deleting thunk)
     */
    ~EEmitterParamTypeInfo() override;

    /**
     * Address: 0x00770810 (FUN_00770810)
     *
     * What it does:
     * Returns the reflection type name literal for EEmitterParam.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007707F0 (FUN_007707F0)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00770850 (FUN_00770850)
     *
     * What it does:
     * Registers EEmitterParam enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EEmitterParamTypeInfo) == 0x78, "EEmitterParamTypeInfo size must be 0x78");
} // namespace moho
