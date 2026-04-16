#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EEmitterCurveTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x007704E0 (FUN_007704E0)
     *
     * What it does:
     * Preregisters the reflected `EEmitterCurve` enum metadata.
     */
    EEmitterCurveTypeInfo();

    /**
     * Address: 0x00770570 (FUN_00770570, scalar deleting thunk)
     */
    ~EEmitterCurveTypeInfo() override;

    /**
     * Address: 0x00770560 (FUN_00770560)
     *
     * What it does:
     * Returns the reflection type name literal for EEmitterCurve.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00770540 (FUN_00770540)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x007705A0 (FUN_007705A0)
     *
     * What it does:
     * Registers EEmitterCurve enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EEmitterCurveTypeInfo) == 0x78, "EEmitterCurveTypeInfo size must be 0x78");
} // namespace moho
