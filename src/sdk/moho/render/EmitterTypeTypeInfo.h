#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EmitterTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0065DF40 (FUN_0065DF40, scalar deleting thunk)
     */
    ~EmitterTypeTypeInfo() override;

    /**
     * Address: 0x0065DF30 (FUN_0065DF30)
     *
     * What it does:
     * Returns the reflection type name literal for EmitterType.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0065DF10 (FUN_0065DF10)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EmitterTypeTypeInfo) == 0x78, "EmitterTypeTypeInfo size must be 0x78");
} // namespace moho
