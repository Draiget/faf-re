#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/render/EmitterType.h"

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


  /**
   * Address: 0x0065DEB0 (FUN_0065DEB0, register_EmitterTypeTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::EmitterType`.
   */
  gpg::RType* register_EmitterTypeTypeInfo_00();

  /**
   * Address: 0x00BD4290 (FUN_00BD4290, register_EmitterTypeTypeInfo)
   *
   * What it does:
   * Registers `EmitterType` RTTI bootstrap and installs process-exit cleanup.
   */
  void register_EmitterTypeTypeInfo();
} // namespace moho
