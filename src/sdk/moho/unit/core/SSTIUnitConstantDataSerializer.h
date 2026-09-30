#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SSTIUnitConstantData;

  /**
   * Address: 0x0055C410 (FUN_0055C410, preregister_SSTIUnitConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIUnitConstantData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIUnitConstantDataTypeInfo();
} // namespace moho
