#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Address: 0x00BC3360 (FUN_00BC3360, register_CRandomStreamTypeInfo)
   *
   * What it does:
   * Startup thunk that constructs the CRandomStream type-info object.
   */
  void register_CRandomStreamTypeInfo();
} // namespace moho
