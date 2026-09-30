#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Address: 0x00BCD5A0 (FUN_00BCD5A0)
   *
   * What it does:
   * Preregisters startup RTTI for the legacy AI `SValuePair` lane and installs
   * process-exit cleanup.
   */
  void register_SValuePairTypeInfo();
} // namespace moho
