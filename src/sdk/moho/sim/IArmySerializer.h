#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Address: 0x005506B0 (FUN_005506B0, preregister_SSTIArmyConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIArmyConstantData`. This is
   * orthogonal to IArmySerializer above: SSTIArmyConstantDataTypeInfo derives
   * from gpg::RType directly (not gpg::SerHelperBase) and this preregister
   * function is independently reachable through GPG_PREREGISTER_INIT: the
   * real IArmySerializer ctor's disassembly does not call it.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIArmyConstantDataTypeInfo();
} // namespace moho
