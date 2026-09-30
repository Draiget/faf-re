#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00BCE0B0 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `SSiloBuildInfoSerializer` singleton from an explicit registration
   * sequence. `gSSiloBuildInfoSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  int register_SSiloBuildInfoSerializer();

  /**
   * Address: 0x00BCE150 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `CAiSiloBuildImplSerializer` singleton from an explicit registration
   * sequence. `gCAiSiloBuildImplSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  int register_CAiSiloBuildImplSerializer();
} // namespace moho
