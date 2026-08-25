#pragma once

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho::blueprint_ser
{
  /**
   * Lazily resolves and caches the reflection descriptor for `TObject` into
   * caller-owned storage (`slot`). Shared by the `R*BlueprintConstruct` /
   * `R*BlueprintSaveConstruct` family in this directory, mirroring the
   * per-type `Cached*Type()` lazy-lookup helpers used elsewhere in the SDK
   * (see `CachedSEconStorageType()` in `moho/sim/CEconomy.cpp`).
   */
  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }
} // namespace moho::blueprint_ser
