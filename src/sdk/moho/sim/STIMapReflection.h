#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class STIMap;

  /**
   * Address: 0x00577750 (FUN_00577750, preregister_STIMapTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `STIMap`.
   */
  [[nodiscard]] gpg::RType* preregister_STIMapTypeInfo();
}

namespace gpg
{
  /**
   * Address: 0x00509AC0 (FUN_00509AC0, gpg::RRef_STIMap)
   *
   * What it does:
   * Builds one typed reflection reference for a `STIMap*` pointer.
   */
  gpg::RRef* RRef_STIMap(gpg::RRef* outRef, moho::STIMap* value);

  /**
    * Alias of FUN_005096E0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one tracked-pointer lane, upcasts it to `STIMap`, and raises
   * `SerializationError` on mismatched pointee type.
   */
  [[nodiscard]] moho::STIMap* ReadPointerSTIMap(gpg::ReadArchive* archive, const gpg::RRef& ownerRef);

  /**
   * Address: 0x005097F0 (FUN_005097F0, STIMap unowned pointer write helper)
   *
   * What it does:
   * Writes one `STIMap*` as an unowned tracked-pointer lane owned by
   * `ownerRef`.
   */
  gpg::WriteArchive* WriteUnownedPointerSTIMap(moho::STIMap* value, gpg::WriteArchive* archive, const gpg::RRef& ownerRef);

  /**
   * Address: 0x005099A0 (FUN_005099A0, STIMap RRef upcast helper)
   *
   * What it does:
   * Upcasts one generic `RRef` lane to `STIMap` and returns the typed object
   * pointer (or `nullptr` on mismatch).
   */
  [[nodiscard]] void* UpcastPointerToSTIMap(const gpg::RRef& source);
} // namespace gpg

