#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E2E228
   * COL: 0x00E87EDC
   */
  class CWeaponAttributesSerializer
  {
  public:
    /**
      * Alias of FUN_006D3780 (non-canonical helper lane).
     *
     * What it does:
     * Loads the reflected pointer/string/float lanes for `CWeaponAttributes`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
      * Alias of FUN_006D3790 (non-canonical helper lane).
     *
     * What it does:
     * Saves the reflected pointer/string/float lanes for `CWeaponAttributes`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DB4C0 (FUN_006DB4C0, Moho::CWeaponAttributesSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `CWeaponAttributes` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CWeaponAttributesSerializer, mHelperNext) == 0x04, "CWeaponAttributesSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CWeaponAttributesSerializer, mHelperPrev) == 0x08, "CWeaponAttributesSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CWeaponAttributesSerializer, mDeserialize) == 0x0C, "CWeaponAttributesSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CWeaponAttributesSerializer, mSerialize) == 0x10, "CWeaponAttributesSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CWeaponAttributesSerializer) == 0x14, "CWeaponAttributesSerializer size must be 0x14");

  /**
   * Address: 0x00BFE5F0 (FUN_00BFE5F0, serializer helper unlink cleanup)
   *
   * What it does:
   * Unlinks `CWeaponAttributesSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_CWeaponAttributesSerializer();

  /**
   * Address: 0x00BD87D0 (FUN_00BD87D0, startup registration + atexit cleanup)
   *
   * What it does:
   * Initializes and registers `CWeaponAttributes` serializer callbacks.
   */
  int register_CWeaponAttributesSerializer();
} // namespace moho
