#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2E228
   * COL: 0x00E87EDC
   */
  class CWeaponAttributesSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD87D0 (FUN_00BD87D0, dynamic initializer for the global
     * `CWeaponAttributesSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CWeaponAttributesSerializer();

    /**
     * Address: 0x00BFE5F0 (FUN_00BFE5F0, Moho::CWeaponAttributesSerializer::~CWeaponAttributesSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. The ctor's atexit
     * target has no mangled name in the binary (a plain unlink thunk, not a
     * `??1...` symbol), so it is modeled as the compiler's implicit
     * static-destructor registration rather than an explicit free-function
     * atexit call.
     */
    ~CWeaponAttributesSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CWeaponAttributesSerializer, mDeserialize) == 0x0C, "CWeaponAttributesSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CWeaponAttributesSerializer, mSerialize) == 0x10, "CWeaponAttributesSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CWeaponAttributesSerializer) == 0x14, "CWeaponAttributesSerializer size must be 0x14");
} // namespace moho
