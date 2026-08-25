#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E294BC
   */
  class SPhysConstantsSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6050 (FUN_00BD6050, dynamic initializer for the global
     * `SPhysConstantsSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target is a plain
     * unlink thunk, not a mangled destructor, so it is modeled as the
     * compiler's implicit static-destructor registration rather than an
     * explicit call.
     */
    SPhysConstantsSerializer();

    /**
     * Address: 0x00BFD460 (FUN_00BFD460, ??1SPhysConstantsSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPhysConstantsSerializer();

    /**
     * Address: 0x00699C10 (FUN_00699C10, Moho::SPhysConstantsSerializer::Deserialize)
     *
     * What it does:
     * Loads the reflected `mGravity` vector for `SPhysConstants`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00699C50 (FUN_00699C50, Moho::SPhysConstantsSerializer::Serialize)
     *
     * What it does:
     * Saves the reflected `mGravity` vector for `SPhysConstants`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00699ED0 (FUN_00699ED0, Moho::SPhysConstantsSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `SPhysConstants` RTTI load/save callbacks.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SPhysConstantsSerializer, mLoadCallback) == 0x0C,
    "SPhysConstantsSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SPhysConstantsSerializer, mSaveCallback) == 0x10,
    "SPhysConstantsSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SPhysConstantsSerializer) == 0x14, "SPhysConstantsSerializer size must be 0x14");
} // namespace moho
