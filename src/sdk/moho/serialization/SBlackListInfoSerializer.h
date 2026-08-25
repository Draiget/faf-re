#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2E268
   * COL: 0x00E87DE0
   */
  class SBlackListInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8830 (FUN_00BD8830, register_SBlackListInfoSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target (0x00BFE680) is
     * a plain unlink thunk, not a mangled destructor, so it is modeled as
     * the compiler's implicit static-destructor registration rather than
     * an explicit call.
     */
    SBlackListInfoSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SBlackListInfoSerializer();

    /**
     * Address: 0x006D3980 (FUN_006D3980, Moho::SBlackListInfoSerializer::Deserialize)
     *
     * What it does:
     * Loads the reflected `WeakPtr<Entity>` and integer lanes for `SBlackListInfo`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D3990 (FUN_006D3990, Moho::SBlackListInfoSerializer::Serialize)
     *
     * What it does:
     * Saves the reflected `WeakPtr<Entity>` and integer lanes for `SBlackListInfo`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DB560 (FUN_006DB560, gpg::SerSaveLoadHelper<Moho::SBlackListInfo>::Init)
     *
     * What it does:
     * Binds `SBlackListInfo` RTTI load/save callbacks.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(SBlackListInfoSerializer, mDeserialize) == 0x0C,
    "SBlackListInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SBlackListInfoSerializer, mSerialize) == 0x10,
    "SBlackListInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SBlackListInfoSerializer) == 0x14, "SBlackListInfoSerializer size must be 0x14");
} // namespace moho
