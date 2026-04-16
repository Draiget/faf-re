#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/audio/SParamKey.h"

namespace moho
{
  class SParamKeySerializer
  {
  public:
    /**
     * Address: 0x004DEFD0 (FUN_004DEFD0, Moho::SParamKeySerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, SParamKey* key);

    /**
     * Address: 0x004DF010 (FUN_004DF010, Moho::SParamKeySerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, SParamKey* key);

    /**
     * Address: 0x004E1600 (FUN_004E1600)
     *
     * What it does:
     * Binds `SParamKey` RTTI serializer callbacks (`serLoadFunc_` / `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

    /**
       * Address: 0x00BF0E50 (FUN_00BF0E50)
     */
    virtual ~SParamKeySerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  /**
    * Alias of FUN_00BF0E50 (non-canonical helper lane).
   */
  gpg::SerHelperBase* cleanup_SParamKeySerializer();

  /**
   * Address: 0x00BC6860 (FUN_00BC6860, register_SParamKeySerializer)
   */
  void register_SParamKeySerializer();

  static_assert(
    offsetof(SParamKeySerializer, mHelperNext) == 0x04, "SParamKeySerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SParamKeySerializer, mHelperPrev) == 0x08, "SParamKeySerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SParamKeySerializer, mDeserialize) == 0x0C, "SParamKeySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SParamKeySerializer, mSerialize) == 0x10, "SParamKeySerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SParamKeySerializer) == 0x14, "SParamKeySerializer size must be 0x14");
} // namespace moho
