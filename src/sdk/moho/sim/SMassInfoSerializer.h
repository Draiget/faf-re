#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class SMassInfoSerializer
  {
  public:
    /**
     * Address: 0x00585E10 (FUN_00585E10, Moho::SMassInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SMassInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00585E20 (FUN_00585E20, Moho::SMassInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SMassInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00591B90 (FUN_00591B90)
     *
     * What it does:
     * Binds load/save serializer callbacks into SMassInfo RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(SMassInfoSerializer, mHelperNext) == 0x04, "SMassInfoSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SMassInfoSerializer, mHelperPrev) == 0x08, "SMassInfoSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SMassInfoSerializer, mLoadCallback) == 0x0C, "SMassInfoSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(SMassInfoSerializer, mSaveCallback) == 0x10, "SMassInfoSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(SMassInfoSerializer) == 0x14, "SMassInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BCB700 (FUN_00BCB700, register_SMassInfoSerializer)
   *
   * What it does:
   * Initializes the global SMassInfo serializer helper callbacks and
   * installs process-exit cleanup.
   */
  void register_SMassInfoSerializer();
} // namespace moho
