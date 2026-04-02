#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  struct SerHelperBase;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1C89C
   * COL:  0x00E72578
   */
  class SContinueInfoSerializer
  {
  public:
    /**
     * Address: 0x005B2290 (FUN_005B2290, Moho::SContinueInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SContinueInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B22A0 (FUN_005B22A0, Moho::SContinueInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SContinueInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B4820 (FUN_005B4820)
     *
     * What it does:
     * Binds load/save callbacks into reflected `SContinueInfo` metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(SContinueInfoSerializer, mHelperNext) == 0x04,
    "SContinueInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SContinueInfoSerializer, mHelperPrev) == 0x08,
    "SContinueInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SContinueInfoSerializer, mLoadCallback) == 0x0C,
    "SContinueInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SContinueInfoSerializer, mSaveCallback) == 0x10,
    "SContinueInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SContinueInfoSerializer) == 0x14, "SContinueInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BCD2F0 (FUN_00BCD2F0, register_SContinueInfoSerializer)
   *
   * What it does:
   * Initializes startup serializer callbacks for `SContinueInfo` and installs
   * process-exit helper unlink cleanup.
   */
  int register_SContinueInfoSerializer();
} // namespace moho
