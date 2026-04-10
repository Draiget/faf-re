#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  struct SBuildReserveInfo;

  /**
   * Serializer helper for reflected `SBuildReserveInfo` archive callbacks.
   */
  class SBuildReserveInfoSerializer
  {
  public:
    /**
     * Address: 0x00579A70 (FUN_00579A70, Moho::SBuildReserveInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `SBuildReserveInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00579A80 (FUN_00579A80, Moho::SBuildReserveInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `SBuildReserveInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0057E1D0 (FUN_0057E1D0, gpg::SerSaveLoadHelper<Moho::SBuildReserveInfo>::Init lane)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `SBuildReserveInfo` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext; // +0x04
    gpg::SerHelperBase* mHelperPrev; // +0x08
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SBuildReserveInfoSerializer, mHelperNext) == 0x04,
    "SBuildReserveInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SBuildReserveInfoSerializer, mHelperPrev) == 0x08,
    "SBuildReserveInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SBuildReserveInfoSerializer, mDeserialize) == 0x0C,
    "SBuildReserveInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SBuildReserveInfoSerializer, mSerialize) == 0x10,
    "SBuildReserveInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SBuildReserveInfoSerializer) == 0x14, "SBuildReserveInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BF6230 (FUN_00BF6230, Moho::SBuildReserveInfoSerializer::~SBuildReserveInfoSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_SBuildReserveInfoSerializer();

  /**
   * Address: 0x00BCB390 (FUN_00BCB390, register_SBuildReserveInfoSerializer)
   *
   * What it does:
   * Initializes `SBuildReserveInfo` serializer callback pointers and schedules
   * process-exit helper unlink cleanup.
   */
  void register_SBuildReserveInfoSerializer();
} // namespace moho
