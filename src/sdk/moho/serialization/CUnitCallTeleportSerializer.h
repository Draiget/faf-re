#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallTeleport;

  class CUnitCallTeleportSerializer
  {
  public:
    /**
     * Address: 0x006011F0 (FUN_006011F0, Moho::CUnitCallTeleportSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitCallTeleport::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00601200 (FUN_00601200, Moho::CUnitCallTeleportSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitCallTeleport::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00602530 (FUN_00602530)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `CUnitCallTeleport` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext; // +0x04
    gpg::SerHelperBase* mHelperPrev; // +0x08
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CUnitCallTeleportSerializer, mHelperNext) == 0x04,
    "CUnitCallTeleportSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCallTeleportSerializer, mHelperPrev) == 0x08,
    "CUnitCallTeleportSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitCallTeleportSerializer, mDeserialize) == 0x0C,
    "CUnitCallTeleportSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCallTeleportSerializer, mSerialize) == 0x10,
    "CUnitCallTeleportSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCallTeleportSerializer) == 0x14, "CUnitCallTeleportSerializer size must be 0x14");

  /**
   * Address: 0x00BF9740 (FUN_00BF9740, cleanup_CUnitCallTeleportSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallTeleportSerializer();

  /**
   * Address: 0x00BCFD20 (FUN_00BCFD20, register_CUnitCallTeleportSerializer)
   *
   * What it does:
   * Initializes `CUnitCallTeleport` serializer callback pointers and schedules
   * process-exit helper unlink cleanup.
   */
  void register_CUnitCallTeleportSerializer();
} // namespace moho

