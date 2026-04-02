#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CFireWeaponTask;

  /**
   * Address: 0x00BD8890 (FUN_00BD8890, register_CFireWeaponTaskSerializer)
   *
   * What it does:
   * Forces `CFireWeaponTaskSerializer` helper registration and schedules exit
   * cleanup.
   */
  void register_CFireWeaponTaskSerializer();

  /**
   * Address: 0x00BFE710 (FUN_00BFE710, cleanup_CFireWeaponTaskSerializer)
   *
   * What it does:
   * Restores the serializer helper node to a self-linked singleton lane during
   * process exit.
   */
  void cleanup_CFireWeaponTaskSerializer();

  class CFireWeaponTaskSerializer
  {
  public:
    /**
     * Address: 0x006D3EF0 (FUN_006D3EF0, Moho::CFireWeaponTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CFireWeaponTask::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D3F00 (FUN_006D3F00, Moho::CFireWeaponTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CFireWeaponTask::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DB850 (FUN_006DB850, Moho::CFireWeaponTaskSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `CFireWeaponTask` load/save callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(CFireWeaponTaskSerializer, mHelperNext) == 0x04, "CFireWeaponTaskSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CFireWeaponTaskSerializer, mHelperPrev) == 0x08, "CFireWeaponTaskSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CFireWeaponTaskSerializer, mDeserialize) == 0x0C, "CFireWeaponTaskSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CFireWeaponTaskSerializer, mSerialize) == 0x10, "CFireWeaponTaskSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CFireWeaponTaskSerializer) == 0x14, "CFireWeaponTaskSerializer size must be 0x14");
} // namespace moho
