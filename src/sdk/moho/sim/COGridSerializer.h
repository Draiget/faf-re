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
   * VFTABLE: 0x00E3195C
   * COL: 0x00E8E5B4
   */
  class COGridSerializer
  {
  public:
    /**
     * Address: 0x00722CC0 (FUN_00722CC0, Moho::COGridSerializer::Deserialize)
     *
     * What it does:
     * Registers one pre-created `COGrid` pointer instance in read-archive tracking.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00722D00 (FUN_00722D00, Moho::COGridSerializer::Serialize)
     *
     * What it does:
     * Publishes one pre-created `COGrid` pointer instance into write-archive tracking.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00722F90 (FUN_00722F90, gpg::SerSaveLoadHelper_COGrid::Init)
     *
     * What it does:
     * Resolves `COGrid` RTTI and installs serializer load/save callback lanes.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(COGridSerializer, mHelperNext) == 0x04, "COGridSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(COGridSerializer, mHelperPrev) == 0x08, "COGridSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(COGridSerializer, mLoadCallback) == 0x0C, "COGridSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(COGridSerializer, mSaveCallback) == 0x10, "COGridSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(COGridSerializer) == 0x14, "COGridSerializer size must be 0x14");

  /**
   * Address: 0x00BDAAB0 (FUN_00BDAAB0, register_COGridSerializer)
   *
   * What it does:
   * Materializes startup serializer helper state for `COGrid` and installs
   * process-exit teardown.
   */
  void register_COGridSerializer();
} // namespace moho
