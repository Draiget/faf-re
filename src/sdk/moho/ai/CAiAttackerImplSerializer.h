#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1EAE4
   * COL: 0x00E757AC
   */
  class CAiAttackerImplSerializer
  {
  public:
    /**
     * Address: 0x005D8430 (FUN_005D8430, Moho::CAiAttackerImplSerializer::Deserialize)
     *
     * What it does:
     * Loads the recovered `CAiAttackerImpl` state payload from the archive.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005D8440 (FUN_005D8440, Moho::CAiAttackerImplSerializer::Serialize)
     *
     * What it does:
     * Saves the recovered `CAiAttackerImpl` state payload to the archive.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DC0D0 (FUN_005DC0D0)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CAiAttackerImpl` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CAiAttackerImplSerializer, mHelperNext) == 0x04, "CAiAttackerImplSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CAiAttackerImplSerializer, mHelperPrev) == 0x08, "CAiAttackerImplSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CAiAttackerImplSerializer, mLoadCallback) == 0x0C, "CAiAttackerImplSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CAiAttackerImplSerializer, mSaveCallback) == 0x10, "CAiAttackerImplSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CAiAttackerImplSerializer) == 0x14, "CAiAttackerImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCE8D0 (FUN_00BCE8D0, register_CAiAttackerImplSerializer)
   *
   * What it does:
   * Constructs the recovered `CAiAttackerImpl` serializer helper and installs
   * process-exit cleanup.
   */
  void register_CAiAttackerImplSerializer();
} // namespace moho
