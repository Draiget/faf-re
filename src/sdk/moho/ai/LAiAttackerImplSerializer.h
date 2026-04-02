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
   * VFTABLE: 0x00E1EAC4
   * COL: 0x00E75904
   */
  class LAiAttackerImplSerializer
  {
  public:
    /**
     * Address: 0x005D61A0 (FUN_005D61A0, Moho::LAiAttackerImplSerializer::Deserialize)
     *
     * What it does:
     * Loads the `CAiAttackerImpl` link stored by `LAiAttackerImpl`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005D61D0 (FUN_005D61D0, Moho::LAiAttackerImplSerializer::Serialize)
     *
     * What it does:
     * Saves the `CAiAttackerImpl` link stored by `LAiAttackerImpl`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DBF80 (FUN_005DBF80)
     *
     * What it does:
     * Binds load/save serializer callbacks into `LAiAttackerImpl` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(LAiAttackerImplSerializer, mHelperNext) == 0x04, "LAiAttackerImplSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(LAiAttackerImplSerializer, mHelperPrev) == 0x08, "LAiAttackerImplSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(LAiAttackerImplSerializer, mLoadCallback) == 0x0C, "LAiAttackerImplSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(LAiAttackerImplSerializer, mSaveCallback) == 0x10, "LAiAttackerImplSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(LAiAttackerImplSerializer) == 0x14, "LAiAttackerImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCE850 (FUN_00BCE850, register_LAiAttackerImplSerializer)
   *
   * What it does:
   * Constructs the recovered `LAiAttackerImpl` serializer helper and installs
   * process-exit cleanup.
   */
  void register_LAiAttackerImplSerializer();
} // namespace moho
