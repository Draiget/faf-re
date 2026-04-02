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
   * VFTABLE: 0x00E1C100
   * COL:  0x00E71580
   */
  class CAiNavigatorLandSerializer
  {
  public:
    /**
     * Address: 0x005A47D0 (FUN_005A47D0, Moho::CAiNavigatorLandSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiNavigatorLand::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A47E0 (FUN_005A47E0, Moho::CAiNavigatorLandSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiNavigatorLand::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A7430 (FUN_005A7430)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiNavigatorLand RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiNavigatorLandSerializer, mHelperNext) == 0x04,
    "CAiNavigatorLandSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiNavigatorLandSerializer, mHelperPrev) == 0x08,
    "CAiNavigatorLandSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiNavigatorLandSerializer, mLoadCallback) == 0x0C,
    "CAiNavigatorLandSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorLandSerializer, mSaveCallback) == 0x10,
    "CAiNavigatorLandSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorLandSerializer) == 0x14, "CAiNavigatorLandSerializer size must be 0x14");

  /**
   * Address: 0x00BCC7E0 (FUN_00BCC7E0, register_CAiNavigatorLandSerializer)
   *
   * What it does:
   * Initializes the global CAiNavigatorLand serializer helper callbacks and
   * installs process-exit cleanup.
   */
  void register_CAiNavigatorLandSerializer();
} // namespace moho
