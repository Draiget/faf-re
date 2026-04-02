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
   * VFTABLE: 0x00E1C6E4
   * COL:  0x00E723F0
   */
  class CAiPathNavigatorSerializer
  {
  public:
    /**
     * Address: 0x005AFBE0 (FUN_005AFBE0, Moho::CAiPathNavigatorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiPathNavigator::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005AFC00 (FUN_005AFC00, Moho::CAiPathNavigatorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiPathNavigator::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B0130 (FUN_005B0130)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathNavigator RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiPathNavigatorSerializer, mHelperNext) == 0x04,
    "CAiPathNavigatorSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mHelperPrev) == 0x08,
    "CAiPathNavigatorSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mLoadCallback) == 0x0C,
    "CAiPathNavigatorSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mSaveCallback) == 0x10,
    "CAiPathNavigatorSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPathNavigatorSerializer) == 0x14, "CAiPathNavigatorSerializer size must be 0x14");

  /**
   * Address: 0x00BCD040 (FUN_00BCD040, register_CAiPathNavigatorSerializer)
   *
   * What it does:
   * Initializes the global path navigator serializer helper callbacks and
   * installs process-exit cleanup.
   */
  int register_CAiPathNavigatorSerializer();
} // namespace moho
