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
   * VFTABLE: 0x00E1C068
   * COL:  0x00E71870
   */
  class IAiNavigatorSerializer
  {
  public:
    /**
     * Address: 0x005A32D0 (FUN_005A32D0, Moho::IAiNavigatorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `IAiNavigator::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A32E0 (FUN_005A32E0, Moho::IAiNavigatorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `IAiNavigator::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A71A0 (FUN_005A71A0)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiNavigator RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(IAiNavigatorSerializer, mHelperNext) == 0x04,
    "IAiNavigatorSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(IAiNavigatorSerializer, mHelperPrev) == 0x08,
    "IAiNavigatorSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(IAiNavigatorSerializer, mLoadCallback) == 0x0C,
    "IAiNavigatorSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiNavigatorSerializer, mSaveCallback) == 0x10,
    "IAiNavigatorSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiNavigatorSerializer) == 0x14, "IAiNavigatorSerializer size must be 0x14");

  /**
   * Address: 0x00BCC6C0 (FUN_00BCC6C0, register_IAiNavigatorSerializer)
   *
   * What it does:
   * Initializes the global IAiNavigator serializer helper callbacks and
   * installs process-exit cleanup.
   */
  void register_IAiNavigatorSerializer();
} // namespace moho

