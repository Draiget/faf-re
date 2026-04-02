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
   * VFTABLE: 0x00E1C150
   * COL:  0x00E713D8
   */
  class CAiNavigatorAirSerializer
  {
  public:
    /**
     * Address: 0x005A56D0 (FUN_005A56D0, Moho::CAiNavigatorAirSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiNavigatorAir::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A56E0 (FUN_005A56E0, Moho::CAiNavigatorAirSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiNavigatorAir::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A7550 (FUN_005A7550)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiNavigatorAir RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiNavigatorAirSerializer, mHelperNext) == 0x04,
    "CAiNavigatorAirSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiNavigatorAirSerializer, mHelperPrev) == 0x08,
    "CAiNavigatorAirSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiNavigatorAirSerializer, mLoadCallback) == 0x0C,
    "CAiNavigatorAirSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorAirSerializer, mSaveCallback) == 0x10,
    "CAiNavigatorAirSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorAirSerializer) == 0x14, "CAiNavigatorAirSerializer size must be 0x14");

  /**
   * Address: 0x00BCC880 (FUN_00BCC880, register_CAiNavigatorAirSerializer)
   *
   * What it does:
   * Initializes the global CAiNavigatorAir serializer helper callbacks and
   * installs process-exit cleanup.
   */
  void register_CAiNavigatorAirSerializer();
} // namespace moho

