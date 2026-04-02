#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class IAiAttackerSerializer
  {
  public:
    /**
     * Address: 0x005DE8D0 (FUN_005DE8D0, sub_5DE8D0)
     *
     * What it does:
     * Loads `IAiAttacker` broadcaster event-list lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DE920 (FUN_005DE920, sub_5DE920)
     *
     * What it does:
     * Saves `IAiAttacker` broadcaster event-list lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DBC90 (FUN_005DBC90)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiAttacker RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IAiAttackerSerializer, mHelperNext) == 0x04, "IAiAttackerSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mHelperPrev) == 0x08, "IAiAttackerSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mLoadCallback) == 0x0C, "IAiAttackerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mSaveCallback) == 0x10, "IAiAttackerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiAttackerSerializer) == 0x14, "IAiAttackerSerializer size must be 0x14");

  /**
   * Address: 0x00BCE7D0 (FUN_00BCE7D0, sub_BCE7D0)
   *
   * What it does:
   * Registers serializer callbacks for `IAiAttacker` and installs process-exit
   * cleanup.
   */
  int register_IAiAttackerSerializer();
} // namespace moho
