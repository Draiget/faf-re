#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CArmyStatItemSerializer
  {
  public:
    /**
     * Address: 0x0070B770 (FUN_0070B770, sub_70B770)
     *
     * What it does:
     * Reflection load callback that deserializes `CArmyStatItem` fields.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0070B780 (FUN_0070B780, sub_70B780)
     *
     * What it does:
     * Reflection save callback that serializes `CArmyStatItem` fields.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0070EEE0 (FUN_0070EEE0, gpg::SerSaveLoadHelper_CArmyStatItem::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CArmyStatItem RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CArmyStatItemSerializer, mHelperNext) == 0x04,
    "CArmyStatItemSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CArmyStatItemSerializer, mHelperPrev) == 0x08,
    "CArmyStatItemSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CArmyStatItemSerializer, mLoadCallback) == 0x0C,
    "CArmyStatItemSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyStatItemSerializer, mSaveCallback) == 0x10,
    "CArmyStatItemSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyStatItemSerializer) == 0x14, "CArmyStatItemSerializer size must be 0x14");
} // namespace moho
