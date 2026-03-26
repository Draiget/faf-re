#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class InfluenceMapEntrySerializer
  {
  public:
    /**
     * Address: 0x00718C00 (FUN_00718C00, gpg::SerSaveLoadHelper_InfluenceMapEntry::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into InfluenceMapEntry RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(InfluenceMapEntrySerializer, mHelperNext) == 0x04,
    "InfluenceMapEntrySerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(InfluenceMapEntrySerializer, mHelperPrev) == 0x08,
    "InfluenceMapEntrySerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(InfluenceMapEntrySerializer, mLoadCallback) == 0x0C,
    "InfluenceMapEntrySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(InfluenceMapEntrySerializer, mSaveCallback) == 0x10,
    "InfluenceMapEntrySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(InfluenceMapEntrySerializer) == 0x14, "InfluenceMapEntrySerializer size must be 0x14");
} // namespace moho
