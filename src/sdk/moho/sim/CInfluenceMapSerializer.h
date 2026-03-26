#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CInfluenceMapSerializer
  {
  public:
    /**
     * Address: 0x00718B60 (FUN_00718B60, gpg::SerSaveLoadHelper_CInfluenceMap::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CInfluenceMap RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CInfluenceMapSerializer, mHelperNext) == 0x04, "CInfluenceMapSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CInfluenceMapSerializer, mHelperPrev) == 0x08, "CInfluenceMapSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CInfluenceMapSerializer, mLoadCallback) == 0x0C,
    "CInfluenceMapSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CInfluenceMapSerializer, mSaveCallback) == 0x10,
    "CInfluenceMapSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CInfluenceMapSerializer) == 0x14, "CInfluenceMapSerializer size must be 0x14");
} // namespace moho
