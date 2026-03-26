#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class InfluenceGridSerializer
  {
  public:
    /**
     * Address: 0x00719410 (FUN_00719410, gpg::SerSaveLoadHelper_InfluenceGrid::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into InfluenceGrid RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(InfluenceGridSerializer, mHelperNext) == 0x04, "InfluenceGridSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(InfluenceGridSerializer, mHelperPrev) == 0x08, "InfluenceGridSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(InfluenceGridSerializer, mLoadCallback) == 0x0C,
    "InfluenceGridSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(InfluenceGridSerializer, mSaveCallback) == 0x10,
    "InfluenceGridSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(InfluenceGridSerializer) == 0x14, "InfluenceGridSerializer size must be 0x14");
} // namespace moho
