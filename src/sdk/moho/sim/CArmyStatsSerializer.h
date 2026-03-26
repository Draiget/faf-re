#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CArmyStatsSerializer
  {
  public:
    /**
     * Address: 0x0070F5E0 (FUN_0070F5E0, gpg::SerSaveLoadHelper_CArmyStats::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CArmyStats RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CArmyStatsSerializer, mHelperNext) == 0x04, "CArmyStatsSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CArmyStatsSerializer, mHelperPrev) == 0x08, "CArmyStatsSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CArmyStatsSerializer, mLoadCallback) == 0x0C, "CArmyStatsSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyStatsSerializer, mSaveCallback) == 0x10, "CArmyStatsSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyStatsSerializer) == 0x14, "CArmyStatsSerializer size must be 0x14");
} // namespace moho
