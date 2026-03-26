#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CArmyStatsConstruct
  {
  public:
    /**
     * Address: 0x0070F560 (FUN_0070F560, gpg::SerConstructHelper_CArmyStats::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CArmyStats RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CArmyStatsConstruct, mHelperNext) == 0x04, "CArmyStatsConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CArmyStatsConstruct, mHelperPrev) == 0x08, "CArmyStatsConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CArmyStatsConstruct, mConstructCallback) == 0x0C,
    "CArmyStatsConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyStatsConstruct, mDeleteCallback) == 0x10, "CArmyStatsConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyStatsConstruct) == 0x14, "CArmyStatsConstruct size must be 0x14");
} // namespace moho
