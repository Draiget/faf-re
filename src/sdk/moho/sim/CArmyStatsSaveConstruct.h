#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CArmyStatsSaveConstruct
  {
  public:
    /**
     * Address: 0x0070F4E0 (FUN_0070F4E0, gpg::SerSaveConstructHelper_CArmyStats::Init)
     *
     * What it does:
     * Binds save-construct-args callback into CArmyStats RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(CArmyStatsSaveConstruct, mHelperNext) == 0x04,
    "CArmyStatsSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CArmyStatsSaveConstruct, mHelperPrev) == 0x08,
    "CArmyStatsSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CArmyStatsSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CArmyStatsSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CArmyStatsSaveConstruct) == 0x10, "CArmyStatsSaveConstruct size must be 0x10");
} // namespace moho
