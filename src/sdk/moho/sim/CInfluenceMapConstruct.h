#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CInfluenceMapConstruct
  {
  public:
    /**
     * Address: 0x00718AE0 (FUN_00718AE0, gpg::SerConstructHelper_CInfluenceMap::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CInfluenceMap RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CInfluenceMapConstruct, mHelperNext) == 0x04, "CInfluenceMapConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CInfluenceMapConstruct, mHelperPrev) == 0x08, "CInfluenceMapConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CInfluenceMapConstruct, mConstructCallback) == 0x0C,
    "CInfluenceMapConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CInfluenceMapConstruct, mDeleteCallback) == 0x10,
    "CInfluenceMapConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CInfluenceMapConstruct) == 0x14, "CInfluenceMapConstruct size must be 0x14");
} // namespace moho
