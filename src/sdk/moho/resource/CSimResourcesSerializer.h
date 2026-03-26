#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E171E4
   * COL: 0x00E6B64C
   */
  class CSimResourcesSerializer
  {
  public:
    /**
     * Address: 0x00547870 (FUN_00547870, gpg::SerSaveLoadHelper_CSimResources::Init)
     *
     * What it does:
     * Binds `CSimResources` load/save serializer callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CSimResourcesSerializer, mHelperNext) == 0x04,
    "CSimResourcesSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mHelperPrev) == 0x08,
    "CSimResourcesSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mLoadCallback) == 0x0C,
    "CSimResourcesSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mSaveCallback) == 0x10,
    "CSimResourcesSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CSimResourcesSerializer) == 0x14, "CSimResourcesSerializer size must be 0x14");
} // namespace moho
