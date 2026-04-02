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
   * VFTABLE: 0x00E3635C
   * COL:  0x00E8FE50
   */
  class CIntelCounterHandleConstruct
  {
  public:
    /**
     * Address: 0x0076FBA0 (FUN_0076FBA0, gpg::SerConstructHelper_CIntelCounterHandle::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CIntelCounterHandle RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CIntelCounterHandleConstruct, mHelperLinks) == 0x04,
    "CIntelCounterHandleConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelCounterHandleConstruct, mConstructCallback) == 0x0C,
    "CIntelCounterHandleConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelCounterHandleConstruct, mDeleteCallback) == 0x10,
    "CIntelCounterHandleConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelCounterHandleConstruct) == 0x14, "CIntelCounterHandleConstruct size must be 0x14");
} // namespace moho

