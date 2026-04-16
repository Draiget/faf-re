#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  struct SerHelperBase;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E3630C
   * COL:  0x00E8FFF8
   */
  class CIntelPosHandleConstruct
  {
  public:
    /**
     * Address: 0x0076F350 (FUN_0076F350, Moho::CIntelPosHandleConstruct::Construct)
     *
     * What it does:
     * Allocates one `CIntelPosHandle` runtime object, zero-initializes its
     * fields through constructor semantics, and returns it as an unowned
     * construct-result payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x0076FA80 (FUN_0076FA80, gpg::SerConstructHelper_CIntelPosHandle::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CIntelPosHandle RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CIntelPosHandleConstruct, mHelperLinks) == 0x04, "CIntelPosHandleConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelPosHandleConstruct, mConstructCallback) == 0x0C,
    "CIntelPosHandleConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelPosHandleConstruct, mDeleteCallback) == 0x10,
    "CIntelPosHandleConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelPosHandleConstruct) == 0x14, "CIntelPosHandleConstruct size must be 0x14");
} // namespace moho

