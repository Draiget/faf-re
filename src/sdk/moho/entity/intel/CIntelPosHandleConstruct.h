#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E3630C
   * COL:  0x00E8FFF8
   */
  class CIntelPosHandleConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDCCB0 (FUN_00BDCCB0, dynamic initializer for the global
     * `CIntelPosHandleConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields.
     */
    CIntelPosHandleConstruct();

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
     * Address: 0x0076FCB0 (FUN_0076FCB0)
     *
     * What it does:
     * Deleting-teardown callback: invokes `CIntelPosHandle::Destroy(1)` for
     * one runtime object when the pointer lane is non-null. (Confirmed
     * Pos-side by xref evidence: all callers of 0x0076FCB0 sit in the
     * 0x76F2xx/0x76FAxx range and this class's own dynamic initializer
     * 0xBDCCB0 -- never near CIntelCounterHandle's 0x76F8xx/0x76FBxx code.)
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0076FA80 (FUN_0076FA80, gpg::SerConstructHelper_CIntelPosHandle::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CIntelPosHandle RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CIntelPosHandleConstruct, mNext) == 0x04, "CIntelPosHandleConstruct::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelPosHandleConstruct, mPrev) == 0x08, "CIntelPosHandleConstruct::mPrev offset must be 0x08"
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
