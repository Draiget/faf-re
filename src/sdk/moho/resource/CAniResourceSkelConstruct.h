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
   * VFTABLE: 0x00E16350
   * COL: 0x00E6A8B0
   */
  class CAniResourceSkelConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC90B0 (FUN_00BC90B0, register_CAniResourceSkelConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields.
     */
    CAniResourceSkelConstruct();

    /**
     * Address: 0x00BF3BB0 (FUN_00BF3BB0, Moho::CAniResourceSkelConstruct::~CAniResourceSkelConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BC90B0) as the global's `atexit` teardown.
     */
    ~CAniResourceSkelConstruct();

    /**
     * Address: 0x005388C0 (FUN_005388C0, Moho::CAniResourceSkelConstruct::Construct)
     *
     * What it does:
     * Reads one model path from archive, resolves/loads the referenced SCM
     * resource, acquires its shared skeleton payload, and forwards it into the
     * construct result as shared `CAniSkel` content.
     */
    static void Construct(gpg::ReadArchive* archive, int objectStorage, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x00539B80 (FUN_00539B80, Moho::CAniResourceSkelConstruct::Deconstruct)
     *
     * What it does:
     * Deleting-teardown callback: dispatches through the runtime object's own
     * vtable slot 0 (scalar deleting destructor) with the deleting flag set,
     * when the object pointer is non-null. Type-erased in the binary -- the
     * concrete payload type is whatever `Construct`'s archive-owned raw path
     * produces, independent of the shared-`CAniSkel` result path.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00539580 (FUN_00539580, gpg::SerConstructHelper_CAniResourceSkel::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into `CAniResourceSkel` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAniResourceSkelConstruct, mNext) == 0x04, "CAniResourceSkelConstruct::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAniResourceSkelConstruct, mPrev) == 0x08, "CAniResourceSkelConstruct::mPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAniResourceSkelConstruct, mConstructCallback) == 0x0C,
    "CAniResourceSkelConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAniResourceSkelConstruct, mDeleteCallback) == 0x10,
    "CAniResourceSkelConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAniResourceSkelConstruct) == 0x14, "CAniResourceSkelConstruct size must be 0x14");
} // namespace moho
