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
   * VFTABLE: 0x00E1DE38
   * COL:  0x00E748A4
   */
  class CAiSiloBuildImplConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCE110 (FUN_00BCE110, dynamic initializer for the global
     * `CAiSiloBuildImplConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly, then
     * installs `??_7CAiSiloBuildImplConstruct@Moho@@6B@` -- no eager `Init()`
     * call exists here.
     */
    CAiSiloBuildImplConstruct();

    /**
     * Address: 0x00BF7F30 (FUN_00BF7F30, Moho::CAiSiloBuildImplConstruct::~CAiSiloBuildImplConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCE110) as the global's `atexit` teardown.
     */
    ~CAiSiloBuildImplConstruct();

    /**
     * Address: 0x005CF840 (FUN_005CF840, Moho::CAiSiloBuildImplConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `CAiSiloBuildImpl::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005D0870 (FUN_005D0870, Moho::CAiSiloBuildImplConstruct::Deconstruct)
     *
     * What it does:
     * Deletes one constructed `CAiSiloBuildImpl` object.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x005CFEB0 (FUN_005CFEB0, gpg::SerConstructHelper_CAiSiloBuildImpl::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiSiloBuildImpl RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;   // +0x10
  };

  static_assert(
    offsetof(CAiSiloBuildImplConstruct, mConstructCallback) == 0x0C,
    "CAiSiloBuildImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiSiloBuildImplConstruct, mDeleteCallback) == 0x10,
    "CAiSiloBuildImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiSiloBuildImplConstruct) == 0x14, "CAiSiloBuildImplConstruct size must be 0x14");

  /**
   * Compatibility no-op: `CAiSiloBuildImplTypeInfo.cpp`'s reflection
   * bootstrap sequence still calls this by name. See the definition in
   * CAiSiloBuildImplConstruct.cpp for why it no longer needs to do anything.
   */
  int register_CAiSiloBuildImplConstruct();
} // namespace moho
