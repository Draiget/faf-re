#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1B3F8
   * COL:  0x00E70430
   */
  class IAiCommandDispatchImplConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCBEC0 (FUN_00BCBEC0, dynamic initializer for the global
     * `IAiCommandDispatchImplConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly, then
     * installs `??_7IAiCommandDispatchImplConstruct@Moho@@6B@` -- no eager
     * `RegisterConstructFunction()`/`Init()` call exists here. The `atexit`
     * argument is the real mangled destructor
     * (`??1IAiCommandDispatchImplConstruct@Moho@@QAE@@Z`), not a free
     * function.
     */
    IAiCommandDispatchImplConstruct();

    /**
     * Address: 0x00BF66C0 (FUN_00BF66C0, Moho::IAiCommandDispatchImplConstruct::~IAiCommandDispatchImplConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCBEC0) as the global's `atexit` teardown.
     * `FUN_005992C0` and `FUN_005992F0` are duplicate-emission twins of this
     * exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
     * addresses); neither has a distinct source-level body of its own.
     */
    ~IAiCommandDispatchImplConstruct();

    /**
     * Address: 0x00599320 (FUN_00599320, Moho::IAiCommandDispatchImplConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback arguments into
     * `IAiCommandDispatchImpl::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005999D0 (FUN_005999D0, Moho::IAiCommandDispatchImplConstruct::Deconstruct)
     *
     * What it does:
     * Deletes one recovered command-dispatch object through its deleting
     * destructor lane.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x00599650 (FUN_00599650, gpg::SerConstructHelper_IAiCommandDispatchImpl::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into IAiCommandDispatchImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructFunc; // +0x0C
    gpg::RType::delete_func_t mDeleteFunc;       // +0x10
  };

  static_assert(
    offsetof(IAiCommandDispatchImplConstruct, mConstructFunc) == 0x0C,
    "IAiCommandDispatchImplConstruct::mConstructFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplConstruct, mDeleteFunc) == 0x10,
    "IAiCommandDispatchImplConstruct::mDeleteFunc offset must be 0x10"
  );
  static_assert(sizeof(IAiCommandDispatchImplConstruct) == 0x14, "IAiCommandDispatchImplConstruct size must be 0x14");
} // namespace moho
