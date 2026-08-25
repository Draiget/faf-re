#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E1F4AC
   * COL:  0x00E76564
   */
  class CAiTransportImplConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCEF10 (FUN_00BCEF10, dynamic initializer for the global
     * `CAiTransportImplConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly, then
     * installs `??_7CAiTransportImplConstruct@Moho@@6B@` -- no eager
     * `RegisterConstructFunction()`/`Init()` call exists here. The `atexit`
     * argument is the real mangled destructor
     * (`??1CAiTransportImplConstruct@Moho@@QAE@@Z`), not a free function.
     */
    CAiTransportImplConstruct();

    /**
     * Address: 0x00BF8C40 (FUN_00BF8C40, Moho::CAiTransportImplConstruct::~CAiTransportImplConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCEF10) as the global's `atexit` teardown.
     * `FUN_005E8490` and `FUN_005E84C0` are duplicate-emission twins of this
     * exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
     * addresses); neither has a distinct source-level body of its own.
     */
    ~CAiTransportImplConstruct();

    /**
     * Address: 0x005E84F0 (FUN_005E84F0, Moho::CAiTransportImplConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `CAiTransportImpl::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005EC380 (FUN_005EC380, Moho::CAiTransportImplConstruct::Deconstruct)
     *
     * What it does:
     * Deletes one constructed `CAiTransportImpl` object.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x005E9BB0 (FUN_005E9BB0, gpg::SerConstructHelper_CAiTransportImpl::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiTransportImpl RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;   // +0x10
  };

  static_assert(
    offsetof(CAiTransportImplConstruct, mConstructCallback) == 0x0C,
    "CAiTransportImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiTransportImplConstruct, mDeleteCallback) == 0x10,
    "CAiTransportImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiTransportImplConstruct) == 0x14, "CAiTransportImplConstruct size must be 0x14");

  /**
   * Compatibility no-op: `IAiTransport.cpp`'s reflection bootstrap sequence
   * (`IAiTransportReflectionBootstrap`) still calls this by name. See the
   * definition in CAiTransportImplConstruct.cpp for why it no longer needs
   * to do anything.
   */
  void register_CAiTransportImplConstruct();
} // namespace moho
