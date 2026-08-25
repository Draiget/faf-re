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
   * VFTABLE: 0x00E1EAD4
   * COL: 0x00E75858
   */
  class CAiAttackerImplConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005D8390 (FUN_005D8390)
     *
     * What it does:
     * Constructs a recovered `CAiAttackerImpl` object for archive loading.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005DEB50 (FUN_005DEB50)
     *
     * What it does:
     * Deletes one recovered `CAiAttackerImpl` object.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x00BCE890 (FUN_00BCE890, dynamic initializer for the global
     * `CAiAttackerImplConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CAiAttackerImplConstruct@Moho@@6B@` -- no eager
     * `Init()` call exists here, and this class has no user-declared
     * destructor (the real binary explicitly registers `atexit(&sub_BF8400)`
     * instead).
     */
    CAiAttackerImplConstruct();

    /**
     * Address: 0x005DC050 (FUN_005DC050)
     *
     * What it does:
     * Lazily resolves `CAiAttackerImpl` RTTI and installs construct/delete
     * callbacks. Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this
     * helper is drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(CAiAttackerImplConstruct, mConstructCallback) == 0x0C, "CAiAttackerImplConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CAiAttackerImplConstruct, mDeleteCallback) == 0x10, "CAiAttackerImplConstruct::mDeleteCallback offset must be 0x10");
  static_assert(sizeof(CAiAttackerImplConstruct) == 0x14, "CAiAttackerImplConstruct size must be 0x14");

  /**
   * Address: 0x00BCE890 caller lane (`CAiAttackerImplTypeInfo.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `CAiAttackerImplConstruct` singleton from an explicit registration
   * sequence. `gCAiAttackerImplConstruct` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `CAiAttackerImplTypeInfo.cpp`'s existing
   * bootstrap sequence does not need editing.
   */
  int register_CAiAttackerImplConstruct();
} // namespace moho
