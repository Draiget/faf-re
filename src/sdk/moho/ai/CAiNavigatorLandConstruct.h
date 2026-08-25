#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class SerConstructResult;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E1C0F0
   * COL:  0x00E7162C
   */
  class CAiNavigatorLandConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC7A0 (FUN_00BCC7A0, dynamic initializer for the global
     * `CAiNavigatorLandConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly, then
     * installs `??_7CAiNavigatorLandConstruct@Moho@@6B@` -- no eager
     * `RegisterConstructFunction()`/`Init()` call exists here.
     */
    CAiNavigatorLandConstruct();

    /**
     * Address: 0x005A4730 (FUN_005A4730, construct callback)
     *
     * What it does:
     * Allocates one `CAiNavigatorLand` and publishes it as unowned construct
     * result payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005A7DF0 (FUN_005A7DF0, delete callback)
     *
     * What it does:
     * Deletes one constructed `CAiNavigatorLand` object when present.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005A73B0 (FUN_005A73B0, gpg::SerConstructHelper_CAiNavigatorLand::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiNavigatorLand RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiNavigatorLandConstruct, mConstructCallback) == 0x0C,
    "CAiNavigatorLandConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mDeleteCallback) == 0x10,
    "CAiNavigatorLandConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorLandConstruct) == 0x14, "CAiNavigatorLandConstruct size must be 0x14");
} // namespace moho
