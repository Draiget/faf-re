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
   * VFTABLE: 0x00E1B7FC
   * COL:  0x00E70D48
   */
  class CAiBuilderImplConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC2E0 (FUN_00BCC2E0, dynamic initializer for the global
     * `CAiBuilderImplConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: this address calls `gpg::SerHelperBase::SerHelperBase()`
     * directly (`__imp_??0SerHelperBase@gpg@@QAE@XZ`), then installs
     * `??_7CAiBuilderImplConstruct@Moho@@6B@` (the more-derived vtable,
     * standard base-then-derived ctor chaining), sets both callback fields (the
     * compiler then registers the destructor with `atexit`) -- it does NOT
     * eagerly call `RegisterConstructFunction()`/`Init()`.
     */
    CAiBuilderImplConstruct();

    /**
     * Address: 0x00BF6AC0 (FUN_00BF6AC0, dynamic atexit destructor for `gCAiBuilderImplConstruct`)
     *
     * What it does:
     * Unlinks this helper node from the serializer-helper list (the
     * `TDatListItem` base destructor). The compiler registers it with
     * `atexit` from the global's dynamic initializer (0x00BCC2E0).
     * `FUN_0059FD20` and `FUN_0059FD50` are
     * unreferenced out-of-line copies of the same body.
     */
    ~CAiBuilderImplConstruct();

    /**
     * Address: 0x0059FD80 (FUN_0059FD80, construct callback)
     *
     * What it does:
     * Allocates one `CAiBuilderImpl` and publishes it as unowned construct
     * result payload.
     */
    static void Construct(
      gpg::ReadArchive* archive, int version, gpg::RRef* ownerRef, gpg::SerConstructResult* result
    );

    /**
     * Address: 0x005A1C80 (FUN_005A1C80, delete callback)
     *
     * What it does:
     * Releases one `CAiBuilderImpl` object created by construct callback
     * lanes.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005A0650 (FUN_005A0650, gpg::SerConstructHelper_CAiBuilderImpl::Init)
     *
     * What it does:
     * Lazily resolves CAiBuilderImpl RTTI and installs construct/delete
     * callbacks. Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this
     * helper is drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiBuilderImplConstruct, mConstructCallback) == 0x0C,
    "CAiBuilderImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiBuilderImplConstruct, mDeleteCallback) == 0x10,
    "CAiBuilderImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiBuilderImplConstruct) == 0x14, "CAiBuilderImplConstruct size must be 0x14");
} // namespace moho
