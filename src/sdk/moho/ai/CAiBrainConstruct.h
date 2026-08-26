#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E19A48
   * COL:  0x00E6E680
   */
  class CAiBrainConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCB3F0 (FUN_00BCB3F0, dynamic initializer for the global
     * `CAiBrainConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields. Confirmed from raw
     * disassembly: this address calls `gpg::SerHelperBase::SerHelperBase()`
     * directly (`__imp_??0SerHelperBase@gpg@@QAE@XZ`), then installs
     * `??_7CAiBrainConstruct@Moho@@6B@` (the more-derived vtable, standard
     * base-then-derived ctor chaining), sets both callback fields, and
     * registers `atexit` cleanup -- it does NOT eagerly call `Init()`. The
     * previously-recovered body here (an eager `RegisterConstructFunction()`
     * call, plus a hand-rolled self-link that bypassed the real
     * `SerHelperBase` base ctor entirely) did not match this evidence.
     *
     * `mDeleteCallback` is bound to `&DeleteConstructedCAiBrain`
     * (CAiBrainConstruct.cpp) -- the typed specialization of the shared
     * generic `delete_func_t` thunk the binary literally stores at this
     * field (`&sub_581890`, instruction 0x00BCB409); see
     * `DeleteConstructedCAiBrain`'s own doc comment for the full vtable-slot
     * equivalence proof. The binary also contains two byte-verified
     * DUPLICATE, UNREACHABLE emissions of this entire constructor
     * (0x00579C60, 0x0057E3B0) -- see the `gCAiBrainConstructStartupHelper`
     * global's doc comment in the .cpp for the evidence; neither needs a
     * separate recovery.
     */
    CAiBrainConstruct();

    /**
     * Address: 0x0057E3E0 (FUN_0057E3E0, gpg::SerConstructHelper_CAiBrain::Init)
     *
     * What it does:
     * Lazily resolves CAiBrain RTTI and installs construct/delete callbacks.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(CAiBrainConstruct, mConstructCallback) == 0x0C,
      "CAiBrainConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CAiBrainConstruct, mDeleteCallback) == 0x10, "CAiBrainConstruct::mDeleteCallback offset must be 0x10");
  static_assert(sizeof(CAiBrainConstruct) == 0x14, "CAiBrainConstruct size must be 0x14");
} // namespace moho
