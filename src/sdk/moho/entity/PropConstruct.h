#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2F4E4
   * COL: 0x00E8D85C
   */
  class PropConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD98D0 (FUN_00BD98D0, dynamic initializer for the global
     * `PropConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the construct/delete callback fields. Plain unlink atexit
     * target, modeled as the compiler's implicit static-destructor
     * registration.
     */
    PropConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~PropConstruct();

    /**
     * Address: 0x006FA9E0 (FUN_006FA9E0, gpg::SerConstructHelper_Prop::Init)
     *
     * What it does:
     * Asserts `Prop`'s reflected construct callback is not already bound,
     * then installs the construct/delete callback lanes into `Prop` RTTI
     * (unconditional on the delete lane -- the binary does not assert it).
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(PropConstruct, mConstructCallback) == 0x0C, "PropConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(offsetof(PropConstruct, mDeleteCallback) == 0x10, "PropConstruct::mDeleteCallback offset must be 0x10");
  static_assert(sizeof(PropConstruct) == 0x14, "PropConstruct size must be 0x14");
} // namespace moho
