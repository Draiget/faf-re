#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCaptureTask;

  /**
   * Type-info owner for `CUnitCaptureTask`.
   */
  class CUnitCaptureTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00605400 (FUN_00605400, Moho::CUnitCaptureTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitCaptureTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006054A0 (FUN_006054A0, Moho::CUnitCaptureTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitCaptureTask` in caller-provided storage and returns
     * a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);
  };

  static_assert(sizeof(CUnitCaptureTaskTypeInfo) == 0x64, "CUnitCaptureTaskTypeInfo size must be 0x64");
} // namespace moho
