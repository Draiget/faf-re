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
  };

  static_assert(sizeof(CUnitCaptureTaskTypeInfo) == 0x64, "CUnitCaptureTaskTypeInfo size must be 0x64");
} // namespace moho

