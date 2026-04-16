#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitPatrolTask;

  /**
   * Type-info owner for `CUnitPatrolTask`.
   */
  class CUnitPatrolTaskTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    void Init() override;
  };

  /**
   * Address: 0x0061AB10 (FUN_0061AB10, preregister_CUnitPatrolTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitPatrolTaskTypeInfo` reflection
   * lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitPatrolTaskTypeInfo();

  static_assert(sizeof(CUnitPatrolTaskTypeInfo) == 0x64, "CUnitPatrolTaskTypeInfo size must be 0x64");
} // namespace moho
