#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Address: 0x00BFE0A0 (FUN_00BFE0A0, cleanup_CUnitMotionSerializer)
   *
   * What it does:
   * Unlinks the `CUnitMotionSerializer` helper from the intrusive serializer
   * helper list and rewires it as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_CUnitMotionSerializer();

  /**
   * Address: 0x00BFE070 (FUN_00BFE070, cleanup_CUnitMotionConstruct)
   *
   * What it does:
   * Unlinks the `CUnitMotionConstruct` helper from the intrusive serializer
   * helper list and rewires it as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_CUnitMotionConstruct();

  /**
   * Address: 0x00BD7240 (FUN_00BD7240, register_CUnitMotionConstruct)
   *
   * What it does:
   * Initializes callback lanes for the global `CUnitMotionConstruct` helper,
   * binds them into CUnitMotion RTTI, and schedules process-exit cleanup.
   */
  int register_CUnitMotionConstruct();

  /**
   * Address: 0x00BD7280 (FUN_00BD7280, register_CUnitMotionSerializer)
   *
   * What it does:
   * Initializes callback lanes for the global `CUnitMotionSerializer` helper,
   * binds them into CUnitMotion RTTI, and schedules process-exit cleanup.
   */
  int register_CUnitMotionSerializer();
} // namespace moho
