#pragma once

#include <cstddef>

#include "moho/task/CCommandTask.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E202C0
   * COL: 0x00E789EC
   * Source hint: c:\work\rts\main\code\src\sim\AiUnitCommands.cpp
   *
   * Task representing a unit being built by a constructor.
   * Derives from CCommandTask; binary size is 0x30 (no extra fields).
   * Full virtual method recovery pending.
   */
  class CUnitGetBuiltTask : public CCommandTask
  {
  public:
    ~CUnitGetBuiltTask() override;
  };

  static_assert(sizeof(CUnitGetBuiltTask) == 0x30, "CUnitGetBuiltTask size must be 0x30");
} // namespace moho
