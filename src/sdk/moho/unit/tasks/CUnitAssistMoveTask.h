#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class Unit;

  /**
   * Runtime layout evidence:
   * - `Moho::Unit::NeedsPickup` (0x005F0E80) reads `mUnit` at +0x1C.
   */
  class CUnitAssistMoveTask
  {
  public:
    std::uint8_t mPad00_1B[0x1C];
    Unit* mUnit; // +0x1C
    std::uint8_t mPad20_67[0x48];
  };

  static_assert(offsetof(CUnitAssistMoveTask, mUnit) == 0x1C, "CUnitAssistMoveTask::mUnit offset must be 0x1C");
  static_assert(sizeof(CUnitAssistMoveTask) == 0x68, "CUnitAssistMoveTask size must be 0x68");
} // namespace moho
