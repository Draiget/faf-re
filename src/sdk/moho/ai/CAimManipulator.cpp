// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/CAimManipulator.h"

#include <cmath>

bool moho::dbg_Ballistics = false;
gpg::RType* moho::CAimManipulator::sType = nullptr;

namespace
{
  /**
   * Address: 0x00425110 (FUN_00425110, func_round_0)
   *
   * float
   *
   * IDA signature:
   * int __cdecl func_round_0(float a1);
   *
   * What it does:
   * Applies x87 `frndint`-style rounding and increments when the original
   * value is greater than the rounded lane.
   */
  [[nodiscard]] int RoundFrndintAdjustUp(const float value)
  {
    const float rounded = std::nearbyintf(value);
    return static_cast<int>(rounded) + ((value > rounded) ? 1 : 0);
  }
} // namespace

/**
 * Address: 0x00633730 (FUN_00633730, Moho::CAimManipulator::MemberDeserialize)
 *
 * What it does:
 * Placeholder lane for full CAimManipulator state deserialization recovery.
 */
void moho::CAimManipulator::MemberDeserialize(CAimManipulator* const, gpg::ReadArchive* const)
{}

/**
 * Address: 0x006339D0 (FUN_006339D0, Moho::CAimManipulator::MemberSerialize)
 *
 * What it does:
 * Placeholder lane for full CAimManipulator state serialization recovery.
 */
void moho::CAimManipulator::MemberSerialize(const CAimManipulator* const, gpg::WriteArchive* const)
{}
