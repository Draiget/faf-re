#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * Hash key used by the sound-parameter cache lane.
   *
   * Binary shape recovered from `FUN_004DEBB0`, `FUN_004DF790`,
   * `FUN_004DEFD0`, and `FUN_004DF010`.
   */
  struct SParamKey
  {
    inline static gpg::RType* sType = nullptr;

    msvc8::string mCueName;                // +0x00
    msvc8::string mBankName;               // +0x1C
    msvc8::string mLodCutoffVariableName;  // +0x38
    msvc8::string mRpcLoopVariableName;    // +0x54
  };

  static_assert(offsetof(SParamKey, mCueName) == 0x00, "SParamKey::mCueName offset must be 0x00");
  static_assert(offsetof(SParamKey, mBankName) == 0x1C, "SParamKey::mBankName offset must be 0x1C");
  static_assert(
    offsetof(SParamKey, mLodCutoffVariableName) == 0x38,
    "SParamKey::mLodCutoffVariableName offset must be 0x38"
  );
  static_assert(
    offsetof(SParamKey, mRpcLoopVariableName) == 0x54,
    "SParamKey::mRpcLoopVariableName offset must be 0x54"
  );
  static_assert(sizeof(SParamKey) == 0x70, "SParamKey size must be 0x70");
} // namespace moho

