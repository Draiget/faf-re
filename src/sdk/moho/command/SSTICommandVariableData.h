#pragma once

#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/command/SSTITarget.h"
#include "moho/sim/SOCellPos.h"

namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  using EntId = std::int32_t;

  struct SSTICommandVariableData
  {
    msvc8::vector<EntId> mEntIds;
    std::int32_t v1;
    std::int32_t v2;
    EUnitCommandType mCmdType;
    SSTITarget mTarget1;
    SSTITarget mTarget2;
    std::int32_t v14;
    msvc8::vector<SOCellPos> mCells;
    std::int32_t v19;
    std::int32_t v20;
    std::int32_t mMaxCount;
    std::int32_t mCount;
    std::int32_t v23;
  };
} // namespace moho
