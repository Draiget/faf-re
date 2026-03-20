#pragma once
#include "legacy/containers/String.h"

namespace moho
{
  struct SSTICommandSource
  {
    uint8_t mIndex;
    msvc8::string mName;
    int mTimeouts;
  };
} // namespace moho
