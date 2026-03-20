#pragma once
#include "legacy/containers/Vector.h"
#include "moho/ui/SDebugLine.h"

namespace moho
{
  class CDebugCanvas
  {
  public:
    msvc8::vector<SDebugLine> lines;
    msvc8::vector<void*> worldText;
    msvc8::vector<void*> screenText;
    msvc8::vector<void*> decals;
  };

  static_assert(sizeof(CDebugCanvas) == 0x40, "CDebugCanvas size must be 0x40");
} // namespace moho
