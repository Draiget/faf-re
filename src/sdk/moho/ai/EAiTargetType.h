#pragma once
#include <cstdint>

namespace moho
{
  enum class EAiTargetType : int32_t
  {
    AITARGET_None = 0x0,
    AITARGET_Entity = 0x1,
    AITARGET_Ground = 0x2,
  };
}
