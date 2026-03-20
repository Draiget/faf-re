#pragma once
#include <cstdint>

namespace moho
{
  enum ECollisionShape : int32_t
  {
    COLSHAPE_None = 0x0,
    COLSHAPE_Box = 0x1,
    COLSHAPE_Sphere = 0x2,
  };
}
