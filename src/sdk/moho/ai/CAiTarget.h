#pragma once
#include <cstdint>

#include "moho/ai/EAiTargetType.h"
#include "moho/containers/TDatList.h"
#include "wm3/Vector3.h"

namespace moho
{
  class CAiTarget : public TDatList<CAiTarget, void>
  {
  public:
    EAiTargetType targetType;
    Wm3::Vec3f position;
    int32_t targetPoint;
    bool targetIsMobile;
  };
} // namespace moho
