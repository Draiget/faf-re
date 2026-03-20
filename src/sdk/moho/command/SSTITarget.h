#pragma once
#include <cstddef>
#include <cstdint>

#include "moho/ai/EAiTargetType.h"
#include "wm3/Vector3.h"

namespace moho
{
  struct SSTITarget
  {
    EAiTargetType mType;     // +0x00
    std::uint32_t mEntityId; // +0x04 (serialized raw id for AITARGET_Entity)
    Wm3::Vec3f mPos;         // +0x08
  };

  static_assert(offsetof(SSTITarget, mType) == 0x00, "SSTITarget::mType offset must be 0x00");
  static_assert(offsetof(SSTITarget, mEntityId) == 0x04, "SSTITarget::mEntityId offset must be 0x04");
  static_assert(offsetof(SSTITarget, mPos) == 0x08, "SSTITarget::mPos offset must be 0x08");
  static_assert(sizeof(SSTITarget) == 0x14, "SSTITarget size must be 0x14");
} // namespace moho
